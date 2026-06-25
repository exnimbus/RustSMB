//! CREATE handler — open or create a file/directory and allocate a FileId.

use std::sync::Arc;

use crate::error::SmbError;
use crate::proto::auth::ntlm::Identity;
use crate::proto::header::{SMB2_FLAGS_REPLAY_OPERATION, Smb2Header};
use crate::proto::messages::{
    CreateContext, CreateRequest, CreateResponse, Dialect, FileId, OplockLevel,
};
use tracing::{debug, warn};

use crate::backend::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FileInfo, Handle,
    MissingDeleteProbeHandle, OpenIntent, OpenOptions, PipeHandle, QuotaPseudoHandle, ShareBackend,
};
use crate::builder::Access;
use crate::conn::state::{Connection, Open, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::info_class::{self, PosixMetadata};
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::{
    DurableReplayLookup, RequestedLease, SameKeyLeaseState, ServerState, StreamHandle,
    volume_id_for_share,
};
use crate::utils::utf16le_to_units;

// MS-SMB2 §2.2.13 access mask flags
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAX_ALLOWED: u32 = 0x0200_0000;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

// ShareAccess
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0x0000_0000;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// CreateAction in response (MS-SMB2 §2.2.14)
const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;
const FILE_OVERWRITTEN: u32 = 0x0000_0003;

const CREATE_RESPONSE_FIXED_BODY_LEN: u32 = 88;
const QUOTA_PSEUDO_FILE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_DIRECTORY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM;
const AAPL_SERVER_QUERY: u32 = 0x0000_0001;
const AAPL_SERVER_CAPS: u64 = 0x0000_0001;
const AAPL_VOLUME_CAPS: u64 = 0x0000_0002;
const AAPL_MODEL_INFO: u64 = 0x0000_0004;
const AAPL_MODEL: &str = "GoSMB";
const LEASE_NONE: u32 = 0x0000_0000;
const LEASE_READ_CACHING: u32 = 0x0000_0001;
const LEASE_HANDLE_CACHING: u32 = 0x0000_0002;
const LEASE_WRITE_CACHING: u32 = 0x0000_0004;
const LEASE_BREAK_IN_PROGRESS: u32 = 0x0000_0002;
const LEASE_PARENT_LEASE_KEY_SET: u32 = 0x0000_0004;
const OPLOCK_NONE: u8 = 0x00;
const OPLOCK_LEVEL_II: u8 = 0x01;
const OPLOCK_EXCLUSIVE: u8 = 0x08;
const OPLOCK_BATCH: u8 = 0x09;

#[derive(Debug, Clone, Copy)]
struct LeaseResponse {
    key: [u8; 16],
    state: u32,
    flags: u32,
    parent_key: [u8; 16],
    epoch: u16,
    version: u8,
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CreateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let create_contexts = match parse_create_contexts(&req, body) {
        Ok(contexts) => contexts,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if let Err(status) = validate_create_contexts(&req, &create_contexts) {
        return HandlerResponse::err(status);
    }
    let requested_posix_mode = match requested_posix_mode(&create_contexts) {
        Ok(mode) => mode,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let requested_allocation_size = requested_allocation_size(&create_contexts);
    let requested_security_descriptor = match requested_security_descriptor(&create_contexts) {
        Ok(descriptor) => descriptor,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let requested_extended_attributes = match requested_extended_attributes(&create_contexts) {
        Ok(eas) => eas,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let has_durable_reconnect = create_contexts.iter().any(|ctx| {
        ctx.name == CreateContext::NAME_DHNC.as_slice()
            || ctx.name == CreateContext::NAME_DH2C.as_slice()
    });
    let requested_lease = requested_lease_response(&req, &create_contexts, has_durable_reconnect);
    let dialect = *conn.dialect.read().await;
    let client_guid = *conn.client_guid.read().await;
    let desired_access = expand_desired_access(req.desired_access);
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let (granted, backend, share_name, share_is_ipc) = {
        let tree = tree_arc.read().await;
        (
            tree.granted_access,
            tree.share.backend.clone(),
            tree.share.name.clone(),
            tree.share.is_ipc,
        )
    };
    let durable_owner = durable_owner(conn, hdr.session_id).await;
    let session_reauth_anonymous = {
        let session = conn.sessions.read().await.get(&hdr.session_id).cloned();
        match session {
            Some(session) => session.read().await.reauth_anonymous,
            None => false,
        }
    };
    if let Some(file_id) = requested_durable_reconnect_v1(&create_contexts) {
        if share_is_ipc {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if requested_lease.is_none() && server.durable_open_version(file_id).await == Some(2) {
            return reconnect_durable(
                server,
                conn,
                &tree_arc,
                &share_name,
                file_id,
                2,
                CreateContext::NAME_DH2C,
                None,
                requested_lease,
                hdr.session_id,
                client_guid,
                &durable_owner,
            )
            .await;
        }
        if requested_lease.is_some() {
            let requested_path = match requested_create_path(&req) {
                Ok(path) => path,
                Err(status) => return HandlerResponse::err(status),
            };
            if server
                .durable_reconnect_path_mismatch(
                    &share_name,
                    file_id,
                    client_guid,
                    &durable_owner,
                    &requested_path,
                )
                .await
            {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        return reconnect_durable(
            server,
            conn,
            &tree_arc,
            &share_name,
            file_id,
            1,
            CreateContext::NAME_DHNC,
            None,
            requested_lease,
            hdr.session_id,
            client_guid,
            &durable_owner,
        )
        .await;
    }
    if let Some(file_id) = requested_durable_reconnect_v2(&create_contexts) {
        if share_is_ipc {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let create_guid = requested_durable_reconnect_create_guid_v2(&create_contexts);
        if dialect == Some(Dialect::Smb311)
            && requested_lease.is_some()
            && server.durable_open_version(file_id).await == Some(1)
        {
            return reconnect_durable(
                server,
                conn,
                &tree_arc,
                &share_name,
                file_id,
                1,
                CreateContext::NAME_DHNC,
                None,
                requested_lease,
                hdr.session_id,
                client_guid,
                &durable_owner,
            )
            .await;
        }
        if requested_lease.is_some() {
            let requested_path = match requested_create_path(&req) {
                Ok(path) => path,
                Err(status) => return HandlerResponse::err(status),
            };
            if server
                .durable_reconnect_path_mismatch(
                    &share_name,
                    file_id,
                    client_guid,
                    &durable_owner,
                    &requested_path,
                )
                .await
            {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        return reconnect_durable(
            server,
            conn,
            &tree_arc,
            &share_name,
            file_id,
            2,
            CreateContext::NAME_DH2C,
            create_guid,
            requested_lease,
            hdr.session_id,
            client_guid,
            &durable_owner,
        )
        .await;
    }
    let requested_app_instance_id = requested_app_instance_id(&create_contexts);
    if requested_durable_create_guid_v2(&create_contexts).is_some()
        && let Some(app_instance_id) = requested_app_instance_id
    {
        server
            .close_durable_open_for_app_instance(app_instance_id)
            .await;
    }
    if let Some(create_guid) = requested_durable_create_guid_v2(&create_contexts) {
        if hdr.flags & SMB2_FLAGS_REPLAY_OPERATION != 0 {
            let replay_name = replay_raw_name(&req).unwrap_or_default();
            if !is_windows_replay_violation_name(&replay_name)
                && server.durable_pending_create_replay(create_guid, client_guid, &durable_owner)
            {
                let status = if is_windows_replay_name(&replay_name) {
                    ntstatus::STATUS_ACCESS_DENIED
                } else {
                    ntstatus::STATUS_FILE_NOT_AVAILABLE
                };
                return HandlerResponse::err(status);
            }
            if let Some(body) =
                server.completed_create_replay(create_guid, client_guid, &durable_owner)
            {
                return HandlerResponse::ok(body);
            }
            match server
                .durable_replay_open(
                    &share_name,
                    create_guid,
                    client_guid,
                    &durable_owner,
                    conn,
                    hdr.session_id,
                )
                .await
            {
                DurableReplayLookup::Available(open) => {
                    return replay_durable_create_v2(
                        server,
                        conn,
                        &tree_arc,
                        &share_name,
                        open,
                        &req,
                        dialect,
                        &create_contexts,
                        requested_lease,
                        requested_durable_handle_timeout_v2(&create_contexts),
                        hdr.session_id,
                    )
                    .await;
                }
                DurableReplayLookup::AttachedElsewhere => {
                    return HandlerResponse::err(ntstatus::STATUS_DUPLICATE_OBJECTID);
                }
                DurableReplayLookup::NotFound => {}
            }
        }
        match server
            .durable_replay_open(
                &share_name,
                create_guid,
                client_guid,
                &durable_owner,
                conn,
                hdr.session_id,
            )
            .await
        {
            DurableReplayLookup::Available(_) | DurableReplayLookup::AttachedElsewhere => {
                return HandlerResponse::err(ntstatus::STATUS_DUPLICATE_OBJECTID);
            }
            DurableReplayLookup::NotFound => {}
        }
    }

    // Decode path.
    let units = match utf16le_to_units(&req.name) {
        Some(u) => u,
        None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let raw_name = match String::from_utf16(&units) {
        Ok(s) => s,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    if let Err(status) = validate_create_parameters(&req, &raw_name, share_is_ipc) {
        return HandlerResponse::err(status);
    }
    if share_is_ipc {
        return create_ipc_pipe(tree_arc, req, raw_name, desired_access).await;
    }
    if is_quota_pseudo_file(&raw_name) {
        return create_quota_pseudo_file(
            server,
            conn,
            tree_arc,
            req,
            &share_name,
            raw_name,
            desired_access,
        )
        .await;
    }
    let stream_target = match parse_stream_target(&raw_name) {
        Ok(target) => target,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let default_stream_alias = matches!(stream_target, Some(StreamTarget::Default { .. }));
    let path_units;
    let parse_units = match &stream_target {
        Some(StreamTarget::Default { base }) => {
            path_units = base.encode_utf16().collect::<Vec<_>>();
            &path_units
        }
        Some(StreamTarget::Named(target)) => {
            path_units = target
                .base
                .display_backslash()
                .encode_utf16()
                .collect::<Vec<_>>();
            &path_units
        }
        None => &units,
    };
    let path = if stream_target.is_some() {
        match SmbPath::from_utf16(parse_units) {
            Ok(p) => p,
            Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
        }
    } else {
        match SmbPath::from_utf16(&units) {
            Ok(p) => p,
            Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
        }
    };
    debug!(
        share = %share_name,
        raw_name = %raw_name,
        path = %path,
        desired_access = req.desired_access,
        create_disposition = req.create_disposition,
        create_options = req.create_options,
        "create request path decoded"
    );
    if let Some(lease) = requested_lease {
        let stream_name = match &stream_target {
            Some(StreamTarget::Named(target)) => Some(target.stream_name.as_str()),
            _ => None,
        };
        if server
            .lease_key_conflicts_with_path(&share_name, &path, stream_name, lease.key)
            .await
        {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }

    // Translate disposition.
    let intent = match req.create_disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
        FILE_OPEN => OpenIntent::Open,
        FILE_CREATE => OpenIntent::Create,
        FILE_OPEN_IF => OpenIntent::OpenOrCreate,
        FILE_OVERWRITE => OpenIntent::Truncate,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    // Translate desired access into read/write hints.
    let want_read = req.desired_access
        & (FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_ALL | MAX_ALLOWED)
        != 0;
    let want_write = req.desired_access
        & (FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | GENERIC_WRITE
            | GENERIC_ALL
            | MAX_ALLOWED)
        != 0;

    // Reject writes on a read-only tree.
    if want_write && !granted.allows_write() {
        warn!(path = %path, "write open on read-only tree");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    // Disposition that creates: requires write permission.
    if !granted.allows_write()
        && matches!(
            intent,
            OpenIntent::Create
                | OpenIntent::OpenOrCreate
                | OpenIntent::OverwriteOrCreate
                | OpenIntent::Truncate
        )
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let directory = req.create_options & FILE_DIRECTORY_FILE != 0;
    let non_directory = req.create_options & FILE_NON_DIRECTORY_FILE != 0;
    if directory && non_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if default_stream_alias && directory {
        return HandlerResponse::err(ntstatus::STATUS_NOT_A_DIRECTORY);
    }
    let delete_on_close = req.create_options & FILE_DELETE_ON_CLOSE != 0;
    if delete_on_close && desired_access & (DELETE | FILE_DELETE_CHILD) == 0 {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let share_access = req.share_access & (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);

    let opts = OpenOptions {
        read: want_read || !want_write,
        write: want_write,
        intent,
        directory,
        non_directory,
        delete_on_close,
    };

    if let Some(StreamTarget::Named(stream_target)) = stream_target {
        if directory {
            return HandlerResponse::err(ntstatus::STATUS_NOT_A_DIRECTORY);
        }
        let allow_delete_pending_stream_create =
            delete_on_close && matches!(intent, OpenIntent::Create);
        if server
            .open_delete_pending(&share_name, &stream_target.base)
            .await
            && !allow_delete_pending_stream_create
        {
            return HandlerResponse::err(ntstatus::STATUS_DELETE_PENDING);
        }
        if server
            .share_conflicts(
                &share_name,
                &stream_target.base,
                Some(&stream_target.stream_name),
                desired_access,
                share_access,
            )
            .await
        {
            return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
        }
        let base_opts = OpenOptions {
            read: true,
            write: false,
            intent: OpenIntent::Open,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        };
        let base_handle = match backend.open(&stream_target.base, base_opts).await {
            Ok(h) => h,
            Err(crate::error::SmbError::NotFound)
                if stream_create_disposition_allows_missing_base(intent) =>
            {
                let create_base_opts = OpenOptions {
                    read: true,
                    write: true,
                    intent: OpenIntent::Create,
                    directory: false,
                    non_directory: true,
                    delete_on_close: false,
                };
                match backend.open(&stream_target.base, create_base_opts).await {
                    Ok(h) => h,
                    Err(e) => return HandlerResponse::err(e.to_nt_status()),
                }
            }
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        };
        let base_info = match base_handle.stat().await {
            Ok(info) => info,
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        };
        let _ = base_handle.close().await;
        let canonical_base = canonical_path_from_info(&stream_target.base, &base_info);
        let base_creation_time = server
            .effective_file_info(&share_name, &canonical_base, base_info.clone())
            .creation_time;
        let (canonical_stream_name, stream_existed_before) = match server.open_stream(
            &share_name,
            &canonical_base,
            &stream_target.stream_name,
            intent,
            base_creation_time,
        ) {
            Ok(name) => name,
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        };
        let handle: Box<dyn crate::backend::Handle> = Box::new(StreamHandle::new(
            Arc::clone(server),
            share_name.clone(),
            canonical_base.clone(),
            canonical_stream_name.clone(),
        ));
        let info = match handle.stat().await {
            Ok(i) => i,
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        };
        let existing_same_key_lease = match requested_lease {
            Some(lease) => {
                server
                    .same_key_lease_state(
                        &share_name,
                        &canonical_base,
                        Some(&canonical_stream_name),
                        lease.key,
                    )
                    .await
            }
            _ => None,
        };
        let same_key_upgrade_can_share = match requested_lease {
            Some(lease) if existing_same_key_lease.is_some() => {
                server
                    .lease_state_can_share_with_other_keys(
                        &share_name,
                        &canonical_base,
                        Some(&canonical_stream_name),
                        lease.key,
                        lease.state,
                        LEASE_WRITE_CACHING,
                    )
                    .await
            }
            _ => true,
        };
        let lease_caching_available = match requested_lease {
            Some(lease) => {
                server
                    .lease_caching_available(
                        &share_name,
                        &canonical_base,
                        Some(&canonical_stream_name),
                        lease.key,
                    )
                    .await
            }
            _ => false,
        };
        let lease_handle_caching_available = match requested_lease {
            Some(lease) => {
                server
                    .lease_handle_caching_available(
                        &share_name,
                        &canonical_base,
                        Some(&canonical_stream_name),
                        lease.key,
                    )
                    .await
            }
            _ => false,
        };
        let lease_read_caching_available = !server.has_backed_byte_range_locks(
            &share_name,
            &canonical_base,
            Some(&canonical_stream_name),
            info.end_of_file,
        );
        let granted_lease = granted_lease_response(
            dialect,
            requested_lease,
            false,
            existing_same_key_lease,
            same_key_upgrade_can_share,
            lease_read_caching_available,
            lease_handle_caching_available,
            lease_caching_available,
        );
        let mut granted_oplock_level = if granted_lease.is_some() {
            OPLOCK_NONE
        } else {
            grant_oplock_level(
                server,
                &share_name,
                &canonical_base,
                Some(&canonical_stream_name),
                req.requested_oplock_level,
                desired_access,
                false,
            )
            .await
        };
        let oplock_break_target =
            if matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate)
                || access_is_attribute_only_overwrite(desired_access, intent)
            {
                OPLOCK_NONE
            } else {
                OPLOCK_LEVEL_II
            };
        let cache_break_wait_oplock_file_ids =
            if !access_is_attribute_only_open_probe(desired_access, intent) {
                server
                    .break_conflicting_oplocks_for_open(
                        &share_name,
                        &canonical_base,
                        Some(&canonical_stream_name),
                        oplock_break_target,
                    )
                    .await
            } else {
                Vec::new()
            };
        if !cache_break_wait_oplock_file_ids.is_empty()
            && oplock_break_target == OPLOCK_NONE
            && matches!(req.requested_oplock_level, OPLOCK_EXCLUSIVE | OPLOCK_BATCH)
        {
            granted_oplock_level = OPLOCK_LEVEL_II;
        }
        if !cache_break_wait_oplock_file_ids.is_empty()
            && matches!(req.requested_oplock_level, OPLOCK_EXCLUSIVE | OPLOCK_BATCH)
            && server
                .cache_break_wait_has_force_unacked(&[], &cache_break_wait_oplock_file_ids)
                .await
        {
            granted_oplock_level = req.requested_oplock_level;
        }
        let pending_cache_break = if cache_break_wait_oplock_file_ids.is_empty() {
            None
        } else {
            let Some(tx) = conn.async_sender().await else {
                let _ = handle.close().await;
                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
            };
            if !server.reserve_cache_break_create_async_slot(conn) {
                let _ = handle.close().await;
                return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
            }
            Some((conn.alloc_async_id(), tx))
        };
        let tree = tree_arc.write().await;
        let file_id = server.alloc_file_id();
        let registry_base = canonical_base.clone();
        let registry_stream_name = canonical_stream_name.clone();
        let mut open = Open::new(
            file_id,
            handle,
            if want_write { granted } else { Access::Read },
            desired_access,
            share_access,
            canonical_base,
            false,
            delete_on_close,
            None,
        );
        open.stream_name = Some(canonical_stream_name);
        if let Some(lease) = granted_lease {
            open.oplock_level = req.requested_oplock_level;
            open.lease_key = lease.key;
            open.lease_state = lease.state;
            open.lease_flags = persistent_lease_flags(lease.flags);
            open.lease_epoch = lease.epoch;
            open.lease_version = lease.version;
        } else {
            open.oplock_level = granted_oplock_level;
        }
        let open_arc = Arc::new(tokio::sync::RwLock::new(open));
        tree.opens
            .write()
            .await
            .insert(file_id, Arc::clone(&open_arc));
        drop(tree);
        server.register_open(
            &share_name,
            &registry_base,
            Some(&registry_stream_name),
            &open_arc,
            conn,
        );
        if let Some(lease) = granted_lease {
            server
                .update_same_key_lease_state(
                    &share_name,
                    &registry_base,
                    Some(&registry_stream_name),
                    lease.key,
                    SameKeyLeaseState {
                        state: lease.state,
                        flags: persistent_lease_flags(lease.flags),
                        epoch: lease.epoch,
                        version: lease.version,
                        breaking: false,
                    },
                )
                .await;
        }

        let mut response_context_bytes = Vec::new();
        if let Some(lease) = granted_lease {
            let response_contexts = [CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: encode_lease_response(lease),
            }];
            if CreateContext::encode_chain(&response_contexts, &mut response_context_bytes).is_err()
            {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        let create_contexts_offset = if response_context_bytes.is_empty() {
            0
        } else {
            64 + CREATE_RESPONSE_FIXED_BODY_LEN
        };

        let resp = CreateResponse {
            structure_size: 89,
            oplock_level: if granted_lease.is_some() {
                req.requested_oplock_level
            } else {
                granted_oplock_level
            },
            flags: 0,
            create_action: create_action_for_intent(intent, stream_existed_before),
            creation_time: info.creation_time,
            last_access_time: info.last_access_time,
            last_write_time: info.last_write_time,
            change_time: info.change_time,
            allocation_size: info.allocation_size,
            end_of_file: info.end_of_file,
            file_attributes: info.attributes(),
            reserved2: 0,
            file_id,
            create_contexts_offset,
            create_contexts_length: response_context_bytes.len() as u32,
            create_contexts: response_context_bytes,
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).expect("encode");
        if let Some((async_id, tx)) = pending_cache_break {
            server.register_cache_break_create(
                async_id,
                conn,
                tx,
                *hdr,
                Vec::new(),
                cache_break_wait_oplock_file_ids,
                file_id,
                ntstatus::STATUS_SUCCESS,
                buf,
                None,
                client_guid,
                durable_owner,
            );
            return HandlerResponse::pending_async(
                async_id,
                HandlerResponse::err(ntstatus::STATUS_PENDING).body,
            );
        }
        return HandlerResponse::ok(buf);
    }

    let parent_namespace_lock = path
        .parent()
        .filter(|parent| !parent.is_root())
        .map(|parent| server.namespace_lock(&share_name, &parent));
    let _parent_namespace_guard = match &parent_namespace_lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let namespace_lock = server.namespace_lock(&share_name, &path);
    let _namespace_guard = namespace_lock.lock().await;

    server
        .invalidate_detached_durable_opens_for_path(
            &share_name,
            &path,
            None,
            &backend,
            desired_access,
            requested_lease.map(|lease| RequestedLease {
                key: lease.key,
                state: lease.state,
            }),
        )
        .await;

    let existed_before = backend_object_exists(&backend, &path).await;
    let already_delete_pending = server.open_delete_pending(&share_name, &path).await;
    if !existed_before && !already_delete_pending {
        server.clear_delete_pending(&share_name, &path);
    }
    let idempotent_delete_pending_unlink = already_delete_pending
        && delete_on_close
        && desired_access & (DELETE | FILE_DELETE_CHILD) != 0;
    if already_delete_pending && !idempotent_delete_pending_unlink {
        return HandlerResponse::err(ntstatus::STATUS_DELETE_PENDING);
    }

    let creates_new_object = !existed_before
        && matches!(
            intent,
            OpenIntent::Create | OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate
        );
    if delete_on_close
        && creates_new_object
        && req.file_attributes & FILE_ATTRIBUTE_READONLY != 0
        && !directory
    {
        return HandlerResponse::err(ntstatus::STATUS_CANNOT_DELETE);
    }
    if existed_before && matches!(intent, OpenIntent::Create) {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_COLLISION);
    }
    if !creates_new_object
        && security_descriptor_denies_open(server, &share_name, &path, desired_access)
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if creates_new_object
        && parent_directory_denies_child_create(server, &share_name, &path, directory)
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if default_stream_alias {
        let stat_opts = OpenOptions {
            read: true,
            write: false,
            intent: OpenIntent::Open,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        };
        match backend.open(&path, stat_opts).await {
            Ok(handle) => {
                let info = match handle.stat().await {
                    Ok(info) => info,
                    Err(e) => {
                        let _ = handle.close().await;
                        return HandlerResponse::err(e.to_nt_status());
                    }
                };
                let _ = handle.close().await;
                if info.is_directory {
                    return HandlerResponse::err(ntstatus::STATUS_FILE_IS_A_DIRECTORY);
                }
            }
            Err(SmbError::NotFound) => {}
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        }
    }

    let share_conflicts = server
        .share_conflicts(&share_name, &path, None, desired_access, share_access)
        .await;
    let delete_sharing_conflict = desired_access & DELETE != 0
        && server
            .delete_sharing_conflict(&share_name, &path, None, None)
            .await;
    if (share_conflicts || delete_sharing_conflict) && !idempotent_delete_pending_unlink {
        let wait_lease_keys = if !directory {
            server
                .break_conflicting_leases_for_open(
                    &share_name,
                    &path,
                    None,
                    requested_lease.map(|lease| lease.key).unwrap_or([0; 16]),
                    LEASE_READ_CACHING | LEASE_WRITE_CACHING,
                )
                .await
        } else {
            Vec::new()
        };
        let wait_oplock_file_ids = if !directory {
            server
                .break_conflicting_batch_oplocks_for_open(&share_name, &path, None, OPLOCK_LEVEL_II)
                .await
        } else {
            Vec::new()
        };
        if !wait_lease_keys.is_empty() || !wait_oplock_file_ids.is_empty() {
            return pending_create_after_share_conflict_cache_break(
                server,
                conn,
                hdr,
                &tree_arc,
                &backend,
                &share_name,
                &path,
                opts,
                req.requested_oplock_level,
                desired_access,
                share_access,
                want_write,
                granted,
                delete_on_close,
                wait_lease_keys,
                wait_oplock_file_ids,
                requested_durable_create_guid_v2(&create_contexts).filter(|guid| *guid != [0; 16]),
                client_guid,
                durable_owner.clone(),
            )
            .await;
        }
        return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
    }

    let samba_cleanup_missing_unlink = !existed_before
        && session_reauth_anonymous
        && matches!(intent, OpenIntent::Open)
        && delete_on_close
        && non_directory
        && !directory
        && req.file_attributes == 0
        && desired_access == DELETE
        && share_access == (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        && !server.name_was_deleted(&share_name, &path)
        && match path.parent() {
            Some(parent) if parent.is_root() => true,
            Some(parent) => backend_object_exists(&backend, &parent).await,
            None => false,
        };

    let handle = match backend.open(&path, opts).await {
        Ok(h) => h,
        Err(SmbError::NotFound | SmbError::PathNotFound) if samba_cleanup_missing_unlink => {
            server.mark_name_deleted(&share_name, &path);
            Box::new(MissingDeleteProbeHandle::new(
                path.file_name().unwrap_or_default().to_string(),
            )) as Box<dyn Handle>
        }
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed");
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Stat for the response.
    let info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            return HandlerResponse::err(e.to_nt_status());
        }
    };
    if default_stream_alias && info.is_directory {
        let _ = handle.close().await;
        let status = if directory {
            ntstatus::STATUS_NOT_A_DIRECTORY
        } else {
            ntstatus::STATUS_FILE_IS_A_DIRECTORY
        };
        return HandlerResponse::err(status);
    }
    let path = canonical_path_from_info(&path, &info);
    if creates_new_object {
        server.clear_name_deleted(&share_name, &path);
        server.clear_delete_pending(&share_name, &path);
        server.delete_security_descriptor(&share_name, &path);
        server.delete_extended_attributes(&share_name, &path);
        server.delete_allocation_size(&share_name, &path);
        server.delete_file_attributes(&share_name, &path);
        server.delete_file_times(&share_name, &path);
        server.delete_streams(&share_name, &path);
        server.delete_posix_metadata(&share_name, &path);
    }
    let requested_posix = requested_posix_mode.map(|mode| {
        let mode = if mode == 0 {
            info_class::default_posix_mode(&info)
        } else {
            mode & 0o7777
        };
        let id = derived_posix_identity(&share_name, &path);
        PosixMetadata {
            mode,
            uid: id,
            gid: id,
        }
    });
    if let Some(posix) = requested_posix {
        server.set_posix_metadata(&share_name, &path, posix);
    }
    let inherited_security_descriptor = if creates_new_object {
        inherited_security_descriptor_for_create(server, &share_name, &path, info.is_directory)
    } else {
        None
    };
    if let Some(descriptor) = requested_security_descriptor.or(inherited_security_descriptor) {
        server.set_security_descriptor(&share_name, &path, descriptor);
    }
    if !requested_extended_attributes.is_empty() {
        server.apply_extended_attributes(&share_name, &path, &requested_extended_attributes);
    }
    if let Some(attributes) =
        create_file_attributes_from_request(req.file_attributes, info.is_directory)
        && mutates_metadata(intent)
    {
        server.set_file_attributes(&share_name, &path, attributes, info.is_directory);
    }
    if let Some(allocation_size) = requested_allocation_size
        && mutates_metadata(intent)
        && !info.is_directory
    {
        server.set_allocation_size(&share_name, &path, allocation_size);
    } else if matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate) {
        server.delete_allocation_size(&share_name, &path);
    }
    if req.file_attributes == 0
        && matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate)
    {
        server.delete_file_attributes(&share_name, &path);
    }
    if matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate) {
        server.delete_file_times(&share_name, &path);
    }
    if !info.is_directory && matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate)
    {
        server.delete_streams(&share_name, &path);
    }
    let info = server.effective_file_info(&share_name, &path, info);
    if delete_on_close && !info.is_directory && info.file_attributes & FILE_ATTRIBUTE_READONLY != 0
    {
        let _ = handle.close().await;
        return HandlerResponse::err(ntstatus::STATUS_CANNOT_DELETE);
    }
    let posix_metadata = match requested_posix {
        Some(posix) => Some(posix),
        None => server.posix_metadata(&share_name, &path),
    };

    let create_action = create_action_for_intent(intent, existed_before);
    let existing_same_key_lease = match requested_lease {
        Some(lease) if !info.is_directory => {
            server
                .same_key_lease_state(&share_name, &path, None, lease.key)
                .await
        }
        _ => None,
    };
    let same_key_upgrade_can_share = match requested_lease {
        Some(lease) if existing_same_key_lease.is_some() => {
            server
                .lease_state_can_share_with_other_keys(
                    &share_name,
                    &path,
                    None,
                    lease.key,
                    lease.state,
                    LEASE_WRITE_CACHING,
                )
                .await
        }
        _ => true,
    };
    let lease_caching_available = match requested_lease {
        Some(lease) if !info.is_directory => {
            server
                .lease_caching_available(&share_name, &path, None, lease.key)
                .await
        }
        _ => false,
    };
    let lease_handle_caching_available = match requested_lease {
        Some(lease) if !info.is_directory => {
            server
                .lease_handle_caching_available(&share_name, &path, None, lease.key)
                .await
        }
        _ => false,
    };
    let lease_read_caching_available = !info.is_directory
        && !server.has_backed_byte_range_locks(&share_name, &path, None, info.end_of_file);
    let mut granted_lease = granted_lease_response(
        dialect,
        requested_lease,
        info.is_directory,
        existing_same_key_lease,
        same_key_upgrade_can_share,
        lease_read_caching_available,
        lease_handle_caching_available,
        lease_caching_available,
    );
    let mut granted_oplock_level = if granted_lease.is_some() {
        OPLOCK_NONE
    } else {
        grant_oplock_level(
            server,
            &share_name,
            &path,
            None,
            req.requested_oplock_level,
            desired_access,
            info.is_directory,
        )
        .await
    };
    let lease_break_target =
        if matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate) {
            LEASE_NONE
        } else {
            LEASE_READ_CACHING | LEASE_HANDLE_CACHING
        };
    let cache_break_wait_lease_keys =
        if !info.is_directory && !access_is_lease_stat_open(desired_access) {
            server
                .break_conflicting_leases_for_open(
                    &share_name,
                    &path,
                    None,
                    requested_lease.map(|lease| lease.key).unwrap_or([0; 16]),
                    lease_break_target,
                )
                .await
        } else {
            Vec::new()
        };
    let oplock_break_target =
        if matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate)
            || access_is_attribute_only_overwrite(desired_access, intent)
        {
            OPLOCK_NONE
        } else {
            OPLOCK_LEVEL_II
        };
    let cache_break_wait_oplock_file_ids =
        if !info.is_directory && !access_is_attribute_only_open_probe(desired_access, intent) {
            server
                .break_conflicting_oplocks_for_open(&share_name, &path, None, oplock_break_target)
                .await
        } else {
            Vec::new()
        };
    let requested_durable_v2_create = !info.is_directory
        && dialect_supports_durable_v2(dialect)
        && create_contexts
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice() && ctx.data.len() == 32);
    if !cache_break_wait_oplock_file_ids.is_empty()
        && oplock_break_target == OPLOCK_NONE
        && matches!(req.requested_oplock_level, OPLOCK_EXCLUSIVE | OPLOCK_BATCH)
    {
        granted_oplock_level = OPLOCK_LEVEL_II;
    }
    if !cache_break_wait_oplock_file_ids.is_empty()
        && matches!(req.requested_oplock_level, OPLOCK_EXCLUSIVE | OPLOCK_BATCH)
        && server
            .cache_break_wait_has_force_unacked(&[], &cache_break_wait_oplock_file_ids)
            .await
    {
        granted_oplock_level = req.requested_oplock_level;
    }
    let pending_cache_break =
        if cache_break_wait_lease_keys.is_empty() && cache_break_wait_oplock_file_ids.is_empty() {
            None
        } else {
            let Some(tx) = conn.async_sender().await else {
                let _ = handle.close().await;
                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
            };
            if !server.reserve_cache_break_create_async_slot(conn) {
                let _ = handle.close().await;
                return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
            }
            Some((conn.alloc_async_id(), tx))
        };
    if pending_cache_break.is_some()
        && requested_durable_v2_create
        && let (Some(mut lease), Some(requested)) = (granted_lease, requested_lease)
    {
        lease.state =
            requested.state & (LEASE_READ_CACHING | LEASE_HANDLE_CACHING | LEASE_WRITE_CACHING);
        granted_lease = Some(lease);
    }
    if pending_cache_break.is_some()
        && requested_durable_v2_create
        && granted_lease.is_none()
        && matches!(req.requested_oplock_level, OPLOCK_EXCLUSIVE | OPLOCK_BATCH)
    {
        granted_oplock_level = req.requested_oplock_level;
    }

    // Allocate FileId, register Open.
    let tree = tree_arc.write().await;
    let file_id = server.alloc_file_id();
    let registry_path = path.clone();
    let durable_v2 = can_grant_durable_handle_v2(
        &req,
        dialect,
        &create_contexts,
        granted_lease,
        info.is_directory,
    );
    let durable_v2_timeout_ms = durable_v2.then(|| {
        durable_timeout_ms_for_request(
            server,
            requested_durable_handle_timeout_v2(&create_contexts),
        )
    });
    let durable_v1 = can_grant_durable_handle_v1(
        &req,
        dialect,
        &create_contexts,
        granted_lease,
        info.is_directory,
    );
    let mut open = Open::new(
        file_id,
        handle,
        if want_write { granted } else { Access::Read },
        desired_access,
        share_access,
        path,
        info.is_directory,
        delete_on_close,
        posix_metadata,
    );
    if durable_v2 {
        open.durable = true;
        open.durable_version = 2;
        open.durable_timeout_ms =
            durable_v2_timeout_ms.unwrap_or_else(|| durable_timeout_ms(server));
        open.replay_eligible = replay_eligible_durable_open(desired_access, info.is_directory);
        open.oplock_level = granted_oplock_level;
        open.create_guid = requested_durable_create_guid_v2(&create_contexts).unwrap_or([0; 16]);
        open.app_instance_id = requested_app_instance_id.unwrap_or([0; 16]);
        open.create_action = create_action;
    } else if durable_v1 {
        open.durable = true;
        open.durable_version = 1;
        open.durable_timeout_ms = durable_timeout_ms(server);
        open.replay_eligible = replay_eligible_durable_open(desired_access, info.is_directory);
        open.oplock_level = granted_oplock_level;
        open.create_action = create_action;
    } else {
        open.oplock_level = granted_oplock_level;
    }
    if let Some(lease) = granted_lease {
        open.oplock_level = req.requested_oplock_level;
        open.lease_key = lease.key;
        open.lease_state = lease.state;
        open.lease_flags = persistent_lease_flags(lease.flags);
        open.lease_epoch = lease.epoch;
        open.lease_version = lease.version;
    }
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens
        .write()
        .await
        .insert(file_id, Arc::clone(&open_arc));
    drop(tree);
    server.register_open(&share_name, &registry_path, None, &open_arc, conn);
    if let Some(lease) = granted_lease {
        server
            .update_same_key_lease_state(
                &share_name,
                &registry_path,
                None,
                lease.key,
                SameKeyLeaseState {
                    state: lease.state,
                    flags: persistent_lease_flags(lease.flags),
                    epoch: lease.epoch,
                    version: lease.version,
                    breaking: false,
                },
            )
            .await;
    }
    if durable_v2 || durable_v1 {
        server
            .register_durable_open(
                &share_name,
                file_id,
                &open_arc,
                conn,
                hdr.session_id,
                client_guid,
                &durable_owner,
            )
            .await;
    }

    let mut response_contexts = Vec::new();
    append_aapl_response_contexts(&create_contexts, &mut response_contexts);
    if create_contexts
        .iter()
        .any(|ctx| ctx.name == CreateContext::NAME_POSIX.as_slice())
    {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_POSIX.to_vec(),
            data: info_class::encode_posix_create_context_response(&info, posix_metadata).to_vec(),
        });
    }
    if create_contexts
        .iter()
        .any(|ctx| ctx.name == CreateContext::NAME_MXAC.as_slice())
    {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_MXAC.to_vec(),
            data: encode_maximal_access_response(),
        });
    }
    if create_contexts
        .iter()
        .any(|ctx| ctx.name == CreateContext::NAME_QFID.as_slice())
    {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_QFID.to_vec(),
            data: encode_query_on_disk_id_response(
                info.file_index_or(file_id.volatile),
                volume_id_for_share(&share_name),
            ),
        });
    }
    if let Some(lease) = granted_lease {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data: encode_lease_response(lease),
        });
    }
    if durable_v2 {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_DH2Q.to_vec(),
            data: encode_durable_handle_response_v2(
                durable_v2_timeout_ms.unwrap_or_else(|| durable_timeout_ms(server)),
                0,
            ),
        });
    } else if durable_v1 {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_DHNQ.to_vec(),
            data: encode_durable_handle_response_v1(),
        });
    }
    let mut response_context_bytes = Vec::new();
    if CreateContext::encode_chain(&response_contexts, &mut response_context_bytes).is_err() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let create_contexts_offset = if response_context_bytes.is_empty() {
        0
    } else {
        64 + CREATE_RESPONSE_FIXED_BODY_LEN
    };

    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: if granted_lease.is_some() {
            req.requested_oplock_level
        } else {
            granted_oplock_level
        },
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset,
        create_contexts_length: response_context_bytes.len() as u32,
        create_contexts: response_context_bytes,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    if create_action == FILE_CREATED {
        server
            .notify_child_added(&share_name, &registry_path, info.is_directory)
            .await;
    }
    if let Some((async_id, tx)) = pending_cache_break {
        let replay_create_guid =
            requested_durable_create_guid_v2(&create_contexts).filter(|guid| *guid != [0; 16]);
        server.register_cache_break_create(
            async_id,
            conn,
            tx,
            *hdr,
            cache_break_wait_lease_keys,
            cache_break_wait_oplock_file_ids,
            file_id,
            ntstatus::STATUS_SUCCESS,
            buf,
            replay_create_guid,
            client_guid,
            durable_owner,
        );
        return HandlerResponse::pending_async(
            async_id,
            HandlerResponse::err(ntstatus::STATUS_PENDING).body,
        );
    }
    HandlerResponse::ok(buf)
}

async fn pending_create_after_share_conflict_cache_break(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    tree_arc: &Arc<tokio::sync::RwLock<TreeConnect>>,
    backend: &Arc<dyn ShareBackend>,
    share_name: &str,
    path: &SmbPath,
    opts: OpenOptions,
    requested_oplock_level: u8,
    desired_access: u32,
    share_access: u32,
    want_write: bool,
    granted: Access,
    delete_on_close: bool,
    wait_lease_keys: Vec<[u8; 16]>,
    wait_oplock_file_ids: Vec<FileId>,
    replay_create_guid: Option<[u8; 16]>,
    replay_client_guid: uuid::Uuid,
    replay_owner: String,
) -> HandlerResponse {
    let Some(tx) = conn.async_sender().await else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    if !server.reserve_cache_break_task_async_slot(conn) {
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }
    let async_id = conn.alloc_async_id();
    let resume_server = Arc::clone(server);
    let resume_conn = Arc::clone(conn);
    let resume_tree_arc = Arc::clone(tree_arc);
    let resume_backend = Arc::clone(backend);
    let resume_share_name = share_name.to_string();
    let resume_path = path.clone();
    server.register_cache_break_task_with_replay(
        async_id,
        conn,
        tx,
        *hdr,
        wait_lease_keys,
        wait_oplock_file_ids,
        replay_create_guid,
        replay_client_guid,
        replay_owner,
        Box::new(move || {
            Box::pin(async move {
                if resume_server
                    .share_conflicts(
                        &resume_share_name,
                        &resume_path,
                        None,
                        desired_access,
                        share_access,
                    )
                    .await
                    || desired_access & DELETE != 0
                        && resume_server
                            .delete_sharing_conflict(&resume_share_name, &resume_path, None, None)
                            .await
                {
                    HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION)
                } else {
                    complete_simple_base_file_create_after_share_conflict_oplock_break(
                        &resume_server,
                        &resume_conn,
                        &resume_tree_arc,
                        &resume_backend,
                        resume_share_name,
                        resume_path,
                        opts,
                        requested_oplock_level,
                        desired_access,
                        share_access,
                        want_write,
                        granted,
                        delete_on_close,
                    )
                    .await
                }
            })
        }),
    );
    HandlerResponse::pending_async(
        async_id,
        HandlerResponse::err(ntstatus::STATUS_PENDING).body,
    )
}

#[allow(clippy::too_many_arguments)]
async fn complete_simple_base_file_create_after_share_conflict_oplock_break(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree_arc: &Arc<tokio::sync::RwLock<TreeConnect>>,
    backend: &Arc<dyn ShareBackend>,
    share_name: String,
    path: SmbPath,
    opts: OpenOptions,
    requested_oplock_level: u8,
    desired_access: u32,
    share_access: u32,
    want_write: bool,
    granted: Access,
    delete_on_close: bool,
) -> HandlerResponse {
    server
        .invalidate_detached_durable_opens_for_path(
            &share_name,
            &path,
            None,
            backend,
            desired_access,
            None,
        )
        .await;
    if server.open_delete_pending(&share_name, &path).await {
        return HandlerResponse::err(ntstatus::STATUS_DELETE_PENDING);
    }
    if server
        .share_conflicts(&share_name, &path, None, desired_access, share_access)
        .await
        || desired_access & DELETE != 0
            && server
                .delete_sharing_conflict(&share_name, &path, None, None)
                .await
    {
        return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
    }

    let existed_before = backend_object_exists(backend, &path).await;
    let handle = match backend.open(&path, opts).await {
        Ok(h) => h,
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed after oplock break");
            return HandlerResponse::err(e.to_nt_status());
        }
    };
    let info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            return HandlerResponse::err(e.to_nt_status());
        }
    };
    let path = canonical_path_from_info(&path, &info);
    let info = server.effective_file_info(&share_name, &path, info);
    let create_action = create_action_for_intent(opts.intent, existed_before);

    let granted_oplock_level = grant_oplock_level(
        server,
        &share_name,
        &path,
        None,
        requested_oplock_level,
        desired_access,
        info.is_directory,
    )
    .await;

    let tree = tree_arc.write().await;
    let file_id = server.alloc_file_id();
    let registry_path = path.clone();
    let mut open = Open::new(
        file_id,
        handle,
        if want_write { granted } else { Access::Read },
        desired_access,
        share_access,
        path,
        info.is_directory,
        delete_on_close,
        None,
    );
    open.oplock_level = granted_oplock_level;
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens
        .write()
        .await
        .insert(file_id, Arc::clone(&open_arc));
    drop(tree);
    server.register_open(&share_name, &registry_path, None, &open_arc, conn);

    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: granted_oplock_level,
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        create_contexts: Vec::new(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    if create_action == FILE_CREATED {
        server
            .notify_child_added(&share_name, &registry_path, info.is_directory)
            .await;
    }
    HandlerResponse::ok(buf)
}

async fn reconnect_durable(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree_arc: &Arc<tokio::sync::RwLock<TreeConnect>>,
    share_name: &str,
    file_id: FileId,
    durable_version: u8,
    response_context_name: &[u8],
    reconnect_create_guid: Option<[u8; 16]>,
    requested_lease: Option<LeaseResponse>,
    session_id: u64,
    client_guid: uuid::Uuid,
    durable_owner: &str,
) -> HandlerResponse {
    let Some(open_arc) = server
        .reconnect_durable_open(
            tree_arc,
            file_id,
            durable_version,
            reconnect_create_guid,
            requested_lease.map(|lease| lease.key),
            conn,
            session_id,
            client_guid,
            durable_owner,
        )
        .await
    else {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let (handle_stat, oplock_level, path, stored_lease, durable_timeout_ms) = {
        let open = open_arc.read().await;
        let Some(handle) = open.handle.as_ref() else {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        };
        let stored_lease = if open.lease_state != LEASE_NONE {
            Some(LeaseResponse {
                key: open.lease_key,
                state: open.lease_state,
                flags: open.lease_flags,
                parent_key: [0; 16],
                epoch: open.lease_epoch,
                version: open.lease_version,
            })
        } else {
            None
        };
        (
            handle.stat().await,
            open.oplock_level,
            open.last_path.clone(),
            stored_lease,
            open.durable_timeout_ms,
        )
    };
    match (requested_lease, stored_lease) {
        (Some(requested), Some(stored)) if requested.key != stored.key => {
            return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        }
        (Some(_), None) | (None, Some(_)) => {
            return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        }
        _ => {}
    }
    let info = match handle_stat {
        Ok(info) => server.effective_file_info(share_name, &path, info),
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    let mut response_contexts = Vec::new();
    if let Some(lease) = stored_lease {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data: encode_lease_response(lease),
        });
    }
    response_contexts.push(CreateContext {
        name: response_context_name.to_vec(),
        data: if durable_version >= 2 {
            encode_durable_handle_response_v2(durable_timeout_ms, 0)
        } else {
            encode_durable_handle_response_v1()
        },
    });
    let mut response_context_bytes = Vec::new();
    if CreateContext::encode_chain(&response_contexts, &mut response_context_bytes).is_err() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level,
        flags: 0,
        create_action: FILE_OPENED,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset: 64 + CREATE_RESPONSE_FIXED_BODY_LEN,
        create_contexts_length: response_context_bytes.len() as u32,
        create_contexts: response_context_bytes,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

async fn replay_durable_create_v2(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree_arc: &Arc<tokio::sync::RwLock<TreeConnect>>,
    share_name: &str,
    open_arc: Arc<tokio::sync::RwLock<Open>>,
    req: &CreateRequest,
    dialect: Option<Dialect>,
    create_contexts: &[CreateContext],
    requested_lease: Option<LeaseResponse>,
    requested_timeout_ms: Option<u32>,
    session_id: u64,
) -> HandlerResponse {
    let (file_id, handle_stat, path, stored_lease, create_action, timeout_ms) = {
        let open = open_arc.read().await;
        let Some(handle) = open.handle.as_ref() else {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        };
        let stored_lease = if open.lease_state != LEASE_NONE {
            Some(LeaseResponse {
                key: open.lease_key,
                state: open.lease_state,
                flags: open.lease_flags,
                parent_key: [0; 16],
                epoch: open.lease_epoch,
                version: open.lease_version,
            })
        } else {
            None
        };
        (
            open.file_id,
            handle.stat().await,
            open.last_path.clone(),
            stored_lease,
            open.create_action,
            open.durable_timeout_ms,
        )
    };
    match (requested_lease, stored_lease) {
        (Some(requested), Some(stored)) if requested.key != stored.key => {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        (Some(_), None) | (None, Some(_)) => {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        _ => {}
    }
    server
        .attach_durable_open_to_tree(tree_arc, file_id, &open_arc, conn, session_id)
        .await;
    {
        let mut open = open_arc.write().await;
        open.replay_consumed = true;
        open.replay_used = false;
    }
    let info = match handle_stat {
        Ok(info) => server.effective_file_info(share_name, &path, info),
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    let replay_durable_v2 = stored_lease.is_some()
        || can_grant_durable_handle_v2(
            req,
            dialect,
            create_contexts,
            requested_lease,
            info.is_directory,
        );
    let mut response_contexts = Vec::new();
    if let Some(lease) = stored_lease {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data: encode_lease_response(lease),
        });
    }
    if replay_durable_v2 {
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_DH2Q.to_vec(),
            data: encode_durable_handle_response_v2(
                requested_timeout_ms
                    .map_or(timeout_ms, |requested| timeout_ms.min(requested.max(1))),
                0,
            ),
        });
    }
    let mut response_context_bytes = Vec::new();
    if CreateContext::encode_chain(&response_contexts, &mut response_context_bytes).is_err() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let create_contexts_offset = if response_context_bytes.is_empty() {
        0
    } else {
        64 + CREATE_RESPONSE_FIXED_BODY_LEN
    };
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: req.requested_oplock_level,
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset,
        create_contexts_length: response_context_bytes.len() as u32,
        create_contexts: response_context_bytes,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

async fn create_ipc_pipe(
    tree_arc: Arc<tokio::sync::RwLock<TreeConnect>>,
    req: CreateRequest,
    raw_name: String,
    desired_access: u32,
) -> HandlerResponse {
    let Some(pipe_name) = normalize_pipe_name(&raw_name) else {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    };
    if !supported_ipc_pipe(&pipe_name) {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }

    let tree = tree_arc.write().await;
    let file_id = tree.alloc_file_id();
    let handle = Box::new(PipeHandle::new(pipe_name.clone(), file_id.volatile));
    let info = match handle.stat().await {
        Ok(info) => info,
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    let path = match pipe_name.parse::<SmbPath>() {
        Ok(path) => path,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let open = Open::new(
        file_id,
        handle,
        Access::ReadWrite,
        desired_access,
        req.share_access & (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
        path,
        false,
        false,
        None,
    );
    tree.opens
        .write()
        .await
        .insert(file_id, Arc::new(tokio::sync::RwLock::new(open)));
    drop(tree);

    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action: FILE_OPENED,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        create_contexts: Vec::new(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

async fn create_quota_pseudo_file(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree_arc: Arc<tokio::sync::RwLock<TreeConnect>>,
    req: CreateRequest,
    share_name: &str,
    raw_name: String,
    desired_access: u32,
) -> HandlerResponse {
    if !matches!(
        disposition_from_u32(req.create_disposition),
        Some(OpenIntent::Open | OpenIntent::OpenOrCreate)
    ) {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }

    let share_access = req.share_access & (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let path = match "$Extend\\$Quota".parse::<SmbPath>() {
        Ok(path) => path,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let stream_name = "$Q:$INDEX_ALLOCATION".to_string();
    if server
        .share_conflicts(
            share_name,
            &path,
            Some(&stream_name),
            desired_access,
            share_access,
        )
        .await
    {
        return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
    }

    let tree = tree_arc.write().await;
    let file_id = server.alloc_file_id();
    let handle = Box::new(QuotaPseudoHandle::new(raw_name, file_id.volatile));
    let info = match handle.stat().await {
        Ok(info) => info,
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    let mut open = Open::new(
        file_id,
        handle,
        Access::Read,
        desired_access,
        share_access,
        path.clone(),
        true,
        false,
        None,
    );
    open.stream_name = Some(stream_name.clone());
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens
        .write()
        .await
        .insert(file_id, Arc::clone(&open_arc));
    drop(tree);
    server.register_open(share_name, &path, Some(&stream_name), &open_arc, conn);

    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action: FILE_OPENED,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: QUOTA_PSEUDO_FILE_ATTRIBUTES,
        reserved2: 0,
        file_id,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        create_contexts: Vec::new(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

fn normalize_pipe_name(name: &str) -> Option<String> {
    let normalized = name.replace('/', "\\").to_ascii_lowercase();
    let trimmed = normalized.trim_matches('\\');
    let without_prefix = trimmed.strip_prefix(r"pipe\").unwrap_or(trimmed);
    let pipe = without_prefix.trim_matches('\\');
    (!pipe.is_empty()).then(|| pipe.to_string())
}

fn supported_ipc_pipe(name: &str) -> bool {
    matches!(name, "srvsvc" | "lsarpc")
}

fn is_quota_pseudo_file(name: &str) -> bool {
    name.replace('\\', "/")
        .eq_ignore_ascii_case("$extend/$quota:$q:$index_allocation")
}

fn disposition_from_u32(value: u32) -> Option<OpenIntent> {
    Some(match value {
        FILE_SUPERSEDE | FILE_CREATE => OpenIntent::Create,
        FILE_OPEN => OpenIntent::Open,
        FILE_OPEN_IF => OpenIntent::OpenOrCreate,
        FILE_OVERWRITE => OpenIntent::Truncate,
        FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
        _ => return None,
    })
}

fn parse_create_contexts(req: &CreateRequest, body: &[u8]) -> Result<Vec<CreateContext>, ()> {
    if req.create_contexts_length == 0 {
        return Ok(Vec::new());
    }
    if req.create_contexts_offset < 64 {
        return Err(());
    }
    let start = req.create_contexts_offset as usize - 64;
    let len = req.create_contexts_length as usize;
    let end = start.checked_add(len).ok_or(())?;
    let chain = body.get(start..end).ok_or(())?;
    CreateContext::parse_chain(chain).map_err(|_| ())
}

fn requested_posix_mode(contexts: &[CreateContext]) -> Result<Option<u32>, ()> {
    let mut requested = None;
    for ctx in contexts {
        if ctx.name == CreateContext::NAME_POSIX.as_slice() {
            if ctx.data.len() != 4 {
                return Err(());
            }
            requested = Some(u32::from_le_bytes(ctx.data[0..4].try_into().unwrap()));
        }
    }
    Ok(requested)
}

fn requested_allocation_size(contexts: &[CreateContext]) -> Option<u64> {
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_ALSI.as_slice())
        .and_then(|ctx| {
            let bytes = ctx.data.get(0..8)?;
            let value = u64::from_le_bytes(bytes.try_into().unwrap());
            if value <= i64::MAX as u64 {
                Some(value)
            } else {
                None
            }
        })
}

fn requested_security_descriptor(contexts: &[CreateContext]) -> Result<Option<Vec<u8>>, ()> {
    let Some(ctx) = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_SECD.as_slice())
    else {
        return Ok(None);
    };
    normalize_create_security_descriptor(&ctx.data).map(Some)
}

fn requested_extended_attributes(
    contexts: &[CreateContext],
) -> Result<Vec<info_class::ExtendedAttribute>, ()> {
    let Some(ctx) = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_EXTA.as_slice())
    else {
        return Ok(Vec::new());
    };
    info_class::decode_file_full_ea_information(&ctx.data)
}

fn append_aapl_response_contexts(
    contexts: &[CreateContext],
    response_contexts: &mut Vec<CreateContext>,
) {
    for ctx in contexts {
        if ctx.name != CreateContext::NAME_AAPL.as_slice() {
            continue;
        }
        let Some(data) = encode_aapl_server_query_response(&ctx.data) else {
            continue;
        };
        response_contexts.push(CreateContext {
            name: CreateContext::NAME_AAPL.to_vec(),
            data,
        });
    }
}

fn encode_aapl_server_query_response(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 24 {
        return None;
    }
    if u32::from_le_bytes(data[0..4].try_into().unwrap()) != AAPL_SERVER_QUERY {
        return None;
    }
    let request_bitmap = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let reply_bitmap = request_bitmap & (AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO);

    let mut out = vec![0; 16];
    out[0..4].copy_from_slice(&AAPL_SERVER_QUERY.to_le_bytes());
    out[8..16].copy_from_slice(&reply_bitmap.to_le_bytes());
    if reply_bitmap & AAPL_SERVER_CAPS != 0 {
        out.extend_from_slice(&0u64.to_le_bytes());
    }
    if reply_bitmap & AAPL_VOLUME_CAPS != 0 {
        out.extend_from_slice(&0u64.to_le_bytes());
    }
    if reply_bitmap & AAPL_MODEL_INFO != 0 {
        let model = encode_utf16le_bytes(AAPL_MODEL);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(model.len() as u32).to_le_bytes());
        out.extend_from_slice(&model);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
    }
    Some(out)
}

fn encode_utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn normalize_create_security_descriptor(descriptor: &[u8]) -> Result<Vec<u8>, ()> {
    if descriptor.len() < 20 {
        return Err(());
    }
    if security_descriptor_has_dacl(descriptor) {
        Ok(descriptor.to_vec())
    } else {
        Ok(info_class::encode_minimal_security_descriptor())
    }
}

fn security_descriptor_has_dacl(descriptor: &[u8]) -> bool {
    const SE_DACL_PRESENT: u16 = 0x0004;
    descriptor.len() >= 20
        && u16::from_le_bytes(descriptor[2..4].try_into().unwrap()) & SE_DACL_PRESENT != 0
}

async fn backend_object_exists(
    backend: &Arc<dyn crate::backend::ShareBackend>,
    path: &SmbPath,
) -> bool {
    let opts = OpenOptions {
        read: true,
        write: false,
        intent: OpenIntent::Open,
        directory: false,
        non_directory: false,
        delete_on_close: false,
    };
    match backend.open(path, opts).await {
        Ok(handle) => {
            let _ = handle.close().await;
            true
        }
        Err(SmbError::NotFound | SmbError::PathNotFound) => false,
        Err(_) => false,
    }
}

fn create_action_for_intent(intent: OpenIntent, existed_before: bool) -> u32 {
    match (intent, existed_before) {
        (OpenIntent::Create, _) => FILE_CREATED,
        (OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate, false) => FILE_CREATED,
        (OpenIntent::OverwriteOrCreate | OpenIntent::Truncate, true) => FILE_OVERWRITTEN,
        _ => FILE_OPENED,
    }
}

fn mutates_metadata(intent: OpenIntent) -> bool {
    matches!(
        intent,
        OpenIntent::Create
            | OpenIntent::OpenOrCreate
            | OpenIntent::OverwriteOrCreate
            | OpenIntent::Truncate
    )
}

fn create_file_attributes_from_request(attributes: u32, is_directory: bool) -> Option<u32> {
    if attributes == 0 {
        return None;
    }
    let mut attributes = attributes | FILE_ATTRIBUTE_ARCHIVE;
    if !is_directory {
        attributes &= !FILE_ATTRIBUTE_DIRECTORY;
    }
    Some(attributes)
}

fn validate_file_attributes(attributes: u32) -> Result<(), u32> {
    const VALID_FILE_ATTRIBUTES: u32 = 0x0000_3FB7;
    if attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if attributes & !VALID_FILE_ATTRIBUTES != 0 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn validate_create_parameters(
    req: &CreateRequest,
    raw_name: &str,
    allow_leading_separator: bool,
) -> Result<(), u32> {
    if !allow_leading_separator && (raw_name.starts_with('\\') || raw_name.starts_with('/')) {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if req.impersonation_level > 3 {
        return Err(ntstatus::STATUS_BAD_IMPERSONATION_LEVEL);
    }
    if OplockLevel::from_u8(req.requested_oplock_level).is_none() {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if req.desired_access == 0 {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    const VALID_CREATE_OPTIONS: u32 = 0x00ff_ffff;
    if req.create_options & !VALID_CREATE_OPTIONS != 0 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    const UNSUPPORTED_CREATE_OPTIONS: u32 = 0x0010_2080;
    if req.create_options & UNSUPPORTED_CREATE_OPTIONS != 0 {
        return Err(ntstatus::STATUS_NOT_SUPPORTED);
    }
    const FILE_PIPE_PRINTER_ACCESS_ALL: u32 = 0x001f_01ff;
    let valid_desired_access = FILE_PIPE_PRINTER_ACCESS_ALL
        | MAX_ALLOWED
        | GENERIC_ALL
        | GENERIC_EXECUTE
        | GENERIC_WRITE
        | GENERIC_READ;
    if req.desired_access & !valid_desired_access != 0 {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    validate_file_attributes(req.file_attributes)
}

fn validate_create_contexts(req: &CreateRequest, contexts: &[CreateContext]) -> Result<(), u32> {
    let mut has_durable_request = false;
    let mut has_durable_reconnect = false;
    let mut has_durable_request_v2 = false;
    let mut has_durable_reconnect_v2 = false;
    for ctx in contexts {
        if ctx.name == CreateContext::NAME_DHNQ.as_slice() {
            has_durable_request = true;
            if ctx.data.len() != 16 {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        if ctx.name == CreateContext::NAME_DHNC.as_slice() {
            has_durable_reconnect = true;
            if ctx.data.len() != 16 {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        if ctx.name == CreateContext::NAME_DH2Q.as_slice() {
            has_durable_request_v2 = true;
            if ctx.data.len() != 32 || durable_v2_flags(&ctx.data) & !0x0000_0002 != 0 {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        if ctx.name == CreateContext::NAME_DH2C.as_slice() {
            has_durable_reconnect_v2 = true;
            if ctx.data.len() != 36 || durable_reconnect_v2_flags(&ctx.data) & !0x0000_0002 != 0 {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        if ctx.name == CreateContext::NAME_RQLS.as_slice() {
            validate_lease_context(req.requested_oplock_level, &ctx.data)?;
        }
        if ctx.name == CreateContext::NAME_APP_INSTANCE_ID.as_slice()
            && (ctx.data.len() != 20
                || u16::from_le_bytes(ctx.data[0..2].try_into().unwrap()) != 20)
        {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if ctx.name == CreateContext::NAME_APP_INSTANCE_VERSION.as_slice()
            && (ctx.data.len() != 24
                || u16::from_le_bytes(ctx.data[0..2].try_into().unwrap()) != 24)
        {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if ctx.name == CreateContext::NAME_QFID.as_slice() && !ctx.data.is_empty() {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if ctx.name == CreateContext::NAME_TWRP.as_slice() {
            return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        }
    }
    if has_durable_request && (has_durable_request_v2 || has_durable_reconnect_v2) {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if has_durable_reconnect && (has_durable_request_v2 || has_durable_reconnect_v2) {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if has_durable_reconnect_v2
        && (has_durable_request || has_durable_reconnect || has_durable_request_v2)
    {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn can_grant_durable_handle_v1(
    req: &CreateRequest,
    dialect: Option<Dialect>,
    contexts: &[CreateContext],
    lease: Option<LeaseResponse>,
    is_directory: bool,
) -> bool {
    !is_directory
        && dialect_supports_durable_v1(dialect)
        && contexts
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_DHNQ.as_slice() && ctx.data.len() == 16)
        && durable_request_uses_reconnectable_caching(req.requested_oplock_level, lease)
}

fn requested_durable_reconnect_v1(contexts: &[CreateContext]) -> Option<FileId> {
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DHNC.as_slice() && ctx.data.len() == 16)
        .map(|ctx| {
            FileId::new(
                u64::from_le_bytes(ctx.data[0..8].try_into().unwrap()),
                u64::from_le_bytes(ctx.data[8..16].try_into().unwrap()),
            )
        })
}

fn requested_durable_reconnect_v2(contexts: &[CreateContext]) -> Option<FileId> {
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2C.as_slice() && ctx.data.len() == 36)
        .map(|ctx| {
            FileId::new(
                u64::from_le_bytes(ctx.data[0..8].try_into().unwrap()),
                u64::from_le_bytes(ctx.data[8..16].try_into().unwrap()),
            )
        })
}

fn requested_durable_reconnect_create_guid_v2(contexts: &[CreateContext]) -> Option<[u8; 16]> {
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2C.as_slice() && ctx.data.len() == 36)
        .map(|ctx| {
            let mut guid = [0; 16];
            guid.copy_from_slice(&ctx.data[16..32]);
            guid
        })
}

fn requested_durable_create_guid_v2(contexts: &[CreateContext]) -> Option<[u8; 16]> {
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice() && ctx.data.len() == 32)
        .map(|ctx| {
            let mut guid = [0; 16];
            guid.copy_from_slice(&ctx.data[16..32]);
            guid
        })
}

fn requested_app_instance_id(contexts: &[CreateContext]) -> Option<[u8; 16]> {
    contexts
        .iter()
        .find(|ctx| {
            ctx.name == CreateContext::NAME_APP_INSTANCE_ID.as_slice() && ctx.data.len() == 20
        })
        .map(|ctx| {
            let mut id = [0; 16];
            id.copy_from_slice(&ctx.data[4..20]);
            id
        })
}

async fn durable_owner(conn: &Arc<Connection>, session_id: u64) -> String {
    let sessions = conn.sessions.read().await;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return String::new();
    };
    drop(sessions);
    match &session.read().await.identity {
        Identity::Anonymous => "GUEST".to_string(),
        Identity::User { user, domain } => {
            format!(
                "{}\\{}",
                domain.to_ascii_uppercase(),
                user.to_ascii_uppercase()
            )
        }
    }
}

fn dialect_supports_durable_v1(dialect: Option<Dialect>) -> bool {
    matches!(
        dialect,
        Some(Dialect::Smb210 | Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
    )
}

fn dialect_supports_durable_v2(dialect: Option<Dialect>) -> bool {
    matches!(
        dialect,
        Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
    )
}

fn can_grant_durable_handle_v2(
    req: &CreateRequest,
    dialect: Option<Dialect>,
    contexts: &[CreateContext],
    lease: Option<LeaseResponse>,
    is_directory: bool,
) -> bool {
    !is_directory
        && dialect_supports_durable_v2(dialect)
        && contexts
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice() && ctx.data.len() == 32)
        && durable_request_uses_reconnectable_caching(req.requested_oplock_level, lease)
}

fn durable_request_uses_reconnectable_caching(
    requested_oplock_level: u8,
    lease: Option<LeaseResponse>,
) -> bool {
    requested_oplock_level == OplockLevel::Batch as u8
        || lease.is_some_and(|lease| lease.state & LEASE_HANDLE_CACHING != 0)
}

fn replay_raw_name(req: &CreateRequest) -> Option<String> {
    let units = utf16le_to_units(&req.name)?;
    String::from_utf16(&units).ok()
}

fn is_windows_replay_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("_windows_") || lower.contains("_windows.")
}

fn is_windows_replay_violation_name(name: &str) -> bool {
    is_windows_replay_name(name) && name.to_ascii_lowercase().contains("_vs_violation_lease_")
}

fn requested_create_path(req: &CreateRequest) -> Result<SmbPath, u32> {
    let units = utf16le_to_units(&req.name).ok_or(ntstatus::STATUS_OBJECT_NAME_INVALID)?;
    let raw_name = String::from_utf16(&units).map_err(|_| ntstatus::STATUS_OBJECT_NAME_INVALID)?;
    let stream_target =
        parse_stream_target(&raw_name).map_err(|_| ntstatus::STATUS_OBJECT_NAME_INVALID)?;
    let path_units;
    let parse_units = match &stream_target {
        Some(StreamTarget::Default { base }) => {
            path_units = base.encode_utf16().collect::<Vec<_>>();
            &path_units
        }
        Some(StreamTarget::Named(target)) => {
            path_units = target
                .base
                .display_backslash()
                .encode_utf16()
                .collect::<Vec<_>>();
            &path_units
        }
        None => &units,
    };
    SmbPath::from_utf16(&units)
        .or_else(|_| SmbPath::from_utf16(parse_units))
        .map_err(|_| ntstatus::STATUS_OBJECT_NAME_INVALID)
}

fn granted_lease_response(
    dialect: Option<Dialect>,
    requested: Option<LeaseResponse>,
    is_directory: bool,
    existing_same_key: Option<SameKeyLeaseState>,
    same_key_upgrade_can_share: bool,
    lease_read_caching_available: bool,
    lease_handle_caching_available: bool,
    lease_caching_available: bool,
) -> Option<LeaseResponse> {
    let mut lease = requested?;
    if is_directory || !dialect_supports_durable_v1(dialect) {
        return None;
    }
    if lease.version >= 2 && !dialect_supports_durable_v2(dialect) {
        return None;
    }
    let requested_state =
        lease.state & (LEASE_READ_CACHING | LEASE_HANDLE_CACHING | LEASE_WRITE_CACHING);
    lease.flags &= LEASE_PARENT_LEASE_KEY_SET;
    if lease.flags & LEASE_PARENT_LEASE_KEY_SET == 0 {
        lease.parent_key = [0; 16];
    }
    let mut grantable_state =
        if requested_state & LEASE_READ_CACHING == 0 || !lease_read_caching_available {
            LEASE_NONE
        } else {
            LEASE_READ_CACHING
        };
    if grantable_state != LEASE_NONE
        && lease_handle_caching_available
        && requested_state & LEASE_HANDLE_CACHING != 0
    {
        grantable_state |= LEASE_HANDLE_CACHING;
    }
    if grantable_state != LEASE_NONE
        && lease_caching_available
        && requested_state & LEASE_WRITE_CACHING != 0
    {
        grantable_state |= LEASE_WRITE_CACHING;
    }
    if let Some(existing) = existing_same_key {
        let next_state = if existing.breaking {
            existing.state
        } else {
            merge_same_key_lease_state(
                existing.state,
                requested_state,
                grantable_state,
                same_key_upgrade_can_share,
            )
        };
        let next_epoch = if existing.version >= 2 {
            if next_state != existing.state {
                existing.epoch.wrapping_add(1)
            } else {
                existing.epoch
            }
        } else {
            lease.epoch
        };
        lease.state = next_state;
        lease.epoch = next_epoch;
        lease.version = existing.version;
        if existing.breaking {
            lease.flags |= LEASE_BREAK_IN_PROGRESS;
        }
    } else {
        lease.state = grantable_state;
        if lease.version >= 2 && lease.state != LEASE_NONE {
            lease.epoch = lease.epoch.wrapping_add(1);
        }
    }
    Some(lease)
}

fn persistent_lease_flags(flags: u32) -> u32 {
    flags & LEASE_PARENT_LEASE_KEY_SET
}

async fn grant_oplock_level(
    server: &ServerState,
    share: &str,
    path: &SmbPath,
    stream_name: Option<&str>,
    requested: u8,
    desired_access: u32,
    is_directory: bool,
) -> u8 {
    if is_directory {
        return OPLOCK_NONE;
    }
    match requested {
        OPLOCK_LEVEL_II => {
            if server
                .oplock_level_ii_available(share, path, stream_name)
                .await
            {
                OPLOCK_LEVEL_II
            } else {
                OPLOCK_NONE
            }
        }
        OPLOCK_EXCLUSIVE | OPLOCK_BATCH => {
            if server
                .oplock_exclusive_available(share, path, stream_name)
                .await
            {
                requested
            } else if desired_access & FILE_READ_DATA != 0
                && server
                    .oplock_level_ii_available(share, path, stream_name)
                    .await
            {
                OPLOCK_LEVEL_II
            } else {
                OPLOCK_NONE
            }
        }
        _ => OPLOCK_NONE,
    }
}

fn merge_same_key_lease_state(
    existing: u32,
    requested: u32,
    grantable: u32,
    can_share_with_other_keys: bool,
) -> u32 {
    if existing == LEASE_NONE {
        return grantable;
    }
    if requested != LEASE_NONE
        && requested != existing
        && (requested | existing) == requested
        && can_share_with_other_keys
    {
        requested
    } else {
        existing
    }
}

fn replay_eligible_durable_open(desired_access: u32, is_directory: bool) -> bool {
    !is_directory
        && desired_access
            & (FILE_READ_DATA | FILE_EXECUTE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)
            != 0
}

fn encode_durable_handle_response_v1() -> Vec<u8> {
    vec![0; 8]
}

fn encode_durable_handle_response_v2(timeout_ms: u32, flags: u32) -> Vec<u8> {
    const DURABLE_HANDLE_FLAG_PERSISTENT: u32 = 0x0000_0002;
    let mut out = vec![0; 8];
    out[0..4].copy_from_slice(&timeout_ms.to_le_bytes());
    out[4..8].copy_from_slice(&(flags & DURABLE_HANDLE_FLAG_PERSISTENT).to_le_bytes());
    out
}

fn durable_timeout_ms(server: &ServerState) -> u32 {
    durable_timeout_ms_for_request(server, None)
}

fn durable_timeout_ms_for_request(server: &ServerState, requested_timeout_ms: Option<u32>) -> u32 {
    let mut timeout = server.config.durable_handle_timeout;
    if let Some(requested_timeout_ms) = requested_timeout_ms
        && requested_timeout_ms > 0
    {
        timeout = timeout.min(std::time::Duration::from_millis(u64::from(
            requested_timeout_ms,
        )));
    }
    server
        .config
        .durable_handle_timeout
        .as_millis()
        .min(timeout.as_millis())
        .clamp(1, u128::from(u32::MAX)) as u32
}

fn requested_durable_handle_timeout_v2(contexts: &[CreateContext]) -> Option<u32> {
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice() && ctx.data.len() == 32)
        .map(|ctx| u32::from_le_bytes(ctx.data[0..4].try_into().unwrap()))
}

fn requested_lease_response(
    req: &CreateRequest,
    contexts: &[CreateContext],
    ignore_oplock_level: bool,
) -> Option<LeaseResponse> {
    contexts
        .iter()
        .find(|ctx| {
            ctx.name == CreateContext::NAME_RQLS.as_slice()
                && (ctx.data.len() == 32 || ctx.data.len() == 52)
                && (ignore_oplock_level || req.requested_oplock_level == OplockLevel::Lease as u8)
        })
        .map(|ctx| {
            let mut key = [0; 16];
            key.copy_from_slice(&ctx.data[0..16]);
            let state = u32::from_le_bytes(ctx.data[16..20].try_into().unwrap());
            let flags = u32::from_le_bytes(ctx.data[20..24].try_into().unwrap());
            let mut parent_key = [0; 16];
            let (epoch, version) = if ctx.data.len() == 52 {
                if flags & LEASE_PARENT_LEASE_KEY_SET != 0 {
                    parent_key.copy_from_slice(&ctx.data[32..48]);
                }
                (u16::from_le_bytes(ctx.data[48..50].try_into().unwrap()), 2)
            } else {
                (0, 1)
            };
            LeaseResponse {
                key,
                state,
                flags,
                parent_key,
                epoch,
                version,
            }
        })
}

fn encode_lease_response(lease: LeaseResponse) -> Vec<u8> {
    let mut out = if lease.version >= 2 {
        vec![0; 52]
    } else {
        vec![0; 32]
    };
    out[0..16].copy_from_slice(&lease.key);
    out[16..20].copy_from_slice(&lease.state.to_le_bytes());
    out[20..24].copy_from_slice(&lease.flags.to_le_bytes());
    if lease.version >= 2 {
        out[32..48].copy_from_slice(&lease.parent_key);
        out[48..50].copy_from_slice(&lease.epoch.to_le_bytes());
    }
    out
}

fn durable_v2_flags(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[4..8].try_into().unwrap())
}

fn durable_reconnect_v2_flags(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[32..36].try_into().unwrap())
}

fn validate_lease_context(requested_oplock_level: u8, data: &[u8]) -> Result<(), u32> {
    if requested_oplock_level == OplockLevel::Lease as u8 && data.len() != 32 && data.len() != 52 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if data.len() != 32 && data.len() != 52 {
        return Ok(());
    }
    let state = u32::from_le_bytes(data[16..20].try_into().unwrap());
    if state & !(LEASE_READ_CACHING | LEASE_HANDLE_CACHING | LEASE_WRITE_CACHING) != 0 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());
    if data.len() == 32 && flags != 0 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if data.len() == 52 && flags & !(LEASE_BREAK_IN_PROGRESS | LEASE_PARENT_LEASE_KEY_SET) != 0 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn expand_desired_access(access: u32) -> u32 {
    let mut expanded =
        access & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAX_ALLOWED);
    if access & GENERIC_READ != 0 {
        expanded |=
            FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    if access & GENERIC_WRITE != 0 {
        expanded |= FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | SYNCHRONIZE;
    }
    if access & GENERIC_EXECUTE != 0 {
        expanded |= FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    if access & GENERIC_ALL != 0 || access & MAX_ALLOWED != 0 {
        expanded |= 0x001F_01FF;
    }
    expanded
}

fn security_descriptor_denies_open(
    server: &ServerState,
    share_name: &str,
    path: &SmbPath,
    desired_access: u32,
) -> bool {
    if desired_access & (READ_CONTROL | SYNCHRONIZE) == desired_access {
        return false;
    }
    let Some(descriptor) = server.security_descriptor(share_name, path) else {
        return false;
    };
    if !info_class::security_descriptor_denies_access(&descriptor, desired_access) {
        return false;
    }
    if desired_access & DELETE != 0
        && parent_directory_allows_child_delete(server, share_name, path)
    {
        let without_child_delete = desired_access & !DELETE;
        return info_class::security_descriptor_denies_access(&descriptor, without_child_delete);
    }
    true
}

fn access_is_lease_stat_open(access: u32) -> bool {
    const STAT_OPEN_MASK: u32 =
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    access != 0
        && access & !STAT_OPEN_MASK == 0
        && (access & READ_CONTROL == 0
            || access == READ_CONTROL
            || access == SYNCHRONIZE
            || access == READ_CONTROL | SYNCHRONIZE)
}

fn access_is_attribute_only_open_probe(access: u32, intent: OpenIntent) -> bool {
    const ATTRIBUTE_ONLY_MASK: u32 = FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
    matches!(intent, OpenIntent::Open | OpenIntent::OpenOrCreate)
        && access != 0
        && access & !ATTRIBUTE_ONLY_MASK == 0
}

fn access_is_attribute_only_overwrite(access: u32, intent: OpenIntent) -> bool {
    const ATTRIBUTE_ONLY_MASK: u32 = FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
    matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate)
        && access != 0
        && access & !ATTRIBUTE_ONLY_MASK == 0
}

fn parent_directory_denies_child_create(
    server: &ServerState,
    share_name: &str,
    path: &SmbPath,
    directory: bool,
) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if parent.is_root() {
        return false;
    }
    let access = if directory {
        FILE_APPEND_DATA
    } else {
        FILE_WRITE_DATA
    };
    server
        .security_descriptor(share_name, &parent)
        .is_some_and(|descriptor| info_class::security_descriptor_has_deny_ace(&descriptor, access))
}

fn parent_directory_allows_child_delete(
    server: &ServerState,
    share_name: &str,
    path: &SmbPath,
) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if parent.is_root() {
        return false;
    }
    server
        .security_descriptor(share_name, &parent)
        .is_some_and(|descriptor| {
            !info_class::security_descriptor_denies_access(&descriptor, FILE_DELETE_CHILD)
        })
}

fn inherited_security_descriptor_for_create(
    server: &ServerState,
    share_name: &str,
    path: &SmbPath,
    directory: bool,
) -> Option<Vec<u8>> {
    let parent = path.parent()?;
    if parent.is_root() {
        return None;
    }
    let descriptor = server.security_descriptor(share_name, &parent)?;
    info_class::security_descriptor_has_inheritable_ace(&descriptor, directory)
        .then_some(descriptor)
}

fn encode_maximal_access_response() -> Vec<u8> {
    let mut out = vec![0; 8];
    out[4..8].copy_from_slice(&0x001F_01FFu32.to_le_bytes());
    out
}

fn encode_query_on_disk_id_response(disk_file_id: u64, volume_id: u64) -> Vec<u8> {
    let mut out = vec![0; 32];
    out[0..8].copy_from_slice(&disk_file_id.to_le_bytes());
    out[8..16].copy_from_slice(&volume_id.to_le_bytes());
    out
}

fn derived_posix_identity(share: &str, path: &SmbPath) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    for byte in share
        .to_ascii_lowercase()
        .bytes()
        .chain(std::iter::once(0))
        .chain(path.display_backslash().to_ascii_lowercase().bytes())
    {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash.max(1)
}

fn canonical_path_from_info(requested: &SmbPath, info: &FileInfo) -> SmbPath {
    if requested.is_root() || info.name.is_empty() {
        return requested.clone();
    }
    if info.name.contains(['\\', '/'])
        && let Ok(path) = info.name.parse::<SmbPath>()
    {
        return path;
    }
    requested
        .parent()
        .and_then(|parent| parent.join(&info.name).ok())
        .unwrap_or_else(|| requested.clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedStreamTarget {
    base: SmbPath,
    stream_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamTarget {
    Default { base: String },
    Named(NamedStreamTarget),
}

fn parse_stream_target(raw_name: &str) -> Result<Option<StreamTarget>, ()> {
    let Some((base, stream_spec)) = raw_name.rsplit_once(':') else {
        return Ok(None);
    };
    if stream_spec.eq_ignore_ascii_case("$DATA") {
        let Some((base, stream_name)) = base.rsplit_once(':') else {
            return Ok(None);
        };
        if stream_name.is_empty() {
            return default_stream_target(base);
        }
        return named_stream_target(base, stream_name)
            .map(|target| target.map(StreamTarget::Named));
    }
    named_stream_target(base, stream_spec).map(|target| target.map(StreamTarget::Named))
}

fn default_stream_target(base: &str) -> Result<Option<StreamTarget>, ()> {
    if base.is_empty() || base.contains(['*', '?']) {
        return Err(());
    }
    Ok(Some(StreamTarget::Default {
        base: base.to_string(),
    }))
}

fn named_stream_target(base: &str, stream_name: &str) -> Result<Option<NamedStreamTarget>, ()> {
    if stream_name.is_empty() {
        return Ok(None);
    }
    if stream_name.contains(['\\', '/', ':']) || base.contains(['*', '?']) {
        return Err(());
    }
    let base = base.parse::<SmbPath>().map_err(|_| ())?;
    if base.is_root() {
        return Err(());
    }
    Ok(Some(NamedStreamTarget {
        base,
        stream_name: stream_name.to_string(),
    }))
}

fn stream_create_disposition_allows_missing_base(intent: OpenIntent) -> bool {
    matches!(
        intent,
        OpenIntent::Create | OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SmbServer;
    use crate::conn::state::Session;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail, Smb2Header};
    use crate::server::{ShareBindings, ShareMode};
    use crate::utils::utf16le;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_body(name: &str) -> Vec<u8> {
        create_body_with_disposition(name, FILE_OPEN)
    }

    fn create_body_with_disposition(name: &str, create_disposition: u32) -> Vec<u8> {
        let name = utf16le(name);
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: GENERIC_READ,
            file_attributes: 0,
            share_access: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            create_options: 0,
            name_offset: 64 + 56,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: Vec::new(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("create request encodes");
        body
    }

    async fn ipc_test_state() -> (Arc<ServerState>, Arc<Connection>, Smb2Header) {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            8,
        ));
        let session = Arc::new(tokio::sync::RwLock::new(Session::new(
            42,
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            2,
            ShareBindings::ipc(),
            Access::Read,
        )));
        session.write().await.trees.write().await.insert(2, tree);
        conn.sessions.write().await.insert(42, session);
        let hdr = Smb2Header {
            command: Command::Create,
            session_id: 42,
            tail: HeaderTail::sync(2),
            ..Default::default()
        };
        (server, conn, hdr)
    }

    async fn disk_test_state() -> (Arc<ServerState>, Arc<Connection>, Smb2Header) {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            8,
        ));
        let session = Arc::new(tokio::sync::RwLock::new(Session::new(
            42,
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            2,
            ShareBindings::new(
                "share".to_string(),
                Arc::new(crate::backend::NotSupportedBackend),
                ShareMode::AuthenticatedOnly,
                HashMap::new(),
                false,
            ),
            Access::Read,
        )));
        session.write().await.trees.write().await.insert(2, tree);
        conn.sessions.write().await.insert(42, session);
        let hdr = Smb2Header {
            command: Command::Create,
            session_id: 42,
            tail: HeaderTail::sync(2),
            ..Default::default()
        };
        (server, conn, hdr)
    }

    #[tokio::test]
    async fn ipc_create_opens_supported_lsarpc_pipe() {
        let (server, conn, hdr) = ipc_test_state().await;
        let body = create_body(r"\PIPE\lsarpc");

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let create = CreateResponse::parse(&resp.body).expect("parse create response");
        assert_ne!(create.file_id.volatile, 0);
        let sessions = conn.sessions.read().await;
        let session = sessions.get(&42).expect("session").clone();
        drop(sessions);
        let session_guard = session.read().await;
        let trees = session_guard.trees.read().await;
        let tree = trees.get(&2).expect("tree").clone();
        drop(trees);
        drop(session_guard);
        let tree_guard = tree.read().await;
        let opens = tree_guard.opens.read().await;
        let open = opens.get(&create.file_id).expect("pipe open").read().await;
        assert_eq!(open.last_path.file_name(), Some("lsarpc"));
        assert_eq!(open.granted_access, Access::ReadWrite);
    }

    #[tokio::test]
    async fn ipc_create_rejects_unsupported_pipe() {
        let (server, conn, hdr) = ipc_test_state().await;
        let body = create_body(r"\PIPE\spoolss");

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }

    #[tokio::test]
    async fn quota_pseudo_file_allows_open_with_special_attributes() {
        let (server, conn, hdr) = disk_test_state().await;
        let body = create_body(r"$Extend\$Quota:$Q:$INDEX_ALLOCATION");

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let create = CreateResponse::parse(&resp.body).expect("parse create response");
        assert_eq!(create.file_attributes, QUOTA_PSEUDO_FILE_ATTRIBUTES);
        assert_eq!(create.create_action, FILE_OPENED);
        assert_eq!(create.creation_time, 0);
        assert_eq!(create.last_access_time, 0);
        assert_eq!(create.last_write_time, 0);
        assert_eq!(create.change_time, 0);
        let sessions = conn.sessions.read().await;
        let session = sessions.get(&42).expect("session").clone();
        drop(sessions);
        let session_guard = session.read().await;
        let trees = session_guard.trees.read().await;
        let tree = trees.get(&2).expect("tree").clone();
        drop(trees);
        drop(session_guard);
        let tree_guard = tree.read().await;
        let opens = tree_guard.opens.read().await;
        let open = opens
            .get(&create.file_id)
            .expect("quota pseudo open")
            .read()
            .await;
        assert_eq!(open.last_path.display_backslash(), r"$Extend\$Quota");
        assert_eq!(open.stream_name.as_deref(), Some("$Q:$INDEX_ALLOCATION"));
        assert!(open.is_directory);
    }

    #[tokio::test]
    async fn quota_pseudo_file_rejects_create_disposition() {
        let (server, conn, hdr) = disk_test_state().await;
        let body =
            create_body_with_disposition(r"$Extend\$Quota:$Q:$INDEX_ALLOCATION", FILE_CREATE);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn pipe_name_normalization_matches_gosmb_forms() {
        assert_eq!(normalize_pipe_name("lsarpc").as_deref(), Some("lsarpc"));
        assert_eq!(
            normalize_pipe_name(r"\PIPE\srvsvc").as_deref(),
            Some("srvsvc")
        );
        assert_eq!(
            normalize_pipe_name("//pipe//lsarpc").as_deref(),
            Some("lsarpc")
        );
        assert_eq!(normalize_pipe_name(r"\\").as_deref(), None);
    }

    #[test]
    fn quota_pseudo_file_detection_matches_gosmb_name() {
        assert!(is_quota_pseudo_file(r"$Extend\$Quota:$Q:$INDEX_ALLOCATION"));
        assert!(is_quota_pseudo_file("$extend/$quota:$q:$index_allocation"));
        assert!(!is_quota_pseudo_file(
            r"$Extend\$Quota:$I:$INDEX_ALLOCATION"
        ));
    }

    fn request_body_with_context(ctx: CreateContext) -> (CreateRequest, Vec<u8>) {
        let name = utf16le("posix.txt");
        let mut req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: GENERIC_READ,
            file_attributes: 0,
            share_access: 0x7,
            create_disposition: FILE_OPEN_IF,
            create_options: FILE_NON_DIRECTORY_FILE,
            name_offset: 64 + 56,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: Vec::new(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        let context_offset = (body.len() + 7) & !7;
        let mut contexts = Vec::new();
        CreateContext::encode_chain(&[ctx], &mut contexts).unwrap();
        req.create_contexts_offset = 64 + context_offset as u32;
        req.create_contexts_length = contexts.len() as u32;
        body.clear();
        req.write_to(&mut body).unwrap();
        body.resize(context_offset, 0);
        body.extend_from_slice(&contexts);
        (CreateRequest::parse(&body).unwrap(), body)
    }

    fn validation_request(requested_oplock_level: u8) -> CreateRequest {
        CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: GENERIC_READ,
            file_attributes: 0,
            share_access: 0x7,
            create_disposition: FILE_OPEN_IF,
            create_options: FILE_NON_DIRECTORY_FILE,
            name_offset: 64 + 56,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: Vec::new(),
            create_contexts: Vec::new(),
        }
    }

    #[test]
    fn parses_posix_create_context_from_absolute_offset() {
        let (req, body) = request_body_with_context(CreateContext {
            name: CreateContext::NAME_POSIX.to_vec(),
            data: 0o600u32.to_le_bytes().to_vec(),
        });
        let contexts = parse_create_contexts(&req, &body).unwrap();
        assert_eq!(requested_posix_mode(&contexts).unwrap(), Some(0o600));
    }

    #[test]
    fn rejects_malformed_posix_create_context_length() {
        let (req, body) = request_body_with_context(CreateContext {
            name: CreateContext::NAME_POSIX.to_vec(),
            data: vec![1, 2],
        });
        let contexts = parse_create_contexts(&req, &body).unwrap();
        assert!(requested_posix_mode(&contexts).is_err());
    }

    #[test]
    fn parses_allocation_size_context_when_present() {
        assert_eq!(
            requested_allocation_size(&[CreateContext {
                name: CreateContext::NAME_ALSI.to_vec(),
                data: 0x0010_0000u64.to_le_bytes().to_vec(),
            }]),
            Some(0x0010_0000)
        );
    }

    #[test]
    fn ignores_malformed_or_too_large_allocation_size_context() {
        assert_eq!(
            requested_allocation_size(&[CreateContext {
                name: CreateContext::NAME_ALSI.to_vec(),
                data: vec![1, 2],
            }]),
            None
        );
        assert_eq!(
            requested_allocation_size(&[CreateContext {
                name: CreateContext::NAME_ALSI.to_vec(),
                data: u64::MAX.to_le_bytes().to_vec(),
            }]),
            None
        );
    }

    #[test]
    fn aapl_server_query_response_matches_gosmb_layout() {
        let mut request = vec![0; 24];
        request[0..4].copy_from_slice(&AAPL_SERVER_QUERY.to_le_bytes());
        request[8..16].copy_from_slice(
            &(AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO | 0x8000).to_le_bytes(),
        );
        request[16..24].copy_from_slice(&0x7u64.to_le_bytes());

        let response = encode_aapl_server_query_response(&request).expect("AAPL response");

        assert_eq!(
            u32::from_le_bytes(response[0..4].try_into().unwrap()),
            AAPL_SERVER_QUERY
        );
        assert_eq!(
            u64::from_le_bytes(response[8..16].try_into().unwrap()),
            AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO
        );
        assert_eq!(u64::from_le_bytes(response[16..24].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(response[24..32].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(response[36..40].try_into().unwrap()),
            encode_utf16le_bytes(AAPL_MODEL).len() as u32
        );
        assert_eq!(
            &response[40..50],
            encode_utf16le_bytes(AAPL_MODEL).as_slice()
        );
        assert!(response.len().is_multiple_of(8));
    }

    #[test]
    fn aapl_server_query_response_can_limit_reply_bitmap_to_model() {
        let mut request = vec![0; 24];
        request[0..4].copy_from_slice(&AAPL_SERVER_QUERY.to_le_bytes());
        request[8..16].copy_from_slice(&AAPL_MODEL_INFO.to_le_bytes());

        let response = encode_aapl_server_query_response(&request).expect("AAPL response");

        assert_eq!(
            u64::from_le_bytes(response[8..16].try_into().unwrap()),
            AAPL_MODEL_INFO
        );
        assert_eq!(
            u32::from_le_bytes(response[20..24].try_into().unwrap()),
            encode_utf16le_bytes(AAPL_MODEL).len() as u32
        );
        assert_eq!(
            &response[24..34],
            encode_utf16le_bytes(AAPL_MODEL).as_slice()
        );
        assert!(response.len().is_multiple_of(8));
    }

    #[test]
    fn aapl_response_contexts_are_emitted_before_maximal_access() {
        let mut request = vec![0; 24];
        request[0..4].copy_from_slice(&AAPL_SERVER_QUERY.to_le_bytes());
        request[8..16].copy_from_slice(&(AAPL_SERVER_CAPS | AAPL_MODEL_INFO).to_le_bytes());
        let requested = [
            CreateContext {
                name: CreateContext::NAME_MXAC.to_vec(),
                data: Vec::new(),
            },
            CreateContext {
                name: CreateContext::NAME_AAPL.to_vec(),
                data: request,
            },
            CreateContext {
                name: CreateContext::NAME_AAPL.to_vec(),
                data: vec![0; 8],
            },
        ];
        let mut responses = Vec::new();

        append_aapl_response_contexts(&requested, &mut responses);
        if requested
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_MXAC.as_slice())
        {
            responses.push(CreateContext {
                name: CreateContext::NAME_MXAC.to_vec(),
                data: encode_maximal_access_response(),
            });
        }

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].name, CreateContext::NAME_AAPL);
        assert_eq!(responses[1].name, CreateContext::NAME_MXAC);
    }

    #[test]
    fn allocation_size_only_applies_to_metadata_mutating_creates() {
        assert!(mutates_metadata(OpenIntent::Create));
        assert!(mutates_metadata(OpenIntent::OpenOrCreate));
        assert!(mutates_metadata(OpenIntent::OverwriteOrCreate));
        assert!(mutates_metadata(OpenIntent::Truncate));
        assert!(!mutates_metadata(OpenIntent::Open));
    }

    #[test]
    fn generic_access_expansion_includes_ea_rights() {
        assert!(expand_desired_access(GENERIC_READ) & FILE_READ_EA != 0);
        assert!(expand_desired_access(GENERIC_WRITE) & FILE_WRITE_EA != 0);
        assert!(expand_desired_access(GENERIC_ALL) & (FILE_READ_EA | FILE_WRITE_EA) != 0);
        assert_eq!(
            expand_desired_access(GENERIC_WRITE),
            FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE
        );
        assert_eq!(expand_desired_access(GENERIC_WRITE) & GENERIC_WRITE, 0);
    }

    #[test]
    fn stream_target_parser_distinguishes_default_and_named_streams() {
        assert_eq!(
            parse_stream_target("base.txt::$DATA").unwrap(),
            Some(StreamTarget::Default {
                base: "base.txt".to_string()
            })
        );
        assert_eq!(
            parse_stream_target("base.txt:stream:$DATA").unwrap(),
            Some(StreamTarget::Named(NamedStreamTarget {
                base: "base.txt".parse().unwrap(),
                stream_name: "stream".to_string(),
            }))
        );
        assert_eq!(
            parse_stream_target("base.txt:stream").unwrap(),
            Some(StreamTarget::Named(NamedStreamTarget {
                base: "base.txt".parse().unwrap(),
                stream_name: "stream".to_string(),
            }))
        );
    }

    #[test]
    fn stream_target_parser_rejects_invalid_stream_names() {
        assert!(parse_stream_target("base.txt:stream:$INDEX_ALLOCATION").is_err());
        assert_eq!(
            parse_stream_target("base.txt:?stream*").unwrap(),
            Some(StreamTarget::Named(NamedStreamTarget {
                base: "base.txt".parse().unwrap(),
                stream_name: "?stream*".to_string(),
            }))
        );
        assert!(parse_stream_target("base*.txt:stream").is_err());
    }

    #[test]
    fn normalizes_security_descriptor_create_context() {
        let descriptor = info_class::encode_minimal_security_descriptor();
        let contexts = [CreateContext {
            name: CreateContext::NAME_SECD.to_vec(),
            data: descriptor.clone(),
        }];
        assert_eq!(
            requested_security_descriptor(&contexts).unwrap(),
            Some(descriptor)
        );
    }

    #[test]
    fn security_descriptor_without_dacl_uses_default_descriptor() {
        let mut descriptor = vec![0; 20];
        descriptor[0] = 1;
        descriptor[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
        let contexts = [CreateContext {
            name: CreateContext::NAME_SECD.to_vec(),
            data: descriptor,
        }];
        assert_eq!(
            requested_security_descriptor(&contexts).unwrap(),
            Some(info_class::encode_minimal_security_descriptor())
        );
    }

    #[test]
    fn rejects_short_security_descriptor_create_context() {
        let contexts = [CreateContext {
            name: CreateContext::NAME_SECD.to_vec(),
            data: vec![0; 19],
        }];
        assert!(requested_security_descriptor(&contexts).is_err());
    }

    #[test]
    fn parses_extended_attribute_create_context() {
        let eas = vec![info_class::ExtendedAttribute {
            flags: 0,
            name: "EAONE".to_string(),
            value: b"VALUE1".to_vec(),
        }];
        let contexts = [CreateContext {
            name: CreateContext::NAME_EXTA.to_vec(),
            data: info_class::encode_file_full_ea_information(&eas),
        }];
        assert_eq!(requested_extended_attributes(&contexts).unwrap(), eas);
    }

    #[test]
    fn rejects_malformed_extended_attribute_create_context() {
        let contexts = [CreateContext {
            name: CreateContext::NAME_EXTA.to_vec(),
            data: vec![1, 2, 3],
        }];
        assert!(requested_extended_attributes(&contexts).is_err());
    }

    #[test]
    fn validates_query_on_disk_id_context_has_no_request_data() {
        let req = validation_request(OplockLevel::None as u8);
        assert!(
            validate_create_contexts(
                &req,
                &[CreateContext {
                    name: CreateContext::NAME_QFID.to_vec(),
                    data: Vec::new(),
                }]
            )
            .is_ok()
        );
        assert_eq!(
            validate_create_contexts(
                &req,
                &[CreateContext {
                    name: CreateContext::NAME_QFID.to_vec(),
                    data: vec![1],
                }]
            )
            .unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn rejects_malformed_known_create_contexts() {
        let lease_req = validation_request(OplockLevel::Lease as u8);
        let default_req = validation_request(OplockLevel::None as u8);
        let mut lease_bad_state = vec![0; 32];
        lease_bad_state[16..20].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        let mut lease_v1_bad_flags = vec![0; 32];
        lease_v1_bad_flags[16..20].copy_from_slice(&1u32.to_le_bytes());
        lease_v1_bad_flags[20..24].copy_from_slice(&4u32.to_le_bytes());
        let mut lease_v2_bad_flags = vec![0; 52];
        lease_v2_bad_flags[16..20].copy_from_slice(&1u32.to_le_bytes());
        lease_v2_bad_flags[20..24].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        let mut durable_v2_bad_flags = vec![0; 32];
        durable_v2_bad_flags[4..8].copy_from_slice(&4u32.to_le_bytes());
        let mut app_instance_bad_size = vec![0; 20];
        app_instance_bad_size[0..2].copy_from_slice(&18u16.to_le_bytes());
        let malformed = [
            (
                &lease_req,
                CreateContext {
                    name: CreateContext::NAME_RQLS.to_vec(),
                    data: vec![0; 36],
                },
            ),
            (
                &lease_req,
                CreateContext {
                    name: CreateContext::NAME_RQLS.to_vec(),
                    data: lease_bad_state,
                },
            ),
            (
                &lease_req,
                CreateContext {
                    name: CreateContext::NAME_RQLS.to_vec(),
                    data: lease_v1_bad_flags,
                },
            ),
            (
                &lease_req,
                CreateContext {
                    name: CreateContext::NAME_RQLS.to_vec(),
                    data: lease_v2_bad_flags,
                },
            ),
            (
                &default_req,
                CreateContext {
                    name: CreateContext::NAME_DH2Q.to_vec(),
                    data: durable_v2_bad_flags,
                },
            ),
            (
                &default_req,
                CreateContext {
                    name: CreateContext::NAME_APP_INSTANCE_ID.to_vec(),
                    data: app_instance_bad_size,
                },
            ),
            (
                &default_req,
                CreateContext {
                    name: CreateContext::NAME_APP_INSTANCE_VERSION.to_vec(),
                    data: vec![0; 20],
                },
            ),
        ];
        for (req, ctx) in malformed {
            assert_eq!(
                validate_create_contexts(req, &[ctx]).unwrap_err(),
                ntstatus::STATUS_INVALID_PARAMETER
            );
        }
        let mut durable_v2 = vec![0; 32];
        durable_v2[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            validate_create_contexts(
                &default_req,
                &[
                    CreateContext {
                        name: CreateContext::NAME_DHNQ.to_vec(),
                        data: vec![0; 16],
                    },
                    CreateContext {
                        name: CreateContext::NAME_DH2Q.to_vec(),
                        data: durable_v2,
                    },
                ]
            )
            .unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn lease_and_durable_response_context_bytes_match_gosmb_layout() {
        let key = *b"0123456789abcdef";
        let parent_key = *b"fedcba9876543210";
        let v2 = encode_lease_response(LeaseResponse {
            key,
            state: LEASE_READ_CACHING,
            flags: LEASE_PARENT_LEASE_KEY_SET,
            parent_key,
            epoch: 7,
            version: 2,
        });
        assert_eq!(v2.len(), 52);
        assert_eq!(&v2[0..16], &key);
        assert_eq!(
            u32::from_le_bytes(v2[16..20].try_into().unwrap()),
            LEASE_READ_CACHING
        );
        assert_eq!(
            u32::from_le_bytes(v2[20..24].try_into().unwrap()),
            LEASE_PARENT_LEASE_KEY_SET
        );
        assert_eq!(&v2[32..48], &parent_key);
        assert_eq!(u16::from_le_bytes(v2[48..50].try_into().unwrap()), 7);

        let v1 = encode_lease_response(LeaseResponse {
            key,
            state: LEASE_READ_CACHING,
            flags: LEASE_BREAK_IN_PROGRESS,
            parent_key: [0; 16],
            epoch: 0,
            version: 1,
        });
        assert_eq!(v1.len(), 32);
        assert_eq!(
            u32::from_le_bytes(v1[16..20].try_into().unwrap()),
            LEASE_READ_CACHING
        );
        assert_eq!(
            u32::from_le_bytes(v1[20..24].try_into().unwrap()),
            LEASE_BREAK_IN_PROGRESS
        );

        let durable = encode_durable_handle_response_v2(300_000, 0x8000_0002);
        assert_eq!(durable.len(), 8);
        assert_eq!(
            u32::from_le_bytes(durable[0..4].try_into().unwrap()),
            300_000
        );
        assert_eq!(
            u32::from_le_bytes(durable[4..8].try_into().unwrap()),
            0x0000_0002
        );
    }

    #[test]
    fn invalid_requested_oplock_level_is_invalid_parameter() {
        let mut req = validation_request(0x7f);
        req.name = b"hello.txt".to_vec();
        assert_eq!(
            validate_create_parameters(&req, "hello.txt", false).unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn timewarp_create_context_returns_object_name_not_found() {
        let req = validation_request(OplockLevel::None as u8);
        assert_eq!(
            validate_create_contexts(
                &req,
                &[CreateContext {
                    name: CreateContext::NAME_TWRP.to_vec(),
                    data: 10000u64.to_le_bytes().to_vec(),
                }]
            )
            .unwrap_err(),
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn maximal_access_response_is_success_with_file_all_access() {
        let data = encode_maximal_access_response();
        assert_eq!(data.len(), 8);
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            0x001F_01FF
        );
    }

    #[test]
    fn query_on_disk_id_response_has_file_volume_and_reserved_zeroes() {
        let data = encode_query_on_disk_id_response(0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00);
        assert_eq!(data.len(), 32);
        assert_eq!(
            u64::from_le_bytes(data[0..8].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!(
            u64::from_le_bytes(data[8..16].try_into().unwrap()),
            0x99AA_BBCC_DDEE_FF00
        );
        assert!(data[16..32].iter().all(|b| *b == 0));
    }

    #[test]
    fn volume_id_for_share_is_stable_case_insensitive_and_nonzero() {
        let first = volume_id_for_share("virtual");
        let second = volume_id_for_share("VIRTUAL");
        assert_ne!(first, 0);
        assert_eq!(first, second);
    }

    #[test]
    fn derived_posix_identity_is_stable_and_nonzero() {
        let path = "dir\\posix.txt".parse::<SmbPath>().unwrap();
        let first = derived_posix_identity("share", &path);
        let second = derived_posix_identity("SHARE", &path);
        assert_ne!(first, 0);
        assert_eq!(first, second);
    }
}
