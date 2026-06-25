//! SET_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, SetInfoRequest, SetInfoResponse};

use crate::backend::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
    FILE_ATTRIBUTE_TEMPORARY, FileTimes, OpenIntent, OpenOptions, ShareBackend,
};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::{ServerState, StreamHandle};
use crate::utils::utf16le_to_units;

const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

const LEASE_NONE: u32 = 0x0000_0000;
const LEASE_READ_CACHING: u32 = 0x0000_0001;
const LEASE_WRITE_CACHING: u32 = 0x0000_0004;
const OPLOCK_NONE: u8 = 0x00;

const FILE_DISPOSITION_DELETE: u32 = 0x0000_0001;
const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x0000_0002;
const FILE_DISPOSITION_ON_CLOSE: u32 = 0x0000_0008;
const FILE_DISPOSITION_IGNORE_READONLY: u32 = 0x0000_0010;

const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x0000_0002;
const FILE_RENAME_IGNORE_READONLY: u32 = 0x0000_0040;

const NTTIME_OMIT: u64 = 0;
const NTTIME_FREEZE: u64 = u64::MAX;
const NTTIME_THAW: u64 = u64::MAX - 1;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    handle_inner(server, conn, hdr, body, true).await
}

async fn handle_inner(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    allow_cache_break: bool,
) -> HandlerResponse {
    let req = match SetInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match InfoType::from_u8(req.info_type) {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    let class = req.file_information_class;
    let buffer = req.buffer;
    let (backend, share_name) = {
        let tree = tree_arc.read().await;
        (tree.share.backend.clone(), tree.share.name.clone())
    };

    if matches!(info_type, InfoType::Security) {
        let open = open_arc.read().await;
        if open.desired_access & (WRITE_DAC | WRITE_OWNER) == 0 {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        let path = open.last_path.clone();
        let is_directory = open.is_directory;
        drop(open);
        let Some(descriptor) = ic::normalize_set_security_descriptor(&buffer) else {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        };
        server.set_security_descriptor(&share_name, &path, descriptor);
        server
            .notify_security_modified(&share_name, &path, is_directory)
            .await;
        let mut buf = Vec::new();
        SetInfoResponse::default()
            .write_to(&mut buf)
            .expect("encode");
        return HandlerResponse::ok(buf);
    }
    if !matches!(info_type, InfoType::File) {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }

    let desired_access = open_arc.read().await.desired_access;
    if !set_file_access_allowed(class, desired_access) {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let result = match class {
        ic::FILE_BASIC_INFORMATION => {
            if buffer.len() < 40 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let creation = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let access = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
            let write = u64::from_le_bytes(buffer[16..24].try_into().unwrap());
            let change = u64::from_le_bytes(buffer[24..32].try_into().unwrap());
            let attributes = u32::from_le_bytes(buffer[32..36].try_into().unwrap());
            // Omit/freeze/thaw sentinel values mean "do not change" for SET_INFO.
            let to_some = |v: u64| {
                if matches!(v, NTTIME_OMIT | NTTIME_FREEZE | NTTIME_THAW) {
                    None
                } else {
                    Some(v)
                }
            };
            let times = FileTimes {
                creation_time: to_some(creation),
                last_access_time: to_some(access),
                last_write_time: to_some(write),
                change_time: to_some(change),
            };
            let times_changed = times.creation_time.is_some()
                || times.last_access_time.is_some()
                || times.last_write_time.is_some()
                || times.change_time.is_some();
            let open = open_arc.read().await;
            let path = open.last_path.clone();
            let stream_name = open.stream_name.clone();
            let is_directory = open.is_directory;
            let file_id = open.file_id;
            let mut notify_attributes = None;
            if attributes != 0 {
                if !is_directory && attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
                }
                if is_directory && attributes & FILE_ATTRIBUTE_TEMPORARY != 0 {
                    return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
                }
                server.set_file_attributes(
                    &share_name,
                    &path,
                    set_info_file_attributes(attributes, is_directory),
                    is_directory,
                );
                notify_attributes = Some((path.clone(), is_directory));
            }
            let set_times = match open.handle.as_ref() {
                Some(h) => h.set_times(times).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            drop(open);
            if set_times.is_ok() && stream_name.is_some() && times_changed {
                let base_handle = match backend
                    .open(
                        &path,
                        OpenOptions {
                            read: true,
                            write: true,
                            intent: OpenIntent::Open,
                            directory: false,
                            non_directory: false,
                            delete_on_close: false,
                        },
                    )
                    .await
                {
                    Ok(handle) => handle,
                    Err(e) => return HandlerResponse::err(e.to_nt_status()),
                };
                if let Err(e) = base_handle.set_times(times).await {
                    let _ = base_handle.close().await;
                    return HandlerResponse::err(e.to_nt_status());
                }
                let _ = base_handle.close().await;
            }
            if set_times.is_ok() && times_changed {
                if stream_name.is_none() {
                    server.apply_file_times_for_open(&share_name, &path, times, file_id);
                } else {
                    server.apply_file_times(&share_name, &path, times);
                }
            }
            if set_times.is_ok()
                && let Some((path, is_directory)) = notify_attributes
            {
                server
                    .notify_attributes_modified(&share_name, &path, is_directory)
                    .await;
            }
            set_times
        }
        ic::FILE_END_OF_FILE_INFORMATION => {
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let new_len = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            if allow_cache_break {
                let (lease_key, path, stream_name) = {
                    let open = open_arc.read().await;
                    (
                        open.lease_key,
                        open.last_path.clone(),
                        open.stream_name.clone(),
                    )
                };
                let wait_lease_keys = server
                    .break_conflicting_leases_for_open_waiting_for_ack(
                        &share_name,
                        &path,
                        stream_name.as_deref(),
                        lease_key,
                        LEASE_NONE,
                    )
                    .await;
                let wait_oplock_file_ids = server
                    .break_conflicting_oplocks_for_open(
                        &share_name,
                        &path,
                        stream_name.as_deref(),
                        OPLOCK_NONE,
                    )
                    .await;
                if !wait_lease_keys.is_empty() || !wait_oplock_file_ids.is_empty() {
                    let Some(tx) = conn.async_sender().await else {
                        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
                    };
                    if !server.reserve_cache_break_task_async_slot(conn) {
                        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
                    }
                    let async_id = conn.alloc_async_id();
                    let resume_server = Arc::clone(server);
                    let resume_share_name = share_name.clone();
                    let resume_open = Arc::clone(&open_arc);
                    server.register_cache_break_task(
                        async_id,
                        conn,
                        tx,
                        *hdr,
                        wait_lease_keys,
                        wait_oplock_file_ids,
                        Box::new(move || {
                            Box::pin(async move {
                                complete_file_eof_after_cache_break(
                                    &resume_server,
                                    resume_share_name,
                                    resume_open,
                                    new_len,
                                )
                                .await
                            })
                        }),
                    );
                    return HandlerResponse::pending_async(
                        async_id,
                        HandlerResponse::err(ntstatus::STATUS_PENDING).body,
                    );
                }
            }
            let open = open_arc.read().await;
            let path = open.last_path.clone();
            let stream_name = open.stream_name.clone();
            let file_id = open.file_id;
            let result = match open.handle.as_ref() {
                Some(h) => h.truncate(new_len).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            drop(open);
            if result.is_ok() && stream_name.is_none() {
                server.update_file_times_after_write(&share_name, &path, file_id);
            }
            result
        }
        ic::FILE_DISPOSITION_INFORMATION => {
            let disposition = match parse_file_disposition_information(&buffer) {
                Ok(d) => d,
                Err(status) => return HandlerResponse::err(status),
            };
            if allow_cache_break && disposition.delete {
                let (lease_key, path, stream_name) = {
                    let open = open_arc.read().await;
                    (
                        open.lease_key,
                        open.last_path.clone(),
                        open.stream_name.clone(),
                    )
                };
                let wait_lease_keys = server
                    .break_conflicting_leases_for_open(
                        &share_name,
                        &path,
                        stream_name.as_deref(),
                        lease_key,
                        LEASE_READ_CACHING,
                    )
                    .await;
                if !wait_lease_keys.is_empty() {
                    return pending_file_disposition_after_cache_break(
                        server,
                        &backend,
                        conn,
                        hdr,
                        &share_name,
                        &open_arc,
                        disposition,
                        wait_lease_keys,
                    )
                    .await;
                }
            }
            apply_disposition(
                server,
                &backend,
                &share_name,
                &open_arc,
                disposition.delete,
                disposition.posix_semantics,
                disposition.on_close,
                disposition.ignore_readonly,
            )
            .await
        }
        ic::FILE_DISPOSITION_INFORMATION_EX => {
            let disposition = match parse_file_disposition_information_ex(&buffer) {
                Ok(d) => d,
                Err(status) => return HandlerResponse::err(status),
            };
            if allow_cache_break && disposition.delete {
                let (lease_key, path, stream_name) = {
                    let open = open_arc.read().await;
                    (
                        open.lease_key,
                        open.last_path.clone(),
                        open.stream_name.clone(),
                    )
                };
                let wait_lease_keys = server
                    .break_conflicting_leases_for_open(
                        &share_name,
                        &path,
                        stream_name.as_deref(),
                        lease_key,
                        LEASE_READ_CACHING,
                    )
                    .await;
                if !wait_lease_keys.is_empty() {
                    return pending_file_disposition_after_cache_break(
                        server,
                        &backend,
                        conn,
                        hdr,
                        &share_name,
                        &open_arc,
                        disposition,
                        wait_lease_keys,
                    )
                    .await;
                }
            }
            apply_disposition(
                server,
                &backend,
                &share_name,
                &open_arc,
                disposition.delete,
                disposition.posix_semantics,
                disposition.on_close,
                disposition.ignore_readonly,
            )
            .await
        }
        ic::FILE_RENAME_INFORMATION | ic::FILE_RENAME_INFORMATION_EX => {
            let rename = match parse_file_rename_information(
                &buffer,
                class == ic::FILE_RENAME_INFORMATION_EX,
            ) {
                Ok(r) => r,
                Err(status) => return HandlerResponse::err(status),
            };
            let (from, stream_name, is_directory) = {
                let open = open_arc.read().await;
                (
                    open.last_path.clone(),
                    open.stream_name.clone(),
                    open.is_directory,
                )
            };
            if let Some(current_stream) = stream_name {
                let Some(target_stream) = stream_relative_rename_target(&rename.name) else {
                    if rename.name.contains(':') {
                        return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
                    }
                    return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
                };
                if matches!(target_stream, StreamRenameTarget::Default) {
                    let data = match server.stream_data(&share_name, &from, &current_stream) {
                        Ok(data) => data,
                        Err(e) => return HandlerResponse::err(e.to_nt_status()),
                    };
                    let base_opts = OpenOptions {
                        read: true,
                        write: true,
                        intent: OpenIntent::Truncate,
                        directory: false,
                        non_directory: true,
                        delete_on_close: false,
                    };
                    let base_handle = match backend.open(&from, base_opts).await {
                        Ok(handle) => handle,
                        Err(e) => return HandlerResponse::err(e.to_nt_status()),
                    };
                    if !data.is_empty() {
                        match base_handle.write(0, &data).await {
                            Ok(written) if written as usize == data.len() => {}
                            Ok(_) => {
                                return HandlerResponse::err(ntstatus::STATUS_UNEXPECTED_IO_ERROR);
                            }
                            Err(e) => return HandlerResponse::err(e.to_nt_status()),
                        }
                    }
                    if let Err(e) = server.delete_stream(&share_name, &from, &current_stream) {
                        return HandlerResponse::err(e.to_nt_status());
                    }
                    let mut open = open_arc.write().await;
                    open.stream_name = None;
                    open.handle = Some(base_handle);
                    return ok_set_info();
                }
                let StreamRenameTarget::Named(target_stream) = target_stream else {
                    unreachable!();
                };
                match server.rename_stream(
                    &share_name,
                    &from,
                    &current_stream,
                    &target_stream,
                    rename.replace_if_exists,
                ) {
                    Ok(()) => {
                        let mut open = open_arc.write().await;
                        open.stream_name = Some(target_stream.clone());
                        open.handle = Some(Box::new(StreamHandle::new(
                            Arc::clone(server),
                            share_name.clone(),
                            from,
                            target_stream,
                        )));
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            } else {
                if session_reauthenticated_as_anonymous(conn, hdr.session_id).await {
                    return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
                }
                if allow_cache_break {
                    let lease_key = open_arc.read().await.lease_key;
                    let wait_lease_keys = break_rename_conflicting_leases(
                        server,
                        &share_name,
                        &from,
                        is_directory,
                        lease_key,
                        LEASE_READ_CACHING,
                    )
                    .await;
                    if !wait_lease_keys.is_empty() {
                        if server
                            .lease_break_wait_includes_connection(&wait_lease_keys, conn)
                            .await
                        {
                            let Some(tx) = conn.async_sender().await else {
                                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
                            };
                            if !server.reserve_cache_break_task_async_slot(conn) {
                                return HandlerResponse::err(
                                    ntstatus::STATUS_INSUFFICIENT_RESOURCES,
                                );
                            }
                            let async_id = conn.alloc_async_id();
                            let resume_server = Arc::clone(server);
                            let resume_backend = Arc::clone(&backend);
                            let resume_share_name = share_name.clone();
                            let resume_open = Arc::clone(&open_arc);
                            let resume_from = from.clone();
                            let resume_rename = rename.clone();
                            server.register_cache_break_task(
                                async_id,
                                conn,
                                tx,
                                *hdr,
                                wait_lease_keys,
                                Vec::new(),
                                Box::new(move || {
                                    Box::pin(async move {
                                        complete_file_rename_after_cache_break(
                                            &resume_server,
                                            &resume_backend,
                                            resume_share_name,
                                            resume_open,
                                            resume_from,
                                            is_directory,
                                            resume_rename,
                                        )
                                        .await
                                    })
                                }),
                            );
                            return HandlerResponse::pending_async(
                                async_id,
                                HandlerResponse::err(ntstatus::STATUS_PENDING).body,
                            );
                        }
                        server
                            .wait_for_lease_breaks_or_timeout(&wait_lease_keys)
                            .await;
                    }
                }
                let new_path = match SmbPath::from_utf16(&rename.units) {
                    Ok(p) => p,
                    Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
                };
                if new_path == from {
                    return ok_set_info();
                }
                if server
                    .rename_parent_delete_conflict(&share_name, &from, &new_path, &open_arc)
                    .await
                {
                    return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
                }
                if server
                    .named_stream_open_on_base(&share_name, &from, Some(&open_arc))
                    .await
                {
                    return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
                }
                if is_directory
                    && server
                        .has_other_open_under_directory(&share_name, &from, &open_arc)
                        .await
                {
                    return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
                }
                if rename.replace_if_exists && !rename.posix_semantics && new_path != from {
                    let target_has_open = server
                        .has_other_open(&share_name, &new_path, &open_arc)
                        .await;
                    if target_has_open {
                        if allow_cache_break {
                            let lease_key = open_arc.read().await.lease_key;
                            let wait_lease_keys = server
                                .break_conflicting_leases_for_open(
                                    &share_name,
                                    &new_path,
                                    None,
                                    lease_key,
                                    LEASE_READ_CACHING | LEASE_WRITE_CACHING,
                                )
                                .await;
                            if !wait_lease_keys.is_empty() {
                                if server
                                    .lease_break_wait_includes_connection(&wait_lease_keys, conn)
                                    .await
                                {
                                    let Some(tx) = conn.async_sender().await else {
                                        return HandlerResponse::err(
                                            ntstatus::STATUS_NOT_SUPPORTED,
                                        );
                                    };
                                    if !server.reserve_cache_break_task_async_slot(conn) {
                                        return HandlerResponse::err(
                                            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
                                        );
                                    }
                                    let async_id = conn.alloc_async_id();
                                    let resume_server = Arc::clone(server);
                                    let resume_backend = Arc::clone(&backend);
                                    let resume_share_name = share_name.clone();
                                    let resume_open = Arc::clone(&open_arc);
                                    let resume_from = from.clone();
                                    let resume_rename = rename.clone();
                                    server.register_cache_break_task(
                                        async_id,
                                        conn,
                                        tx,
                                        *hdr,
                                        wait_lease_keys,
                                        Vec::new(),
                                        Box::new(move || {
                                            Box::pin(async move {
                                                complete_file_rename_after_cache_break(
                                                    &resume_server,
                                                    &resume_backend,
                                                    resume_share_name,
                                                    resume_open,
                                                    resume_from,
                                                    is_directory,
                                                    resume_rename,
                                                )
                                                .await
                                            })
                                        }),
                                    );
                                    return HandlerResponse::pending_async(
                                        async_id,
                                        HandlerResponse::err(ntstatus::STATUS_PENDING).body,
                                    );
                                }
                                server
                                    .wait_for_lease_breaks_or_timeout(&wait_lease_keys)
                                    .await;
                            }
                        }
                        if server
                            .has_other_open(&share_name, &new_path, &open_arc)
                            .await
                        {
                            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
                        }
                    }
                }
                if rename.replace_if_exists {
                    match backend.unlink(&new_path).await {
                        Ok(()) => {
                            server.mark_name_deleted(&share_name, &new_path);
                            if rename.posix_semantics {
                                server
                                    .mark_posix_deleted_opens(&share_name, &new_path)
                                    .await;
                            }
                            server.delete_security_descriptor(&share_name, &new_path);
                            server.delete_extended_attributes(&share_name, &new_path);
                            server.delete_allocation_size(&share_name, &new_path);
                            server.delete_file_attributes(&share_name, &new_path);
                            server.delete_file_times(&share_name, &new_path);
                            server.delete_streams(&share_name, &new_path);
                            server.delete_posix_metadata(&share_name, &new_path);
                        }
                        Err(SmbError::NotFound | SmbError::PathNotFound) => {}
                        Err(e) => return HandlerResponse::err(e.to_nt_status()),
                    }
                }
                match backend.rename(&from, &new_path).await {
                    Ok(()) => {
                        server.rekey_security_descriptor(&share_name, &from, &new_path);
                        server.rekey_posix_metadata(&share_name, &from, &new_path);
                        server.rekey_extended_attributes(&share_name, &from, &new_path);
                        server.rekey_allocation_size(&share_name, &from, &new_path);
                        server.rekey_file_attributes(&share_name, &from, &new_path);
                        server.rekey_file_times(&share_name, &from, &new_path);
                        server.rekey_streams(&share_name, &from, &new_path);
                        server
                            .purge_detached_durable_opens_under_path(&share_name, &from)
                            .await;
                        server.rekey_open_path(&share_name, &from, &new_path).await;
                        server
                            .notify_renamed(&share_name, &from, &new_path, is_directory)
                            .await;
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
        ic::FILE_FULL_EA_INFORMATION => {
            let updates = match ic::decode_file_full_ea_information(&buffer) {
                Ok(eas) => eas,
                Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
            };
            let path = open_arc.read().await.last_path.clone();
            server.apply_extended_attributes(&share_name, &path, &updates);
            Ok(())
        }
        ic::FILE_ALLOCATION_INFORMATION => {
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let allocation = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            if allocation > i64::MAX as u64 {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            let open = open_arc.read().await;
            if open.stream_name.is_some() {
                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
            }
            let lease_key = open.lease_key;
            let path = open.last_path.clone();
            drop(open);
            if allow_cache_break {
                let wait_lease_keys = server
                    .break_conflicting_leases_for_open_waiting_for_ack(
                        &share_name,
                        &path,
                        None,
                        lease_key,
                        LEASE_NONE,
                    )
                    .await;
                let wait_oplock_file_ids = server
                    .break_conflicting_oplocks_for_open(&share_name, &path, None, OPLOCK_NONE)
                    .await;
                if !wait_lease_keys.is_empty() || !wait_oplock_file_ids.is_empty() {
                    let Some(tx) = conn.async_sender().await else {
                        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
                    };
                    if !server.reserve_cache_break_task_async_slot(conn) {
                        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
                    }
                    let async_id = conn.alloc_async_id();
                    let resume_server = Arc::clone(server);
                    let resume_share_name = share_name.clone();
                    let resume_open = Arc::clone(&open_arc);
                    let resume_path = path.clone();
                    server.register_cache_break_task(
                        async_id,
                        conn,
                        tx,
                        *hdr,
                        wait_lease_keys,
                        wait_oplock_file_ids,
                        Box::new(move || {
                            Box::pin(async move {
                                complete_file_allocation_after_cache_break(
                                    &resume_server,
                                    resume_share_name,
                                    resume_open,
                                    resume_path,
                                    allocation,
                                )
                                .await
                            })
                        }),
                    );
                    return HandlerResponse::pending_async(
                        async_id,
                        HandlerResponse::err(ntstatus::STATUS_PENDING).body,
                    );
                }
            }
            let open = open_arc.read().await;
            let mut truncated = false;
            match open.handle.as_ref() {
                Some(h) => {
                    let info = match h.stat().await {
                        Ok(info) => info,
                        Err(e) => return HandlerResponse::err(e.to_nt_status()),
                    };
                    if allocation < info.end_of_file {
                        if let Err(e) = h.truncate(allocation).await {
                            return HandlerResponse::err(e.to_nt_status());
                        }
                        truncated = true;
                    }
                }
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            }
            drop(open);
            if truncated {
                server.force_update_file_times_after_write(&share_name, &path);
            } else {
                server.update_change_time_after_metadata_mutation(&share_name, &path);
            }
            server.set_allocation_size(&share_name, &path, allocation);
            Ok(())
        }
        ic::FILE_POSITION_INFORMATION => {
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            let position = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            if position > i64::MAX as u64 {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            open_arc.write().await.current_offset = position;
            Ok(())
        }
        ic::FILE_MODE_INFORMATION => {
            if buffer.len() < 4 {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            let mode = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
            const VALID_MODE_MASK: u32 = 0x0000_0002;
            if mode & !VALID_MODE_MASK != 0 {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            open_arc.write().await.mode = mode;
            Ok(())
        }
        _ => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };

    if let Err(e) = result {
        return HandlerResponse::err(e.to_nt_status());
    }
    let mut buf = Vec::new();
    SetInfoResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

async fn pending_file_disposition_after_cache_break(
    server: &Arc<ServerState>,
    backend: &Arc<dyn ShareBackend>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    share_name: &str,
    open_arc: &Arc<tokio::sync::RwLock<Open>>,
    disposition: FileDispositionUpdate,
    wait_lease_keys: Vec<[u8; 16]>,
) -> HandlerResponse {
    let Some(tx) = conn.async_sender().await else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    if !server.reserve_cache_break_task_async_slot(conn) {
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }
    let async_id = conn.alloc_async_id();
    let resume_server = Arc::clone(server);
    let resume_backend = Arc::clone(backend);
    let resume_share_name = share_name.to_string();
    let resume_open = Arc::clone(open_arc);
    let req_hdr = *hdr;
    server.register_cache_break_task(
        async_id,
        conn,
        tx,
        req_hdr,
        wait_lease_keys,
        Vec::new(),
        Box::new(move || {
            Box::pin(async move {
                complete_file_disposition_after_cache_break(
                    &resume_server,
                    &resume_backend,
                    resume_share_name,
                    resume_open,
                    disposition,
                )
                .await
            })
        }),
    );
    HandlerResponse::pending_async(
        async_id,
        HandlerResponse::err(ntstatus::STATUS_PENDING).body,
    )
}

async fn break_rename_conflicting_leases(
    server: &Arc<ServerState>,
    share_name: &str,
    from: &SmbPath,
    is_directory: bool,
    lease_key: [u8; 16],
    target_state: u32,
) -> Vec<[u8; 16]> {
    let mut wait_lease_keys = server
        .break_conflicting_leases_for_open(share_name, from, None, lease_key, target_state)
        .await;
    if is_directory {
        for key in server
            .break_conflicting_leases_under_directory(share_name, from, lease_key, target_state)
            .await
        {
            if !wait_lease_keys.contains(&key) {
                wait_lease_keys.push(key);
            }
        }
    }
    wait_lease_keys
}

async fn complete_file_disposition_after_cache_break(
    server: &Arc<ServerState>,
    backend: &Arc<dyn ShareBackend>,
    share_name: String,
    open_arc: Arc<tokio::sync::RwLock<Open>>,
    disposition: FileDispositionUpdate,
) -> HandlerResponse {
    match apply_disposition(
        server,
        backend,
        &share_name,
        &open_arc,
        disposition.delete,
        disposition.posix_semantics,
        disposition.on_close,
        disposition.ignore_readonly,
    )
    .await
    {
        Ok(()) => ok_set_info(),
        Err(e) => HandlerResponse::err(e.to_nt_status()),
    }
}

async fn complete_file_rename_after_cache_break(
    server: &Arc<ServerState>,
    backend: &Arc<dyn ShareBackend>,
    share_name: String,
    open_arc: Arc<tokio::sync::RwLock<Open>>,
    from: SmbPath,
    is_directory: bool,
    rename: FileRenameUpdate,
) -> HandlerResponse {
    let new_path = match SmbPath::from_utf16(&rename.units) {
        Ok(p) => p,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    if new_path == from {
        return ok_set_info();
    }
    if server
        .rename_parent_delete_conflict(&share_name, &from, &new_path, &open_arc)
        .await
    {
        return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
    }
    if server
        .named_stream_open_on_base(&share_name, &from, Some(&open_arc))
        .await
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if is_directory
        && server
            .has_other_open_under_directory(&share_name, &from, &open_arc)
            .await
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if rename.replace_if_exists
        && !rename.posix_semantics
        && new_path != from
        && server
            .has_other_open(&share_name, &new_path, &open_arc)
            .await
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if rename.replace_if_exists {
        match backend.unlink(&new_path).await {
            Ok(()) => {
                server.mark_name_deleted(&share_name, &new_path);
                if rename.posix_semantics {
                    server
                        .mark_posix_deleted_opens(&share_name, &new_path)
                        .await;
                }
                server.delete_security_descriptor(&share_name, &new_path);
                server.delete_extended_attributes(&share_name, &new_path);
                server.delete_allocation_size(&share_name, &new_path);
                server.delete_file_attributes(&share_name, &new_path);
                server.delete_file_times(&share_name, &new_path);
                server.delete_streams(&share_name, &new_path);
                server.delete_posix_metadata(&share_name, &new_path);
            }
            Err(SmbError::NotFound | SmbError::PathNotFound) => {}
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        }
    }
    match backend.rename(&from, &new_path).await {
        Ok(()) => {
            server.rekey_security_descriptor(&share_name, &from, &new_path);
            server.rekey_posix_metadata(&share_name, &from, &new_path);
            server.rekey_extended_attributes(&share_name, &from, &new_path);
            server.rekey_allocation_size(&share_name, &from, &new_path);
            server.rekey_file_attributes(&share_name, &from, &new_path);
            server.rekey_file_times(&share_name, &from, &new_path);
            server.rekey_streams(&share_name, &from, &new_path);
            server
                .purge_detached_durable_opens_under_path(&share_name, &from)
                .await;
            server.rekey_open_path(&share_name, &from, &new_path).await;
            server
                .notify_renamed(&share_name, &from, &new_path, is_directory)
                .await;
            ok_set_info()
        }
        Err(e) => HandlerResponse::err(e.to_nt_status()),
    }
}

async fn complete_file_eof_after_cache_break(
    server: &Arc<ServerState>,
    share_name: String,
    open_arc: Arc<tokio::sync::RwLock<Open>>,
    new_len: u64,
) -> HandlerResponse {
    let open = open_arc.read().await;
    let path = open.last_path.clone();
    let stream_name = open.stream_name.clone();
    let file_id = open.file_id;
    let result = match open.handle.as_ref() {
        Some(handle) => handle.truncate(new_len).await,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    drop(open);
    match result {
        Ok(()) => {
            if stream_name.is_none() {
                server.update_file_times_after_write(&share_name, &path, file_id);
            }
            ok_set_info()
        }
        Err(e) => HandlerResponse::err(e.to_nt_status()),
    }
}

async fn complete_file_allocation_after_cache_break(
    server: &Arc<ServerState>,
    share_name: String,
    open_arc: Arc<tokio::sync::RwLock<Open>>,
    path: SmbPath,
    allocation: u64,
) -> HandlerResponse {
    let open = open_arc.read().await;
    if open.stream_name.is_some() {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }
    let mut truncated = false;
    match open.handle.as_ref() {
        Some(handle) => {
            let info = match handle.stat().await {
                Ok(info) => info,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            if allocation < info.end_of_file {
                if let Err(e) = handle.truncate(allocation).await {
                    return HandlerResponse::err(e.to_nt_status());
                }
                truncated = true;
            }
        }
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    }
    drop(open);
    if truncated {
        server.force_update_file_times_after_write(&share_name, &path);
    } else {
        server.update_change_time_after_metadata_mutation(&share_name, &path);
    }
    server.set_allocation_size(&share_name, &path, allocation);
    ok_set_info()
}

fn set_file_access_allowed(class: u8, desired_access: u32) -> bool {
    match class {
        ic::FILE_BASIC_INFORMATION => desired_access & FILE_WRITE_ATTRIBUTES != 0,
        ic::FILE_END_OF_FILE_INFORMATION | ic::FILE_ALLOCATION_INFORMATION => {
            desired_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0
        }
        ic::FILE_DISPOSITION_INFORMATION
        | ic::FILE_DISPOSITION_INFORMATION_EX
        | ic::FILE_RENAME_INFORMATION
        | ic::FILE_RENAME_INFORMATION_EX => desired_access & (DELETE | FILE_DELETE_CHILD) != 0,
        ic::FILE_FULL_EA_INFORMATION => desired_access & FILE_WRITE_EA != 0,
        _ => true,
    }
}

async fn session_reauthenticated_as_anonymous(conn: &Arc<Connection>, session_id: u64) -> bool {
    let sessions = conn.sessions.read().await;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return false;
    };
    drop(sessions);
    session.read().await.reauth_anonymous
}

fn set_info_file_attributes(attributes: u32, is_directory: bool) -> u32 {
    if is_directory {
        return attributes | FILE_ATTRIBUTE_DIRECTORY;
    }
    let attributes = attributes
        & (FILE_ATTRIBUTE_READONLY
            | FILE_ATTRIBUTE_HIDDEN
            | FILE_ATTRIBUTE_SYSTEM
            | FILE_ATTRIBUTE_ARCHIVE
            | FILE_ATTRIBUTE_NORMAL
            | FILE_ATTRIBUTE_TEMPORARY
            | FILE_ATTRIBUTE_OFFLINE);
    if attributes == 0 || attributes == FILE_ATTRIBUTE_NORMAL {
        FILE_ATTRIBUTE_NORMAL
    } else {
        attributes & !FILE_ATTRIBUTE_NORMAL
    }
}

#[derive(Debug)]
struct FileDispositionUpdate {
    delete: bool,
    posix_semantics: bool,
    on_close: bool,
    ignore_readonly: bool,
}

fn parse_file_disposition_information(buffer: &[u8]) -> Result<FileDispositionUpdate, u32> {
    if buffer.is_empty() {
        return Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(FileDispositionUpdate {
        delete: buffer[0] != 0,
        posix_semantics: false,
        on_close: true,
        ignore_readonly: false,
    })
}

fn parse_file_disposition_information_ex(buffer: &[u8]) -> Result<FileDispositionUpdate, u32> {
    if buffer.len() < 4 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let flags = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let valid_flags = FILE_DISPOSITION_DELETE
        | FILE_DISPOSITION_POSIX_SEMANTICS
        | FILE_DISPOSITION_ON_CLOSE
        | FILE_DISPOSITION_IGNORE_READONLY;
    if flags & !valid_flags != 0 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(FileDispositionUpdate {
        delete: flags & FILE_DISPOSITION_DELETE != 0,
        posix_semantics: flags & FILE_DISPOSITION_POSIX_SEMANTICS != 0,
        on_close: flags & FILE_DISPOSITION_ON_CLOSE != 0,
        ignore_readonly: flags & FILE_DISPOSITION_IGNORE_READONLY != 0,
    })
}

async fn apply_disposition(
    server: &Arc<ServerState>,
    backend: &Arc<dyn ShareBackend>,
    share_name: &str,
    open_arc: &Arc<tokio::sync::RwLock<Open>>,
    delete: bool,
    posix_semantics: bool,
    on_close: bool,
    ignore_readonly: bool,
) -> Result<(), SmbError> {
    if !delete {
        let mut open = open_arc.write().await;
        open.delete_on_close = false;
        open.delete_on_close_unlinks_name = false;
        return Ok(());
    }
    let (path, stream_name, is_directory) = {
        let open = open_arc.read().await;
        (
            open.last_path.clone(),
            open.stream_name.clone(),
            open.is_directory,
        )
    };
    if server
        .delete_sharing_conflict(share_name, &path, stream_name.as_deref(), Some(open_arc))
        .await
    {
        return Err(SmbError::Sharing);
    }
    if !ignore_readonly && !is_directory && stream_name.is_none() {
        let open = open_arc.read().await;
        let Some(handle) = open.handle.as_ref() else {
            return Err(SmbError::NotFound);
        };
        let info = handle.stat().await?;
        let info = server.effective_file_info(share_name, &path, info);
        if info.file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(SmbError::CannotDelete);
        }
    }
    if on_close || !posix_semantics {
        let mut open = open_arc.write().await;
        open.delete_on_close = true;
        open.delete_on_close_unlinks_name = false;
        return Ok(());
    }

    if let Some(stream_name) = stream_name {
        server.delete_stream(share_name, &path, &stream_name)?;
    } else {
        backend.unlink(&path).await?;
        server.mark_name_deleted(share_name, &path);
        server.delete_security_descriptor(share_name, &path);
        server.delete_extended_attributes(share_name, &path);
        server.delete_allocation_size(share_name, &path);
        server.delete_file_attributes(share_name, &path);
        server.delete_file_times(share_name, &path);
        server.delete_streams(share_name, &path);
        server.delete_posix_metadata(share_name, &path);
        server.notify_removed(share_name, &path, is_directory).await;
    }
    let mut open = open_arc.write().await;
    open.delete_on_close = false;
    open.delete_on_close_unlinks_name = false;
    open.posix_deleted = true;
    Ok(())
}

#[derive(Debug, Clone)]
struct FileRenameUpdate {
    replace_if_exists: bool,
    posix_semantics: bool,
    name: String,
    units: Vec<u16>,
}

fn parse_file_rename_information(buffer: &[u8], extended: bool) -> Result<FileRenameUpdate, u32> {
    if buffer.len() < 20 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let flags = if extended {
        u32::from_le_bytes(buffer[0..4].try_into().unwrap())
    } else if buffer[0] != 0 {
        FILE_RENAME_REPLACE_IF_EXISTS
    } else {
        0
    };
    if extended {
        let valid_flags = FILE_RENAME_REPLACE_IF_EXISTS
            | FILE_RENAME_POSIX_SEMANTICS
            | FILE_RENAME_IGNORE_READONLY;
        if flags & !valid_flags != 0 {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if flags & FILE_RENAME_POSIX_SEMANTICS != 0 && flags & FILE_RENAME_REPLACE_IF_EXISTS == 0 {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }

    let name_len = u32::from_le_bytes(buffer[16..20].try_into().unwrap()) as usize;
    if !name_len.is_multiple_of(2) || buffer.len() < 20 + name_len {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let name_bytes = &buffer[20..20 + name_len];
    let Some(units) = utf16le_to_units(name_bytes) else {
        return Err(ntstatus::STATUS_OBJECT_NAME_INVALID);
    };
    let name = String::from_utf16(&units).map_err(|_| ntstatus::STATUS_OBJECT_NAME_INVALID)?;
    Ok(FileRenameUpdate {
        replace_if_exists: flags & FILE_RENAME_REPLACE_IF_EXISTS != 0,
        posix_semantics: flags & FILE_RENAME_POSIX_SEMANTICS != 0,
        name,
        units,
    })
}

fn ok_set_info() -> HandlerResponse {
    let mut buf = Vec::new();
    SetInfoResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamRenameTarget {
    Default,
    Named(String),
}

fn stream_relative_rename_target(name: &str) -> Option<StreamRenameTarget> {
    let stream = name.strip_prefix(':')?;
    if stream.is_empty() {
        return None;
    }
    if stream.eq_ignore_ascii_case(":$DATA") {
        return Some(StreamRenameTarget::Default);
    }
    let stream = if let Some((stream_name, stream_type)) = stream.rsplit_once(':') {
        if stream_name.is_empty() || !stream_type.eq_ignore_ascii_case("$DATA") {
            return None;
        }
        stream_name
    } else {
        stream
    };
    if stream.contains(['\\', '/', ':']) {
        return None;
    }
    Some(StreamRenameTarget::Named(stream.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_relative_rename_target_accepts_named_data_streams() {
        assert_eq!(
            stream_relative_rename_target(":Stream One"),
            Some(StreamRenameTarget::Named("Stream One".to_string()))
        );
        assert_eq!(
            stream_relative_rename_target(":Stream One:$DaTa"),
            Some(StreamRenameTarget::Named("Stream One".to_string()))
        );
    }

    #[test]
    fn stream_relative_rename_target_rejects_non_relative_or_default_targets() {
        assert!(stream_relative_rename_target("file.txt:Stream One").is_none());
        assert!(stream_relative_rename_target(":Stream One:$INDEX_ALLOCATION").is_none());
        assert!(stream_relative_rename_target(":bad/name").is_none());
    }

    #[test]
    fn stream_relative_rename_target_accepts_default_data_stream() {
        assert_eq!(
            stream_relative_rename_target("::$DATA"),
            Some(StreamRenameTarget::Default)
        );
    }

    #[test]
    fn parses_disposition_information_ex_flags() {
        let flags =
            FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_ON_CLOSE;
        let update = parse_file_disposition_information_ex(&flags.to_le_bytes()).unwrap();
        assert!(update.delete);
        assert!(update.posix_semantics);
        assert!(update.on_close);
        assert_eq!(
            parse_file_disposition_information_ex(&[0; 3]).unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            parse_file_disposition_information_ex(&0x8000_0000u32.to_le_bytes()).unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn parses_rename_information_ex_flags_and_name() {
        let update = parse_file_rename_information(
            &rename_info_ex(
                "renamed.txt",
                FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
            ),
            true,
        )
        .unwrap();
        assert!(update.replace_if_exists);
        assert!(update.posix_semantics);
        assert_eq!(update.name, "renamed.txt");
        assert_eq!(
            parse_file_rename_information(
                &rename_info_ex_with_len("renamed.txt", 0, Some(19)),
                true,
            )
            .unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            parse_file_rename_information(&rename_info_ex("renamed.txt", 0x8000_0000), true)
                .unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            parse_file_rename_information(
                &rename_info_ex("renamed.txt", FILE_RENAME_POSIX_SEMANTICS),
                true,
            )
            .unwrap_err(),
            ntstatus::STATUS_INVALID_PARAMETER
        );
    }

    fn rename_info_ex(name: &str, flags: u32) -> Vec<u8> {
        rename_info_ex_with_len(name, flags, None)
    }

    fn rename_info_ex_with_len(name: &str, flags: u32, len: Option<u32>) -> Vec<u8> {
        let name = crate::utils::utf16le(name);
        let mut out = Vec::new();
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&len.unwrap_or(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&name);
        out
    }
}
