//! QUERY_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, InfoType, QueryInfoRequest, QueryInfoResponse};

use crate::backend::{OpenIntent, OpenOptions};
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::server::{ServerState, volume_id_for_share};

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const TOTAL_ALLOCATION_UNITS: u64 = 1 << 20;
const AVAILABLE_ALLOCATION_UNITS: u64 = 1 << 19;
const SECTORS_PER_ALLOCATION_UNIT: u32 = 8;
const BYTES_PER_SECTOR: u32 = 512;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match req.info_type_enum() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let (share_name, backend) = {
        let tree = tree_arc.read().await;
        (tree.share.name.clone(), tree.share.backend.clone())
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    let (
        fallback_file_index,
        path,
        stream_name,
        desired_access,
        posix_metadata,
        posix_deleted,
        current_offset,
        mode,
        info_res,
    ) = {
        let open = open_arc.read().await;
        let fid = open.file_id;
        match open.handle.as_ref() {
            Some(h) => (
                fid.volatile,
                open.last_path.clone(),
                open.stream_name.clone(),
                open.desired_access,
                open.posix_metadata,
                open.posix_deleted,
                open.current_offset,
                open.mode,
                h.stat().await,
            ),
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };

    let buf: Vec<u8> = match info_type {
        InfoType::File => {
            let mut info = match info_res {
                Ok(i) => i,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            if stream_name.is_none() {
                info = server.effective_file_info(&share_name, &path, info);
            } else {
                let base_handle = match backend
                    .open(
                        &path,
                        OpenOptions {
                            read: true,
                            write: false,
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
                let base_stat = match base_handle.stat().await {
                    Ok(info) => info,
                    Err(e) => return HandlerResponse::err(e.to_nt_status()),
                };
                let _ = base_handle.close().await;
                let base_info = server.effective_file_info(&share_name, &path, base_stat);
                info.file_attributes = base_info.file_attributes;
            }
            let file_index = info.file_index_or(fallback_file_index);
            if !query_file_access_allowed(req.file_information_class, desired_access) {
                return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
            }
            let delete_pending = matches!(
                req.file_information_class,
                ic::FILE_STANDARD_INFORMATION | ic::FILE_ALL_INFORMATION
            ) && (posix_deleted
                || server.open_delete_pending(&share_name, &path).await);
            let number_of_links = if delete_pending { 0 } else { 1 };
            match req.file_information_class {
                ic::FILE_BASIC_INFORMATION => ic::encode_file_basic_information(&info),
                ic::FILE_STANDARD_INFORMATION if delete_pending => {
                    ic::encode_file_standard_information_with_links(
                        &info,
                        delete_pending,
                        number_of_links,
                    )
                }
                ic::FILE_STANDARD_INFORMATION => {
                    ic::encode_file_standard_information(&info, delete_pending)
                }
                ic::FILE_INTERNAL_INFORMATION => ic::encode_file_internal_information(file_index),
                ic::FILE_EA_INFORMATION => {
                    let eas = server.extended_attributes(&share_name, &path);
                    ic::encode_file_ea_information(&eas)
                }
                ic::FILE_FULL_EA_INFORMATION => {
                    let eas = server.extended_attributes(&share_name, &path);
                    ic::encode_file_full_ea_information(&eas)
                }
                ic::FILE_ACCESS_INFORMATION => ic::encode_file_access_information(desired_access),
                ic::FILE_POSITION_INFORMATION => {
                    ic::encode_file_position_information(current_offset)
                }
                ic::FILE_MODE_INFORMATION => ic::encode_file_mode_information(mode),
                ic::FILE_ALIGNMENT_INFORMATION => ic::encode_file_alignment_information(),
                ic::FILE_NAME_INFORMATION => ic::encode_file_name_information(&info.name),
                ic::FILE_ALTERNATE_NAME_INFORMATION => {
                    ic::encode_file_alternate_name_information(alternate_name_component(&info.name))
                }
                ic::FILE_ALL_INFORMATION if delete_pending => {
                    ic::encode_file_all_information_with_links(
                        &info,
                        file_index,
                        desired_access,
                        current_offset,
                        mode,
                        delete_pending,
                        number_of_links,
                    )
                }
                ic::FILE_ALL_INFORMATION => ic::encode_file_all_information(
                    &info,
                    file_index,
                    desired_access,
                    current_offset,
                    mode,
                    delete_pending,
                ),
                ic::FILE_NETWORK_OPEN_INFORMATION => {
                    ic::encode_file_network_open_information(&info)
                }
                ic::FILE_STREAM_INFORMATION => {
                    let base_info = if stream_name.is_some() {
                        let base_handle = match backend
                            .open(
                                &path,
                                OpenOptions {
                                    read: true,
                                    write: false,
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
                        let stat = match base_handle.stat().await {
                            Ok(info) => info,
                            Err(e) => return HandlerResponse::err(e.to_nt_status()),
                        };
                        let _ = base_handle.close().await;
                        server.effective_file_info(&share_name, &path, stat)
                    } else {
                        info.clone()
                    };
                    let streams = server.stream_info(&share_name, &path, &base_info);
                    ic::encode_file_stream_information(&base_info, &streams)
                }
                ic::FILE_COMPRESSION_INFORMATION => ic::encode_file_compression_information(),
                ic::FILE_ATTRIBUTE_TAG_INFORMATION => {
                    ic::encode_file_attribute_tag_information(&info)
                }
                ic::FILE_NORMALIZED_NAME_INFORMATION => {
                    if *conn.dialect.read().await != Some(Dialect::Smb311) {
                        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
                    }
                    ic::encode_file_name_information(&info.name)
                }
                ic::FILE_REMOTE_PROTOCOL_INFORMATION => {
                    let dialect = *conn.dialect.read().await;
                    ic::encode_file_remote_protocol_information(dialect)
                }
                ic::FILE_ID_INFORMATION => {
                    ic::encode_file_id_information(volume_id_for_share(&share_name), file_index)
                }
                ic::FILE_POSIX_INFORMATION => ic::encode_file_posix_information_with_links(
                    &info,
                    file_index,
                    posix_metadata,
                    number_of_links,
                ),
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::FileSystem => {
            let creation_time = info_res.as_ref().map(|i| i.creation_time).unwrap_or(0);
            match req.file_information_class {
                ic::FS_VOLUME_INFORMATION => {
                    ic::encode_fs_volume_information(creation_time, 0x4753_4d42, "GOSMB")
                }
                ic::FS_CONTROL_INFORMATION => ic::encode_fs_control_information(),
                ic::FS_SIZE_INFORMATION => ic::encode_fs_size_information(
                    TOTAL_ALLOCATION_UNITS,
                    AVAILABLE_ALLOCATION_UNITS,
                    SECTORS_PER_ALLOCATION_UNIT,
                    BYTES_PER_SECTOR,
                ),
                ic::FS_DEVICE_INFORMATION => ic::encode_fs_device_information(FILE_DEVICE_DISK, 0),
                ic::FS_ATTRIBUTE_INFORMATION => {
                    ic::encode_fs_attribute_information(0x0000_0007, 255, "GOSMB")
                }
                ic::FS_QUOTA_INFORMATION => ic::encode_fs_quota_information(
                    TOTAL_ALLOCATION_UNITS,
                    AVAILABLE_ALLOCATION_UNITS,
                ),
                ic::FS_FULL_SIZE_INFORMATION => ic::encode_fs_full_size_information(
                    TOTAL_ALLOCATION_UNITS,
                    AVAILABLE_ALLOCATION_UNITS,
                    AVAILABLE_ALLOCATION_UNITS,
                    SECTORS_PER_ALLOCATION_UNIT,
                    BYTES_PER_SECTOR,
                ),
                ic::FS_OBJECT_ID_INFORMATION => {
                    ic::encode_fs_object_id_information(b"GoSMBVirtualFS!!")
                }
                ic::FS_SECTOR_SIZE_INFORMATION => {
                    ic::encode_fs_sector_size_information(BYTES_PER_SECTOR)
                }
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::Security => {
            if desired_access & READ_CONTROL == 0 {
                return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
            }
            let descriptor = server
                .security_descriptor(&share_name, &path)
                .unwrap_or_else(ic::encode_minimal_security_descriptor);
            ic::filter_security_descriptor(&descriptor, req.additional_information)
        }
        InfoType::Quota => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };

    let (status, buf) = match apply_query_info_buffer_status(
        info_type,
        req.file_information_class,
        req.output_buffer_length,
        buf,
    ) {
        Ok(output) => output,
        Err(status) => return HandlerResponse::err(status),
    };

    let resp = QueryInfoResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out)
        .expect("QUERY_INFO response encodes");
    let mut response = HandlerResponse::ok(out);
    response.status = status;
    response
}

fn alternate_name_component(name: &str) -> &str {
    name.rsplit(['\\', '/']).next().unwrap_or(name)
}

fn apply_query_info_buffer_status(
    info_type: InfoType,
    class: u8,
    requested: u32,
    mut output: Vec<u8>,
) -> Result<(u32, Vec<u8>), u32> {
    if info_type == InfoType::Security {
        if requested < output.len() as u32 {
            return Err(ntstatus::STATUS_BUFFER_TOO_SMALL);
        }
        return Ok((ntstatus::STATUS_SUCCESS, output));
    }

    let fixed = query_info_fixed_size(info_type, class).unwrap_or(output.len());
    let requested = requested as usize;
    if requested < fixed {
        return Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
    if requested < output.len() {
        output.truncate(requested);
        return Ok((ntstatus::STATUS_BUFFER_OVERFLOW, output));
    }
    Ok((ntstatus::STATUS_SUCCESS, output))
}

fn query_info_fixed_size(info_type: InfoType, class: u8) -> Option<usize> {
    match info_type {
        InfoType::File => match class {
            ic::FILE_BASIC_INFORMATION => Some(40),
            ic::FILE_STANDARD_INFORMATION => Some(24),
            ic::FILE_INTERNAL_INFORMATION => Some(8),
            ic::FILE_EA_INFORMATION
            | ic::FILE_ACCESS_INFORMATION
            | ic::FILE_MODE_INFORMATION
            | ic::FILE_ALIGNMENT_INFORMATION => Some(4),
            ic::FILE_NAME_INFORMATION => Some(4),
            ic::FILE_FULL_EA_INFORMATION => Some(4),
            ic::FILE_POSITION_INFORMATION => Some(8),
            ic::FILE_ALL_INFORMATION => Some(104),
            ic::FILE_ALTERNATE_NAME_INFORMATION => Some(8),
            ic::FILE_STREAM_INFORMATION => Some(32),
            ic::FILE_COMPRESSION_INFORMATION => Some(16),
            ic::FILE_NETWORK_OPEN_INFORMATION => Some(56),
            ic::FILE_ATTRIBUTE_TAG_INFORMATION => Some(8),
            ic::FILE_NORMALIZED_NAME_INFORMATION => Some(4),
            ic::FILE_REMOTE_PROTOCOL_INFORMATION => Some(180),
            ic::FILE_ID_INFORMATION => Some(24),
            ic::FILE_POSIX_INFORMATION => Some(136),
            _ => None,
        },
        InfoType::FileSystem => match class {
            ic::FS_VOLUME_INFORMATION => Some(24),
            ic::FS_CONTROL_INFORMATION => Some(48),
            ic::FS_SIZE_INFORMATION => Some(24),
            ic::FS_DEVICE_INFORMATION => Some(8),
            ic::FS_ATTRIBUTE_INFORMATION => Some(16),
            ic::FS_QUOTA_INFORMATION => Some(48),
            ic::FS_FULL_SIZE_INFORMATION => Some(32),
            ic::FS_OBJECT_ID_INFORMATION => Some(64),
            ic::FS_SECTOR_SIZE_INFORMATION => Some(28),
            _ => None,
        },
        InfoType::Security | InfoType::Quota => None,
    }
}

fn query_file_access_allowed(class: u8, desired_access: u32) -> bool {
    match class {
        ic::FILE_ACCESS_INFORMATION => desired_access != 0,
        ic::FILE_EA_INFORMATION => desired_access & (SYNCHRONIZE | FILE_READ_EA) != 0,
        ic::FILE_FULL_EA_INFORMATION => desired_access & FILE_READ_EA != 0,
        ic::FILE_BASIC_INFORMATION
        | ic::FILE_ALL_INFORMATION
        | ic::FILE_NETWORK_OPEN_INFORMATION
        | ic::FILE_ATTRIBUTE_TAG_INFORMATION => {
            desired_access & (FILE_READ_ATTRIBUTES | FILE_READ_EA) != 0
        }
        ic::FILE_STREAM_INFORMATION => {
            desired_access
                & (SYNCHRONIZE
                    | FILE_READ_ATTRIBUTES
                    | FILE_READ_EA
                    | FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_APPEND_DATA)
                != 0
        }
        ic::FILE_STANDARD_INFORMATION
        | ic::FILE_INTERNAL_INFORMATION
        | ic::FILE_POSITION_INFORMATION
        | ic::FILE_MODE_INFORMATION
        | ic::FILE_ALIGNMENT_INFORMATION
        | ic::FILE_ALTERNATE_NAME_INFORMATION
        | ic::FILE_COMPRESSION_INFORMATION
        | ic::FILE_NORMALIZED_NAME_INFORMATION => {
            desired_access & (SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA) != 0
        }
        _ => true,
    }
}
