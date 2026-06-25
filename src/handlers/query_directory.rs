//! QUERY_DIRECTORY handler.

use std::collections::HashSet;
use std::sync::Arc;

use crate::backend::{DirEntry, FileInfo, default_file_attributes};
use crate::proto::header::Smb2Header;
use crate::proto::messages::{FileInfoClass, QueryDirectoryRequest, QueryDirectoryResponse};

use crate::conn::state::{Connection, DirCursor};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class::{
    self, align8, encode_dir_entry_with_index, encode_dir_entry_with_index_and_posix,
};
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::utf16le_to_string;
use tracing::debug;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryDirectoryRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if FileInfoClass::from_u8(req.file_information_class).is_none() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS);
    }
    let class_byte = req.file_information_class;

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let share_name = {
        let tree = tree_arc.read().await;
        tree.share.name.clone()
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    let pattern_str = utf16le_to_string(&req.file_name);
    let requested_pattern: Option<String> = if pattern_str.is_empty() || pattern_str == "*" {
        None
    } else {
        Some(pattern_str.clone())
    };

    let index_specified = req.flags & QueryDirectoryRequest::FLAG_INDEX_SPECIFIED != 0;
    let restart = req.flags & QueryDirectoryRequest::FLAG_RESTART_SCANS != 0
        || req.flags & QueryDirectoryRequest::FLAG_REOPEN != 0;
    let single_entry = req.flags & QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY != 0;

    // Populate or refresh the cursor.
    let mut continuation_names: Option<HashSet<String>> = None;
    {
        let mut open = open_arc.write().await;
        if !open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let refresh = open.search_state.is_none() || restart;
        if refresh {
            let entries = match open.handle.as_ref() {
                Some(h) => h.list_dir(None).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            let mut entries = match entries {
                Ok(e) => e,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            let dir_info = match open.handle.as_ref() {
                Some(h) => h.stat().await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            let dir_info = match dir_info {
                Ok(i) => i,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            normalize_scan_entries(&mut entries, &dir_info);
            open.search_state = Some(DirCursor {
                entries,
                next: 0,
                pattern: requested_pattern.clone(),
            });
        }

        if let Some(cursor) = open.search_state.as_mut() {
            if index_specified {
                cursor.next = req.file_index as usize;
            }
            if !pattern_str.is_empty() || restart {
                cursor.pattern = requested_pattern.clone();
            }
        }

        if !refresh {
            let current = match open.handle.as_ref() {
                Some(h) => h.list_dir(None).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            let current = match current {
                Ok(e) => e,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            continuation_names = Some(
                current
                    .into_iter()
                    .map(|entry| entry.info.name.to_ascii_lowercase())
                    .collect(),
            );
        }
    }

    // Encode entries into the output buffer.
    let mut buf: Vec<u8> = Vec::new();
    let mut last_offset_pos: Option<usize> = None;
    let cap = req.output_buffer_length as usize;
    let search_started;

    {
        let mut open = open_arc.write().await;
        let dir_path = open.last_path.clone();
        let cursor = open.search_state.as_mut().expect("populated above");
        search_started = cursor.next > 0;
        loop {
            if cursor.next >= cursor.entries.len() {
                break;
            }
            let directory_index = cursor.next as u32;
            let resume_key = directory_index.saturating_add(1);
            let mut entry = cursor.entries[cursor.next].clone();
            if !pattern_matches(cursor.pattern.as_deref(), &entry.info.name) {
                cursor.next += 1;
                continue;
            }
            if !snapshot_entry_still_exists(&entry.info.name, continuation_names.as_ref()) {
                cursor.next += 1;
                continue;
            }
            let file_id = entry.info.file_index;
            let entry_path = match entry.info.name.as_str() {
                "." => Some(dir_path.clone()),
                ".." => dir_path
                    .parent()
                    .or_else(|| Some(crate::path::SmbPath::root())),
                name => dir_path.join(name).ok(),
            };
            if let Some(path) = entry_path.as_ref() {
                entry.info = server.effective_file_info(&share_name, path, entry.info);
            }
            debug!(
                share = %share_name,
                directory = %dir_path,
                name = %entry.info.name,
                class = class_byte,
                index = directory_index,
                file_id,
                "query directory returning entry"
            );
            let posix = if class_byte == info_class::FILE_POSIX_INFORMATION {
                entry_path
                    .as_ref()
                    .and_then(|path| server.posix_metadata(&share_name, path))
            } else {
                None
            };
            let mut bytes = if posix.is_some() {
                encode_dir_entry_with_index_and_posix(
                    class_byte, &entry, resume_key, file_id, posix,
                )
            } else {
                encode_dir_entry_with_index(class_byte, &entry, resume_key, file_id)
            };
            if bytes.is_empty() {
                cursor.next += 1;
                continue;
            }

            // Determine total size with padding for chaining.
            let entry_aligned = align8(bytes.len());
            // If this is *not* the first entry, we already padded the previous
            // entry up to entry_aligned. We commit only if total fits.
            let prev_len = buf.len();
            let total_after = prev_len + entry_aligned;
            if total_after > cap && !buf.is_empty() {
                // No room for this entry; stop.
                break;
            }
            // Patch previous NextEntryOffset.
            if let Some(prev_off) = last_offset_pos {
                let delta = (prev_len - prev_off) as u32;
                buf[prev_off..prev_off + 4].copy_from_slice(&delta.to_le_bytes());
            }
            // Track NextEntryOffset position for the entry we are appending.
            last_offset_pos = Some(prev_len);
            // Append the entry, then pad to 8.
            let target_len = prev_len + entry_aligned;
            buf.append(&mut bytes);
            while buf.len() < target_len {
                buf.push(0);
            }
            cursor.next += 1;
            if single_entry {
                break;
            }
        }
    }
    if buf.is_empty() {
        if !search_started {
            return HandlerResponse::err(ntstatus::STATUS_NO_SUCH_FILE);
        }
        return HandlerResponse::err(ntstatus::STATUS_NO_MORE_FILES);
    }

    let resp = QueryDirectoryResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out).expect("encode");
    HandlerResponse::ok(out)
}

fn normalize_scan_entries(entries: &mut Vec<DirEntry>, dir_info: &FileInfo) {
    entries.sort_by(|a, b| a.info.name.cmp(&b.info.name));

    let mut synthetic = Vec::new();
    if !entries.iter().any(|entry| entry.info.name == ".") {
        synthetic.push(DirEntry {
            info: synthetic_dir_entry(dir_info, "."),
        });
    }
    if !entries.iter().any(|entry| entry.info.name == "..") {
        synthetic.push(DirEntry {
            info: synthetic_dir_entry(dir_info, ".."),
        });
    }
    synthetic.append(entries);
    *entries = synthetic;
}

fn synthetic_dir_entry(base: &FileInfo, name: &str) -> FileInfo {
    let mut info = base.clone();
    info.name = name.to_string();
    info.end_of_file = 0;
    info.allocation_size = 0;
    info.is_directory = true;
    info.file_attributes = default_file_attributes(true);
    info
}

fn snapshot_entry_still_exists(name: &str, current_names: Option<&HashSet<String>>) -> bool {
    if name == "." || name == ".." {
        return true;
    }
    current_names
        .map(|names| names.contains(&name.to_ascii_lowercase()))
        .unwrap_or(true)
}

fn pattern_matches(pattern: Option<&str>, name: &str) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };
    if pattern.is_empty() || pattern == "*" || pattern == "*.*" {
        return true;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    glob_match_inner(&pattern, &name)
}

fn glob_match_inner(pattern: &[char], name: &[char]) -> bool {
    let mut pi = 0usize;
    let mut ni = 0usize;
    let mut star: Option<(usize, usize)> = None;

    while ni < name.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || chars_eq_ci(pattern[pi], name[ni])) {
            pi += 1;
            ni += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star = Some((pi + 1, ni));
            pi += 1;
        } else if let Some((star_pi, star_ni)) = star {
            pi = star_pi;
            ni = star_ni + 1;
            star = Some((star_pi, ni));
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

fn chars_eq_ci(a: char, b: char) -> bool {
    a.eq_ignore_ascii_case(&b)
}
