use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::backend::{
    BackendCapabilities, BackendWatch, DirEntry, FileInfo, FileTimes, Handle, OpenIntent,
    OpenOptions, ShareBackend, WATCH_CHANGE_LAST_WRITE, WATCH_CHANGE_NAME, WATCH_CHANGE_SIZE,
    WatchAction, WatchEvent, WatchRecord,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;

/// Minimal in-memory FS used by integration tests. Files are byte vectors,
/// directories are sets of names. Not threadsafe across workers — only used
/// within one test.
pub struct MemFsBackend {
    inner: Arc<Mutex<MemInner>>,
}

#[derive(Default)]
struct MemInner {
    files: HashMap<String, Arc<Mutex<MemFile>>>,
    /// All directories present (always includes "" for the root). Each
    /// directory is keyed by canonical path string.
    dirs: HashMap<String, ()>,
    next_file_index: u64,
    next_watch_id: u64,
    watchers: HashMap<u64, MemWatcher>,
}

struct MemFile {
    data: Vec<u8>,
    allocation_size: u64,
    file_index: u64,
}

struct MemWatcher {
    path: String,
    recursive: bool,
    tx: mpsc::Sender<WatchEvent>,
}

impl Default for MemFsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFsBackend {
    pub fn new() -> Self {
        let mut inner = MemInner::default();
        inner.dirs.insert(String::new(), ());
        inner.next_file_index = 1;
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn with_file(self, path: &str, contents: &[u8]) -> Self {
        self.put_file(path, contents);
        self
    }

    pub fn put_file(&self, path: &str, contents: &[u8]) {
        let path = path.parse::<SmbPath>().expect("valid memfs path");
        let mut g = self.inner.lock().unwrap();
        let k = g.target_key_or_create_parent_dirs(&path);
        if let Some(existing) = g.find_file_key(&k) {
            let file = g.files.get(&existing).expect("file").clone();
            let mut file = file.lock().unwrap();
            file.data = contents.to_vec();
            let size = file.data.len() as u64;
            if size > file.allocation_size {
                file.allocation_size = mem_allocation_for_size(size);
            }
            drop(file);
            g.notify(
                &existing,
                WatchAction::Modified,
                false,
                WATCH_CHANGE_SIZE | WATCH_CHANGE_LAST_WRITE,
            );
            return;
        }
        let file = g.new_file(contents.to_vec());
        g.files.insert(k.clone(), file);
        g.notify(&k, WatchAction::Added, false, WATCH_CHANGE_NAME);
    }
}

fn key(path: &SmbPath) -> String {
    path.display_backslash()
}

fn join_key(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}\\{name}")
    }
}

impl MemInner {
    fn find_file_key(&self, wanted: &str) -> Option<String> {
        find_case_insensitive_key(&self.files, wanted)
    }

    fn find_dir_key(&self, wanted: &str) -> Option<String> {
        find_case_insensitive_key(&self.dirs, wanted)
    }

    fn target_key(&self, path: &SmbPath) -> SmbResult<String> {
        if path.is_root() {
            return Ok(String::new());
        }
        let parent = path.parent().expect("non-root path has parent");
        let parent_key = self
            .find_dir_key(&key(&parent))
            .ok_or(SmbError::PathNotFound)?;
        Ok(join_key(
            &parent_key,
            path.file_name().expect("non-root path has filename"),
        ))
    }

    fn target_key_or_create_parent_dirs(&mut self, path: &SmbPath) -> String {
        if path.is_root() {
            return String::new();
        }
        let mut parent_key = String::new();
        let components = path.components();
        for component in &components[..components.len() - 1] {
            let wanted = join_key(&parent_key, component);
            parent_key = match self.find_dir_key(&wanted) {
                Some(existing) => existing,
                None => {
                    self.dirs.insert(wanted.clone(), ());
                    wanted
                }
            };
        }
        join_key(
            &parent_key,
            path.file_name().expect("non-root path has filename"),
        )
    }

    fn new_file(&mut self, data: Vec<u8>) -> Arc<Mutex<MemFile>> {
        let file_index = self.next_file_index;
        self.next_file_index += 1;
        let allocation_size = mem_allocation_for_size(data.len() as u64);
        Arc::new(Mutex::new(MemFile {
            data,
            allocation_size,
            file_index,
        }))
    }

    fn add_watch(
        &mut self,
        inner: Arc<Mutex<MemInner>>,
        path: String,
        recursive: bool,
    ) -> BackendWatch {
        self.next_watch_id += 1;
        let id = self.next_watch_id;
        let (tx, rx) = mpsc::channel(16);
        self.watchers.insert(
            id,
            MemWatcher {
                path,
                recursive,
                tx,
            },
        );
        BackendWatch::new(rx, Box::new(MemWatchGuard { inner, id }))
    }

    fn notify(&self, path: &str, action: WatchAction, is_directory: bool, change: u32) {
        let Ok(event_path) = path.parse::<SmbPath>() else {
            return;
        };
        let event = WatchEvent {
            records: vec![WatchRecord {
                path: event_path,
                action,
                is_directory,
            }],
            change,
        };
        for watcher in self.watchers.values() {
            if watch_matches(&watcher.path, watcher.recursive, path) {
                let _ = watcher.tx.try_send(event.clone());
            }
        }
    }

    fn notify_rename(&self, from: &str, to: &str, is_directory: bool) {
        let (Ok(from_path), Ok(to_path)) = (from.parse::<SmbPath>(), to.parse::<SmbPath>()) else {
            return;
        };
        let event = WatchEvent {
            records: vec![
                WatchRecord {
                    path: from_path,
                    action: WatchAction::RenamedOld,
                    is_directory,
                },
                WatchRecord {
                    path: to_path,
                    action: WatchAction::RenamedNew,
                    is_directory,
                },
            ],
            change: WATCH_CHANGE_NAME,
        };
        for watcher in self.watchers.values() {
            if watch_matches(&watcher.path, watcher.recursive, from)
                || watch_matches(&watcher.path, watcher.recursive, to)
            {
                let _ = watcher.tx.try_send(event.clone());
            }
        }
    }
}

struct MemWatchGuard {
    inner: Arc<Mutex<MemInner>>,
    id: u64,
}

impl Drop for MemWatchGuard {
    fn drop(&mut self) {
        self.inner.lock().unwrap().watchers.remove(&self.id);
    }
}

fn find_case_insensitive_key<T>(map: &HashMap<String, T>, wanted: &str) -> Option<String> {
    if map.contains_key(wanted) {
        return Some(wanted.to_string());
    }
    map.keys()
        .find(|key| key.eq_ignore_ascii_case(wanted))
        .cloned()
}

fn watch_matches(watch: &str, recursive: bool, event: &str) -> bool {
    let parent = event_parent(event);
    if parent == watch {
        return true;
    }
    recursive && is_descendant(event, watch)
}

fn event_parent(event: &str) -> &str {
    event
        .rsplit_once('\\')
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

fn is_descendant(event: &str, watch: &str) -> bool {
    if watch.is_empty() {
        return !event.is_empty();
    }
    event
        .strip_prefix(watch)
        .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn mem_allocation_for_size(size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        size.div_ceil(4096) * 4096
    }
}

#[async_trait]
impl ShareBackend for MemFsBackend {
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        let mut g = self.inner.lock().unwrap();
        let k = g.target_key(path)?;
        let file_key = g.find_file_key(&k);
        let dir_key = g.find_dir_key(&k);

        if opts.directory {
            if file_key.is_some() {
                return Err(SmbError::NotADirectory);
            }
            let dir_key = if let Some(dir_key) = dir_key {
                dir_key
            } else {
                if matches!(opts.intent, OpenIntent::Create | OpenIntent::OpenOrCreate) {
                    g.dirs.insert(k.clone(), ());
                    g.notify(&k, WatchAction::Added, true, WATCH_CHANGE_NAME);
                } else {
                    return Err(SmbError::NotFound);
                }
                k
            };
            return Ok(Box::new(MemHandle::dir(self.inner.clone(), dir_key)));
        }

        if dir_key.is_some() {
            return Err(SmbError::IsDirectory);
        }

        let mut notify = None;
        let (key, file) = match opts.intent {
            OpenIntent::Open => {
                let key = file_key.ok_or(SmbError::NotFound)?;
                let file = g.files.get(&key).expect("file").clone();
                (key, file)
            }
            OpenIntent::Create => {
                if file_key.is_some() {
                    return Err(SmbError::Exists);
                }
                let file = g.new_file(Vec::new());
                g.files.insert(k.clone(), file.clone());
                notify = Some((k.clone(), WatchAction::Added, WATCH_CHANGE_NAME));
                (k, file)
            }
            OpenIntent::OpenOrCreate => {
                if let Some(key) = file_key {
                    let file = g.files.get(&key).expect("file").clone();
                    (key, file)
                } else {
                    let file = g.new_file(Vec::new());
                    g.files.insert(k.clone(), file.clone());
                    notify = Some((k.clone(), WatchAction::Added, WATCH_CHANGE_NAME));
                    (k, file)
                }
            }
            OpenIntent::Truncate => {
                let key = file_key.ok_or(SmbError::NotFound)?;
                let file = g.files.get(&key).expect("file").clone();
                file.lock().unwrap().data.clear();
                notify = Some((
                    key.clone(),
                    WatchAction::Modified,
                    WATCH_CHANGE_SIZE | WATCH_CHANGE_LAST_WRITE,
                ));
                (key, file)
            }
            OpenIntent::OverwriteOrCreate => {
                if let Some(key) = file_key {
                    let file = g.files.get(&key).expect("file").clone();
                    file.lock().unwrap().data.clear();
                    notify = Some((
                        key.clone(),
                        WatchAction::Modified,
                        WATCH_CHANGE_SIZE | WATCH_CHANGE_LAST_WRITE,
                    ));
                    (key, file)
                } else {
                    let file = g.new_file(Vec::new());
                    g.files.insert(k.clone(), file.clone());
                    notify = Some((k.clone(), WatchAction::Added, WATCH_CHANGE_NAME));
                    (k, file)
                }
            }
        };
        if let Some((path, action, change)) = notify {
            g.notify(&path, action, false, change);
        }
        Ok(Box::new(MemHandle::file(self.inner.clone(), key, file)))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        let mut g = self.inner.lock().unwrap();
        let k = g.target_key(path)?;
        if let Some(k) = g.find_file_key(&k) {
            g.files.remove(&k);
            g.notify(&k, WatchAction::Removed, false, WATCH_CHANGE_NAME);
            return Ok(());
        }
        if let Some(k) = g.find_dir_key(&k) {
            let prefix = format!("{k}\\");
            if g.files.keys().any(|name| name.starts_with(&prefix))
                || g.dirs.keys().any(|name| name.starts_with(&prefix))
            {
                return Err(SmbError::NotEmpty);
            }
            if k.is_empty() {
                return Err(SmbError::AccessDenied);
            }
            g.dirs.remove(&k);
            g.notify(&k, WatchAction::Removed, true, WATCH_CHANGE_NAME);
            return Ok(());
        }
        Err(SmbError::NotFound)
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath) -> SmbResult<()> {
        let mut g = self.inner.lock().unwrap();
        let kf = g.target_key(from)?;
        let kt = g.target_key(to)?;

        if let Some(existing) = g.find_file_key(&kt)
            && !existing.eq_ignore_ascii_case(&kf)
        {
            return Err(SmbError::Exists);
        }
        if let Some(existing) = g.find_dir_key(&kt)
            && !existing.eq_ignore_ascii_case(&kf)
        {
            return Err(SmbError::Exists);
        }

        if let Some(source) = g.find_file_key(&kf) {
            let file = g.files.remove(&source).expect("file");
            g.files.insert(kt.clone(), file);
            g.notify_rename(&source, &kt, false);
            return Ok(());
        }
        if let Some(source) = g.find_dir_key(&kf) {
            if source.is_empty() {
                return Err(SmbError::AccessDenied);
            }
            let old_prefix = format!("{source}\\");
            let file_moves: Vec<(String, String)> = g
                .files
                .keys()
                .filter_map(|name| {
                    name.strip_prefix(&old_prefix)
                        .map(|suffix| (name.clone(), join_key(&kt, suffix)))
                })
                .collect();
            let dir_moves: Vec<(String, String)> = g
                .dirs
                .keys()
                .filter_map(|name| {
                    if name == &source {
                        Some((name.clone(), kt.clone()))
                    } else {
                        name.strip_prefix(&old_prefix)
                            .map(|suffix| (name.clone(), join_key(&kt, suffix)))
                    }
                })
                .collect();
            for (old, new) in file_moves {
                if let Some(file) = g.files.remove(&old) {
                    g.files.insert(new, file);
                }
            }
            for (old, new) in dir_moves {
                if g.dirs.remove(&old).is_some() {
                    g.dirs.insert(new, ());
                }
            }
            g.notify_rename(&source, &kt, true);
            return Ok(());
        }
        Err(SmbError::NotFound)
    }

    async fn watch(&self, path: &SmbPath, recursive: bool) -> SmbResult<Option<BackendWatch>> {
        let mut g = self.inner.lock().unwrap();
        let k = g.target_key(path)?;
        if g.find_file_key(&k).is_some() {
            return Err(SmbError::NotADirectory);
        }
        let dir_key = g.find_dir_key(&k).ok_or(SmbError::NotFound)?;
        Ok(Some(g.add_watch(self.inner.clone(), dir_key, recursive)))
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: false,
            case_sensitive: false,
        }
    }
}

pub struct MemHandle {
    inner: Arc<Mutex<MemInner>>,
    key: String,
    file: Option<Arc<Mutex<MemFile>>>,
    is_dir: bool,
}

impl MemHandle {
    fn file(inner: Arc<Mutex<MemInner>>, key: String, file: Arc<Mutex<MemFile>>) -> Self {
        Self {
            inner,
            key,
            file: Some(file),
            is_dir: false,
        }
    }

    fn dir(inner: Arc<Mutex<MemInner>>, key: String) -> Self {
        Self {
            inner,
            key,
            file: None,
            is_dir: true,
        }
    }
}

#[async_trait]
impl Handle for MemHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        if self.is_dir {
            return Err(SmbError::IsDirectory);
        }
        let file = self
            .file
            .as_ref()
            .ok_or(SmbError::NotFound)?
            .lock()
            .unwrap();
        let data = &file.data;
        let start = offset as usize;
        if start >= data.len() {
            return Ok(Bytes::new());
        }
        let end = (start + len as usize).min(data.len());
        Ok(Bytes::copy_from_slice(&data[start..end]))
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        if self.is_dir {
            return Err(SmbError::IsDirectory);
        }
        let file = self.file.as_ref().ok_or(SmbError::NotFound)?;
        let mut file = file.lock().unwrap();
        let needed = (offset as usize) + data.len();
        if file.data.len() < needed {
            file.data.resize(needed, 0);
            let size = needed as u64;
            if size > file.allocation_size {
                file.allocation_size = mem_allocation_for_size(size);
            }
        }
        file.data[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        drop(file);
        self.inner.lock().unwrap().notify(
            &self.key,
            WatchAction::Modified,
            false,
            WATCH_CHANGE_SIZE | WATCH_CHANGE_LAST_WRITE,
        );
        Ok(data.len() as u32)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let (size, allocation_size, file_index) = if self.is_dir {
            (0, 0, 0)
        } else {
            let file = self
                .file
                .as_ref()
                .ok_or(SmbError::NotFound)?
                .lock()
                .unwrap();
            (
                file.data.len() as u64,
                file.allocation_size,
                file.file_index,
            )
        };
        let name = self
            .key
            .rsplit_once('\\')
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| self.key.clone());
        Ok(FileInfo {
            name,
            end_of_file: size,
            allocation_size,
            creation_time: 0x01D9_0000_0000_0000,
            last_access_time: 0x01D9_0000_0000_0000,
            last_write_time: 0x01D9_0000_0000_0000,
            change_time: 0x01D9_0000_0000_0000,
            is_directory: self.is_dir,
            file_index,
            file_attributes: crate::backend::default_file_attributes(self.is_dir),
        })
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        if self.is_dir {
            return Err(SmbError::IsDirectory);
        }
        let file = self.file.as_ref().ok_or(SmbError::NotFound)?;
        {
            let mut file = file.lock().unwrap();
            file.data.resize(len as usize, 0);
            if len > file.allocation_size {
                file.allocation_size = mem_allocation_for_size(len);
            }
        }
        self.inner.lock().unwrap().notify(
            &self.key,
            WatchAction::Modified,
            false,
            WATCH_CHANGE_SIZE | WATCH_CHANGE_LAST_WRITE,
        );
        Ok(())
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        if !self.is_dir {
            return Err(SmbError::NotADirectory);
        }
        let g = self.inner.lock().unwrap();
        let prefix = if self.key.is_empty() {
            String::new()
        } else {
            format!("{}\\", self.key)
        };
        let mut entries = Vec::new();
        for (k, v) in g.files.iter() {
            if let Some(rest) = k.strip_prefix(&prefix)
                && !rest.contains('\\')
            {
                let file = v.lock().unwrap();
                entries.push(DirEntry {
                    info: FileInfo {
                        name: rest.to_string(),
                        end_of_file: file.data.len() as u64,
                        allocation_size: file.allocation_size,
                        creation_time: 0x01D9_0000_0000_0000,
                        last_access_time: 0x01D9_0000_0000_0000,
                        last_write_time: 0x01D9_0000_0000_0000,
                        change_time: 0x01D9_0000_0000_0000,
                        is_directory: false,
                        file_index: file.file_index,
                        file_attributes: crate::backend::default_file_attributes(false),
                    },
                });
            }
        }
        for k in g.dirs.keys() {
            if let Some(rest) = k.strip_prefix(&prefix)
                && !rest.is_empty()
                && !rest.contains('\\')
            {
                entries.push(DirEntry {
                    info: FileInfo {
                        name: rest.to_string(),
                        end_of_file: 0,
                        allocation_size: 0,
                        creation_time: 0x01D9_0000_0000_0000,
                        last_access_time: 0x01D9_0000_0000_0000,
                        last_write_time: 0x01D9_0000_0000_0000,
                        change_time: 0x01D9_0000_0000_0000,
                        is_directory: true,
                        file_index: 0,
                        file_attributes: crate::backend::default_file_attributes(true),
                    },
                });
            }
        }
        Ok(entries)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    fn path(value: &str) -> SmbPath {
        value.parse().expect("valid SMB path")
    }

    fn create_file_options() -> OpenOptions {
        OpenOptions {
            write: true,
            intent: OpenIntent::Create,
            ..Default::default()
        }
    }

    fn create_dir_options() -> OpenOptions {
        OpenOptions {
            write: true,
            intent: OpenIntent::Create,
            directory: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn resolves_existing_paths_case_insensitively() {
        let fs = MemFsBackend::new();
        fs.open(&path("MiXeD"), create_dir_options()).await.unwrap();
        fs.put_file("MiXeD/Name.TXT", b"hello");

        let handle = fs
            .open(&path("mixed/name.txt"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(&handle.read(0, 5).await.unwrap()[..], b"hello");
        assert_eq!(handle.stat().await.unwrap().name, "Name.TXT");

        let handle = fs
            .open(&path("MIXED/NAME.TXT"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(handle.stat().await.unwrap().name, "Name.TXT");
    }

    #[tokio::test]
    async fn create_uses_canonical_parent_and_rejects_case_collision() {
        let fs = MemFsBackend::new();
        fs.open(&path("MiXeD"), create_dir_options()).await.unwrap();
        fs.open(&path("mixed/New.TXT"), create_file_options())
            .await
            .unwrap();

        let dir = fs
            .open(
                &path("MIXED"),
                OpenOptions {
                    directory: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let entries = dir.list_dir(None).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].info.name, "New.TXT");

        match fs.open(&path("MiXeD/new.txt"), create_file_options()).await {
            Err(SmbError::Exists) => {}
            Err(err) => panic!("case-colliding create returned {err:?}"),
            Ok(_) => panic!("case-colliding create succeeded"),
        }
    }

    #[tokio::test]
    async fn create_existing_file_fails() {
        let fs = MemFsBackend::new();
        fs.open(&path("file.txt"), create_file_options())
            .await
            .unwrap();

        match fs.open(&path("file.txt"), create_file_options()).await {
            Err(SmbError::Exists) => {}
            Err(err) => panic!("second create returned {err:?}"),
            Ok(_) => panic!("second create unexpectedly succeeded"),
        }
    }

    #[tokio::test]
    async fn write_extends_allocation_to_next_cluster() {
        let fs = MemFsBackend::new();
        let handle = fs
            .open(&path("file.txt"), create_file_options())
            .await
            .unwrap();

        handle.truncate(4096).await.unwrap();
        assert_eq!(handle.stat().await.unwrap().allocation_size, 4096);

        handle.write(1, &vec![0; 4096]).await.unwrap();
        let info = handle.stat().await.unwrap();
        assert_eq!(info.end_of_file, 4097);
        assert_eq!(info.allocation_size, 8192);
    }

    #[tokio::test]
    async fn open_handle_survives_unlink() {
        let fs = MemFsBackend::new();
        fs.put_file("open.txt", b"still here");
        let handle = fs
            .open(&path("OPEN.TXT"), OpenOptions::default())
            .await
            .unwrap();

        fs.unlink(&path("open.txt")).await.unwrap();
        match fs.open(&path("open.txt"), OpenOptions::default()).await {
            Err(SmbError::NotFound) => {}
            Err(err) => panic!("removed file open returned {err:?}"),
            Ok(_) => panic!("removed file open succeeded"),
        }

        assert_eq!(
            &handle.read(0, "still here".len() as u32).await.unwrap()[..],
            b"still here"
        );
        assert_eq!(
            handle.stat().await.unwrap().end_of_file,
            "still here".len() as u64
        );
    }

    #[tokio::test]
    async fn put_file_updates_existing_open_node() {
        let fs = MemFsBackend::new();
        fs.put_file("open.txt", b"before");
        let handle = fs
            .open(&path("open.txt"), OpenOptions::default())
            .await
            .unwrap();
        let original_id = handle.stat().await.unwrap().file_index;

        fs.put_file("OPEN.TXT", b"after");

        assert_eq!(&handle.read(0, 5).await.unwrap()[..], b"after");
        assert_eq!(handle.stat().await.unwrap().file_index, original_id);
        let reopened = fs
            .open(&path("open.txt"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(reopened.stat().await.unwrap().file_index, original_id);
    }

    #[tokio::test]
    async fn rename_can_change_only_case_and_rekeys_directory_children() {
        let fs = MemFsBackend::new();
        fs.put_file("Dir/File.TXT", b"data");

        fs.rename(&path("dir\\file.txt"), &path("DIR\\FILE.TXT"))
            .await
            .unwrap();
        let handle = fs
            .open(&path("dir/file.txt"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(handle.stat().await.unwrap().name, "FILE.TXT");

        fs.rename(&path("dir"), &path("Docs")).await.unwrap();
        let handle = fs
            .open(&path("docs/file.txt"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(&handle.read(0, 4).await.unwrap()[..], b"data");
        assert!(matches!(
            fs.open(&path("dir/file.txt"), OpenOptions::default()).await,
            Err(SmbError::PathNotFound)
        ));
    }

    #[tokio::test]
    async fn watch_reports_direct_child_changes() {
        let fs = MemFsBackend::new();
        let mut watch = fs.watch(&path("\\"), false).await.unwrap().unwrap();

        fs.put_file("hello.txt", b"hello");

        let event = wait_for_watch_event(&mut watch).await;
        assert_eq!(event.change, WATCH_CHANGE_NAME);
        assert_eq!(event.records.len(), 1);
        assert_eq!(event.records[0].path, path("hello.txt"));
        assert_eq!(event.records[0].action, WatchAction::Added);
        assert!(!event.records[0].is_directory);
    }

    #[tokio::test]
    async fn watch_honors_recursive_option() {
        let fs = MemFsBackend::new();
        fs.open(&path("docs"), create_dir_options()).await.unwrap();
        let mut non_recursive = fs.watch(&path("\\"), false).await.unwrap().unwrap();

        fs.put_file("docs/nested.txt", b"nested");
        assert!(
            timeout(Duration::from_millis(25), non_recursive.recv())
                .await
                .is_err(),
            "non-recursive root watch received nested event"
        );

        let mut recursive = fs.watch(&path("\\"), true).await.unwrap().unwrap();
        fs.put_file("docs/again.txt", b"again");

        let event = wait_for_watch_event(&mut recursive).await;
        assert_eq!(event.change, WATCH_CHANGE_NAME);
        assert_eq!(event.records.len(), 1);
        assert_eq!(event.records[0].path, path("docs\\again.txt"));
        assert_eq!(event.records[0].action, WatchAction::Added);
    }

    #[tokio::test]
    async fn watch_reports_open_handle_write_changes() {
        let fs = MemFsBackend::new();
        fs.put_file("hello.txt", b"hello");
        let handle = fs
            .open(
                &path("hello.txt"),
                OpenOptions {
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut watch = fs.watch(&path("\\"), false).await.unwrap().unwrap();

        handle.write(0, b"HELLO").await.unwrap();

        let event = wait_for_watch_event(&mut watch).await;
        assert_eq!(event.change, WATCH_CHANGE_SIZE | WATCH_CHANGE_LAST_WRITE);
        assert_eq!(event.records.len(), 1);
        assert_eq!(event.records[0].path, path("hello.txt"));
        assert_eq!(event.records[0].action, WatchAction::Modified);
        assert!(!event.records[0].is_directory);
    }

    #[tokio::test]
    async fn watch_rename_reports_old_and_new_names() {
        let fs = MemFsBackend::new();
        fs.put_file("old.txt", b"data");
        let mut watch = fs.watch(&path("\\"), false).await.unwrap().unwrap();

        fs.rename(&path("old.txt"), &path("new.txt")).await.unwrap();

        let event = wait_for_watch_event(&mut watch).await;
        assert_eq!(event.change, WATCH_CHANGE_NAME);
        assert_eq!(event.records.len(), 2);
        assert_eq!(event.records[0].path, path("old.txt"));
        assert_eq!(event.records[0].action, WatchAction::RenamedOld);
        assert!(!event.records[0].is_directory);
        assert_eq!(event.records[1].path, path("new.txt"));
        assert_eq!(event.records[1].action, WatchAction::RenamedNew);
        assert!(!event.records[1].is_directory);
    }

    #[tokio::test]
    async fn unlink_rejects_non_empty_directory() {
        let fs = MemFsBackend::new();
        fs.put_file("docs/file.txt", b"data");

        let err = fs.unlink(&path("DOCS")).await.unwrap_err();
        assert!(matches!(err, SmbError::NotEmpty));
        fs.unlink(&path("docs/file.txt")).await.unwrap();
        fs.unlink(&path("docs")).await.unwrap();
    }

    async fn wait_for_watch_event(watch: &mut BackendWatch) -> WatchEvent {
        timeout(Duration::from_secs(1), watch.recv())
            .await
            .expect("timed out waiting for MemFS event")
            .expect("watch closed before event")
    }
}
