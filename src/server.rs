//! Top-level `SmbServer` lifecycle: builder integration, accept loop,
//! graceful shutdown.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock, Weak};
use std::time::{Duration, Instant};

use crate::proto::auth::ntlm::UserCreds;
use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, Notify, RwLock, mpsc, oneshot};
use tracing::{Instrument, debug, error, info, info_span};
use uuid::Uuid;

use crate::backend::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
    FILE_ATTRIBUTE_TEMPORARY, FileInfo, FileTimes, Handle, OpenIntent, ShareBackend,
    WATCH_CHANGE_ATTRIBUTES, WATCH_CHANGE_CREATION, WATCH_CHANGE_LAST_ACCESS,
    WATCH_CHANGE_LAST_WRITE, WATCH_CHANGE_SECURITY, WATCH_CHANGE_SIZE, WatchAction, WatchEvent,
    default_file_attributes,
};
use crate::builder::{Access, Share, SmbServerBuilder};
use crate::conn::connection_loop;
use crate::conn::state::{Connection, NotifyEvent, Open, TreeConnect};
use crate::dispatch::{self, HandlerResponse};
use crate::error::{SmbError, SmbResult};
use crate::info_class::{ExtendedAttribute, FileStream, PosixMetadata};
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::crypto::SigningAlgo;
use crate::proto::header::{Command, Smb2Header};
use crate::proto::messages::{
    Dialect, FileId, LeaseBreakNotification, OplockBreakNotification, WriteResponse,
};
use crate::utils::now_filetime;

const CHANGE_NOTIFY_COALESCE_DELAY: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// ShareMode / ShareBindings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    Public,
    PublicReadOnly,
    /// Default — closed share. Only users in the explicit `users` map allowed.
    AuthenticatedOnly,
}

#[derive(Clone)]
pub struct ShareAcl {
    pub mode: ShareMode,
    pub users: HashMap<String, Access>,
}

/// Compiled binding for a single share — the per-server-state form of `Share`.
pub struct ShareBindings {
    pub name: String,
    pub backend: Arc<dyn ShareBackend>,
    pub acl: RwLock<ShareAcl>,
    /// `IPC$` synthetic share. Accepted at TREE_CONNECT for client compatibility
    /// (Windows always probes IPC$ before mounting an actual share). The CREATE
    /// handler supports a small set of named pipes; broader pipe RPC behavior
    /// is implemented by the command handlers incrementally.
    pub is_ipc: bool,
}

impl ShareBindings {
    pub(crate) fn new(
        name: String,
        backend: Arc<dyn ShareBackend>,
        mode: ShareMode,
        users: HashMap<String, Access>,
        is_ipc: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            name,
            backend,
            acl: RwLock::new(ShareAcl { mode, users }),
            is_ipc,
        })
    }

    /// Synthetic IPC$ share. The backend is a no-op; IPC named pipes are
    /// opened directly by the CREATE handler.
    pub fn ipc() -> Arc<Self> {
        Self::new(
            "IPC$".to_string(),
            Arc::new(crate::backend::NotSupportedBackend),
            ShareMode::PublicReadOnly,
            HashMap::new(),
            true,
        )
    }
}

// ---------------------------------------------------------------------------
// ServerConfig / ServerUsers / ServerState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub netbios_name: String,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub max_credits: u16,
    pub durable_handle_timeout: Duration,
    pub cache_break_timeout: Duration,
    pub server_guid: Uuid,
    pub require_signing: bool,
    pub encrypt_data: bool,
    pub disable_compression: bool,
}

pub struct ServerUsers {
    /// Username → precomputed NT hash record.
    pub table: RwLock<HashMap<String, UserCreds>>,
}

pub struct ServerShares {
    by_name: RwLock<HashMap<String, Arc<ShareBindings>>>,
}

impl ServerShares {
    pub fn new(shares: Vec<Arc<ShareBindings>>) -> Self {
        let mut by_name = HashMap::with_capacity(shares.len());
        for share in shares {
            by_name.insert(share.name.to_ascii_lowercase(), share);
        }
        Self {
            by_name: RwLock::new(by_name),
        }
    }

    pub async fn find(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.by_name
            .read()
            .await
            .get(&name.to_ascii_lowercase())
            .cloned()
    }

    pub async fn insert(&self, share: Arc<ShareBindings>) -> Result<(), ConfigError> {
        let key = share.name.to_ascii_lowercase();
        let mut by_name = self.by_name.write().await;
        if by_name.contains_key(&key) {
            return Err(ConfigError::DuplicateShare(share.name.clone()));
        }
        by_name.insert(key, share);
        Ok(())
    }

    pub async fn remove(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.by_name
            .write()
            .await
            .remove(&name.to_ascii_lowercase())
    }

    pub async fn all(&self) -> Vec<Arc<ShareBindings>> {
        self.by_name.read().await.values().cloned().collect()
    }
}

pub struct ActiveConnections {
    next_id: AtomicU64,
    conns: RwLock<HashMap<u64, Weak<Connection>>>,
}

impl ActiveConnections {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(&self, conn: &Arc<Connection>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns.write().await.insert(id, Arc::downgrade(conn));
        id
    }

    pub async fn unregister(&self, id: u64) {
        self.conns.write().await.remove(&id);
    }

    pub async fn live(&self) -> Vec<Arc<Connection>> {
        let mut live = Vec::new();
        let mut conns = self.conns.write().await;
        conns.retain(|_, weak| {
            if let Some(conn) = weak.upgrade() {
                live.push(conn);
                true
            } else {
                false
            }
        });
        live
    }

    pub async fn live_with_ids(&self) -> Vec<(u64, Arc<Connection>)> {
        let mut live = Vec::new();
        let mut conns = self.conns.write().await;
        conns.retain(|id, weak| {
            if let Some(conn) = weak.upgrade() {
                live.push((*id, conn));
                true
            } else {
                false
            }
        });
        live.sort_by_key(|(id, _)| *id);
        live
    }
}

impl Default for ActiveConnections {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level immutable-ish state shared across connections.
pub struct ServerState {
    pub config: ServerConfig,
    pub users: ServerUsers,
    pub shares: ServerShares,
    pub active_connections: ActiveConnections,
    next_session_id: AtomicU64,
    next_file_id: AtomicU64,
    pub server_start_filetime: u64,
    /// Set when `shutdown()` is invoked; the accept loop stops on the next
    /// iteration and connection loops abandon their next read.
    pub shutdown: Arc<Notify>,
    pub shutting_down: Arc<AtomicBool>,
    posix_metadata: StdRwLock<HashMap<PosixKey, PosixMetadata>>,
    security_descriptors: StdRwLock<HashMap<PosixKey, Vec<u8>>>,
    extended_attributes: StdRwLock<HashMap<PosixKey, Vec<ExtendedAttribute>>>,
    allocation_sizes: StdRwLock<HashMap<PosixKey, u64>>,
    file_attributes: StdRwLock<HashMap<PosixKey, u32>>,
    file_times: StdRwLock<HashMap<PosixKey, FileTimes>>,
    sticky_write_time_owners: StdRwLock<HashMap<PosixKey, FileId>>,
    pinned_write_times: StdRwLock<HashSet<PosixKey>>,
    deleted_names: StdRwLock<HashSet<PosixKey>>,
    streams: StdRwLock<HashMap<PosixKey, Vec<NamedStream>>>,
    namespace_locks: StdRwLock<HashMap<PosixKey, Weak<AsyncMutex<()>>>>,
    open_registry: StdRwLock<Vec<OpenRegistryEntry>>,
    durable_opens: StdRwLock<HashMap<FileId, DurableOpen>>,
    delete_pending: StdRwLock<HashMap<PosixKey, bool>>,
    byte_range_locks: StdRwLock<HashMap<ByteRangeLockKey, Vec<ByteRangeLock>>>,
    change_notifies: Arc<StdRwLock<HashMap<PendingChangeNotifyKey, PendingChangeNotify>>>,
    pipe_reads: StdRwLock<HashMap<PendingPipeReadKey, PendingPipeRead>>,
    byte_range_lock_waits: StdRwLock<HashMap<PendingByteRangeLockKey, PendingByteRangeLock>>,
    cache_break_creates: StdRwLock<HashMap<PendingCacheBreakCreateKey, PendingCacheBreakCreate>>,
    completed_create_replays: StdRwLock<HashMap<CreateReplayKey, Vec<u8>>>,
    cache_break_writes: StdRwLock<HashMap<PendingCacheBreakWriteKey, PendingCacheBreakWrite>>,
    cache_break_tasks: StdRwLock<HashMap<PendingCacheBreakTaskKey, PendingCacheBreakTask>>,
    lease_break_generations: StdRwLock<HashMap<[u8; 16], u64>>,
}

#[derive(Clone)]
struct OpenRegistryEntry {
    share: String,
    path: SmbPath,
    stream_name: Option<String>,
    open: Weak<RwLock<Open>>,
    conn: Weak<Connection>,
}

#[derive(Debug, Clone, Copy)]
pub struct SameKeyLeaseState {
    pub state: u32,
    pub flags: u32,
    pub epoch: u16,
    pub version: u8,
    pub breaking: bool,
}

struct DurableOpen {
    share: String,
    open: Arc<RwLock<Open>>,
    client_guid: Uuid,
    owner: String,
    attached_conn: Option<usize>,
    attached_session_id: Option<u64>,
    expires_at: Option<Instant>,
}

pub(crate) enum DurableReplayLookup {
    NotFound,
    AttachedElsewhere,
    Available(Arc<RwLock<Open>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingChangeNotifyKey {
    conn: usize,
    async_id: u64,
}

struct PendingChangeNotify {
    conn: Weak<Connection>,
    open: Weak<RwLock<Open>>,
    tx: mpsc::Sender<Vec<u8>>,
    req_hdr: Smb2Header,
    file_id: FileId,
    share: String,
    path: SmbPath,
    recursive: bool,
    output_buffer_length: u32,
    completion_filter: u32,
    notify_first: bool,
    notify_force_enum_dir: bool,
    notify_events: Vec<NotifyEvent>,
    notify_completion_scheduled: bool,
    watch_cancel: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingPipeReadKey {
    conn: usize,
    async_id: u64,
}

struct PendingPipeRead {
    conn: Weak<Connection>,
    tx: mpsc::Sender<Vec<u8>>,
    req_hdr: Smb2Header,
    file_id: FileId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingByteRangeLockKey {
    conn: usize,
    async_id: u64,
}

struct PendingByteRangeLock {
    conn: Weak<Connection>,
    open: Weak<RwLock<Open>>,
    tx: mpsc::Sender<Vec<u8>>,
    req_hdr: Smb2Header,
    share: String,
    path: SmbPath,
    stream_name: Option<String>,
    file_id: FileId,
    dialect: Option<Dialect>,
    lock_sequence: u32,
    locks: Vec<ByteRangeLockRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingCacheBreakCreateKey {
    conn: usize,
    async_id: u64,
}

struct PendingCacheBreakCreate {
    conn: Weak<Connection>,
    tx: mpsc::Sender<Vec<u8>>,
    req_hdr: Smb2Header,
    wait_lease_keys: Vec<[u8; 16]>,
    wait_oplock_file_ids: Vec<FileId>,
    file_id: FileId,
    status: u32,
    body: Vec<u8>,
    replay_create_guid: Option<[u8; 16]>,
    replay_client_guid: Uuid,
    replay_owner: String,
    compound_completion: Option<CacheBreakCompoundCompletion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CreateReplayKey {
    create_guid: [u8; 16],
    client_guid: Uuid,
    owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingCacheBreakWriteKey {
    conn: usize,
    async_id: u64,
}

struct PendingCacheBreakWrite {
    conn: Weak<Connection>,
    open: Weak<RwLock<Open>>,
    tx: mpsc::Sender<Vec<u8>>,
    req_hdr: Smb2Header,
    wait_lease_keys: Vec<[u8; 16]>,
    share: String,
    path: SmbPath,
    stream_name: Option<String>,
    file_id: FileId,
    offset: u64,
    data: Vec<u8>,
    is_directory: bool,
    compound_completion: Option<CacheBreakCompoundCompletion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingCacheBreakTaskKey {
    conn: usize,
    async_id: u64,
}

pub(crate) type CacheBreakCompletion =
    Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = HandlerResponse> + Send>> + Send + Sync>;
pub(crate) type CacheBreakCompoundCompletion =
    Box<dyn FnOnce(HandlerResponse) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> + Send + Sync>;

struct PendingCacheBreakTask {
    conn: Weak<Connection>,
    tx: mpsc::Sender<Vec<u8>>,
    req_hdr: Smb2Header,
    wait_lease_keys: Vec<[u8; 16]>,
    wait_oplock_file_ids: Vec<FileId>,
    completion: Option<CacheBreakCompletion>,
    compound_completion: Option<CacheBreakCompoundCompletion>,
    replay_create_guid: Option<[u8; 16]>,
    replay_client_guid: Uuid,
    replay_owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteRangeLockRequest {
    pub fid: crate::proto::messages::FileId,
    pub offset: u64,
    pub length: u64,
    pub exclusive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ByteRangeLockKey {
    share: String,
    path: String,
    stream_name: Option<String>,
}

#[derive(Debug, Clone)]
struct ByteRangeLock {
    fid: crate::proto::messages::FileId,
    offset: u64,
    length: u64,
    exclusive: bool,
}

impl ByteRangeLockKey {
    fn new(share: &str, path: &SmbPath, stream_name: Option<&str>) -> Self {
        Self {
            share: share.to_ascii_lowercase(),
            path: path.display_backslash().to_ascii_lowercase(),
            stream_name: stream_name.map(str::to_ascii_lowercase),
        }
    }
}

fn lock_conflicts(existing: &[ByteRangeLock], next: &ByteRangeLock) -> bool {
    existing.iter().any(|held| {
        if !ranges_overlap(held.offset, held.length, next.offset, next.length) {
            return false;
        }
        if held.fid == next.fid {
            return next.exclusive;
        }
        held.exclusive || next.exclusive
    })
}

fn ranges_overlap(a_offset: u64, a_length: u64, b_offset: u64, b_length: u64) -> bool {
    if a_length == 0 && b_length == 0 {
        return false;
    }
    if a_length == 0 {
        return b_length != 0
            && b_offset < a_offset
            && range_end_inclusive(b_offset, b_length) >= a_offset;
    }
    if b_length == 0 {
        return a_offset < b_offset && range_end_inclusive(a_offset, a_length) >= b_offset;
    }
    let a_end = range_end_inclusive(a_offset, a_length);
    let b_end = range_end_inclusive(b_offset, b_length);
    a_offset <= b_end && b_offset <= a_end
}

fn round_allocation_size(size: u64) -> u64 {
    const CLUSTER_SIZE: u64 = 4096;
    if size == 0 {
        return 0;
    }
    size.saturating_add(CLUSTER_SIZE - 1) / CLUSTER_SIZE * CLUSTER_SIZE
}

fn normalize_stored_file_attributes(attributes: u32, is_directory: bool) -> u32 {
    let meaningful = attributes
        & (FILE_ATTRIBUTE_READONLY
            | FILE_ATTRIBUTE_HIDDEN
            | FILE_ATTRIBUTE_SYSTEM
            | FILE_ATTRIBUTE_ARCHIVE
            | FILE_ATTRIBUTE_DIRECTORY
            | FILE_ATTRIBUTE_NORMAL
            | FILE_ATTRIBUTE_TEMPORARY
            | FILE_ATTRIBUTE_OFFLINE);
    if is_directory {
        (meaningful & !FILE_ATTRIBUTE_ARCHIVE & !FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_DIRECTORY
    } else {
        let attrs = meaningful & !FILE_ATTRIBUTE_DIRECTORY;
        if attrs == 0 || attrs == FILE_ATTRIBUTE_NORMAL {
            FILE_ATTRIBUTE_NORMAL
        } else {
            attrs & !FILE_ATTRIBUTE_NORMAL
        }
    }
}

pub(crate) fn volume_id_for_share(share: &str) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    for byte in share.to_ascii_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash.max(1)
}

fn range_end_inclusive(offset: u64, length: u64) -> u64 {
    if length == 0 {
        u64::MAX
    } else {
        offset.wrapping_add(length).wrapping_sub(1)
    }
}

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const LEASE_READ_CACHING: u32 = 0x0000_0001;
const LEASE_HANDLE_CACHING: u32 = 0x0000_0002;
const LEASE_WRITE_CACHING: u32 = 0x0000_0004;
const LEASE_BREAK_ACK_REQUIRED: u32 = 0x0000_0001;
const OPLOCK_NONE: u8 = 0x00;
const OPLOCK_LEVEL_II: u8 = 0x01;
const OPLOCK_EXCLUSIVE: u8 = 0x08;
const OPLOCK_BATCH: u8 = 0x09;
const DEFAULT_MAX_ASYNC_CREDITS: usize = 512;
const MAX_PENDING_ASYNC_REQUESTS: usize = DEFAULT_MAX_ASYNC_CREDITS - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequestedLease {
    pub key: [u8; 16],
    pub state: u32,
}

fn share_conflict(access: u32, peer_share: u32) -> bool {
    (share_needs_read(access) && peer_share & FILE_SHARE_READ == 0)
        || (share_needs_write(access) && peer_share & FILE_SHARE_WRITE == 0)
        || (share_needs_delete(access) && peer_share & FILE_SHARE_DELETE == 0)
}

fn share_enforced_by_access(access: u32) -> bool {
    share_needs_read(access) || share_needs_write(access) || share_needs_delete(access)
}

fn share_needs_read(access: u32) -> bool {
    access & (FILE_READ_DATA | FILE_EXECUTE) != 0
}

fn share_needs_write(access: u32) -> bool {
    access & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0
}

fn share_needs_delete(access: u32) -> bool {
    access & DELETE != 0
}

fn reserve_pending_async_slot(conn: &Arc<Connection>) -> bool {
    conn.try_reserve_pending_async(MAX_PENDING_ASYNC_REQUESTS)
}

fn release_pending_async_slot(conn: &Weak<Connection>) {
    if let Some(conn) = conn.upgrade() {
        conn.release_pending_async();
    }
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

fn preserve_detached_durable_for_fresh_open(
    open: &Open,
    requested_lease: Option<RequestedLease>,
) -> bool {
    if open.durable_version < 2 {
        return false;
    }
    let Some(lease) = requested_lease else {
        return false;
    };
    let requested_state =
        lease.state & (LEASE_READ_CACHING | LEASE_HANDLE_CACHING | LEASE_WRITE_CACHING);
    if requested_state & (LEASE_READ_CACHING | LEASE_HANDLE_CACHING)
        != (LEASE_READ_CACHING | LEASE_HANDLE_CACHING)
    {
        return false;
    }
    !(open.lease_state & LEASE_WRITE_CACHING != 0
        && requested_state != 0
        && lease.key != open.lease_key)
}

fn valid_lease_break_ack_state(ack_state: u32, break_to: u32) -> bool {
    if ack_state & !break_to != 0 {
        return false;
    }
    if ack_state & LEASE_HANDLE_CACHING != 0 && ack_state & LEASE_READ_CACHING == 0 {
        return false;
    }
    true
}

fn staged_lease_break_target(current: u32, final_target: u32) -> u32 {
    let target = current & final_target;
    if target == current {
        return current;
    }
    if current & LEASE_WRITE_CACHING != 0 && target & LEASE_WRITE_CACHING == 0 {
        return current & !LEASE_WRITE_CACHING;
    }
    if current & LEASE_HANDLE_CACHING != 0 && target & LEASE_HANDLE_CACHING == 0 {
        return current & !LEASE_HANDLE_CACHING;
    }
    target
}

fn oplock_break_target(current: u8, requested_target: u8) -> u8 {
    match requested_target {
        OPLOCK_LEVEL_II if matches!(current, OPLOCK_EXCLUSIVE | OPLOCK_BATCH) => OPLOCK_LEVEL_II,
        OPLOCK_NONE if matches!(current, OPLOCK_LEVEL_II | OPLOCK_EXCLUSIVE | OPLOCK_BATCH) => {
            OPLOCK_NONE
        }
        _ => current,
    }
}

fn valid_oplock_break_ack_for_target(level: u8, target: u8) -> bool {
    level == target || (target == OPLOCK_LEVEL_II && level == OPLOCK_NONE)
}

fn durable_reconnect_caching_valid(open: &Open) -> bool {
    if open.lease_state != 0 {
        open.lease_state & LEASE_HANDLE_CACHING != 0
    } else {
        open.oplock_level == OPLOCK_BATCH
    }
}

fn notify_watch_matches(
    watch: &SmbPath,
    recursive: bool,
    event: &SmbPath,
    parent: &SmbPath,
) -> bool {
    if watch == parent {
        return true;
    }
    recursive && path_is_descendant(event, watch)
}

fn notify_filter_matches(completion_filter: u32, wanted_filter: u32) -> bool {
    completion_filter == 0 || completion_filter & wanted_filter != 0
}

fn notify_relative_name(watch: &SmbPath, event: &SmbPath) -> String {
    let watch_components = watch.components();
    let event_components = event.components();
    if event_components.starts_with(watch_components)
        && event_components.len() > watch_components.len()
    {
        event_components[watch_components.len()..].join("\\")
    } else {
        event
            .file_name()
            .map(str::to_string)
            .unwrap_or_else(|| event.display_backslash())
    }
}

fn change_notify_key(conn: &Arc<Connection>, async_id: u64) -> PendingChangeNotifyKey {
    PendingChangeNotifyKey {
        conn: connection_key(conn),
        async_id,
    }
}

fn pipe_read_key(conn: &Arc<Connection>, async_id: u64) -> PendingPipeReadKey {
    PendingPipeReadKey {
        conn: connection_key(conn),
        async_id,
    }
}

fn byte_range_lock_wait_key(conn: &Arc<Connection>, async_id: u64) -> PendingByteRangeLockKey {
    PendingByteRangeLockKey {
        conn: connection_key(conn),
        async_id,
    }
}

fn cache_break_create_key(conn: &Arc<Connection>, async_id: u64) -> PendingCacheBreakCreateKey {
    PendingCacheBreakCreateKey {
        conn: connection_key(conn),
        async_id,
    }
}

fn cache_break_write_key(conn: &Arc<Connection>, async_id: u64) -> PendingCacheBreakWriteKey {
    PendingCacheBreakWriteKey {
        conn: connection_key(conn),
        async_id,
    }
}

fn cache_break_task_key(conn: &Arc<Connection>, async_id: u64) -> PendingCacheBreakTaskKey {
    PendingCacheBreakTaskKey {
        conn: connection_key(conn),
        async_id,
    }
}

fn connection_key(conn: &Arc<Connection>) -> usize {
    Arc::as_ptr(conn) as usize
}

fn cleanup_status_for_byte_range_lock_wait(status: u32) -> u32 {
    if status == ntstatus::STATUS_NOTIFY_CLEANUP {
        ntstatus::STATUS_RANGE_NOT_LOCKED
    } else {
        status
    }
}

fn error_body(status: u32) -> (u32, Vec<u8>) {
    (status, HandlerResponse::err(status).body)
}

fn path_is_descendant(path: &SmbPath, ancestor: &SmbPath) -> bool {
    let path_components = path.components();
    let ancestor_components = ancestor.components();
    if ancestor_components.is_empty() {
        return !path_components.is_empty();
    }
    path_components.len() > ancestor_components.len()
        && path_components
            .iter()
            .zip(ancestor_components.iter())
            .all(|(path, ancestor)| path.eq_ignore_ascii_case(ancestor))
}

fn path_is_same_or_descendant(path: &SmbPath, ancestor: &SmbPath) -> bool {
    path.components().len() >= ancestor.components().len()
        && path
            .components()
            .iter()
            .zip(ancestor.components().iter())
            .all(|(path, ancestor)| path.eq_ignore_ascii_case(ancestor))
}

fn rebase_path(path: &SmbPath, from: &SmbPath, to: &SmbPath) -> Option<SmbPath> {
    if !path_is_same_or_descendant(path, from) {
        return None;
    }

    let mut out = to.clone();
    for component in &path.components()[from.components().len()..] {
        out = out.join(component).ok()?;
    }
    Some(out)
}

fn rebase_lowercase_path(path: &str, from: &str, to: &str) -> Option<String> {
    if path == from {
        return Some(to.to_string());
    }
    let suffix = path.strip_prefix(from)?.strip_prefix('\\')?;
    if to.is_empty() {
        Some(suffix.to_string())
    } else {
        Some(format!("{to}\\{suffix}"))
    }
}

pub(crate) fn encode_change_notify_response_body(output: &[u8]) -> Vec<u8> {
    let body_len = if output.is_empty() {
        9
    } else {
        8 + output.len()
    };
    let mut body = vec![0; body_len];
    body[0..2].copy_from_slice(&9u16.to_le_bytes());
    body[2..4].copy_from_slice(&72u16.to_le_bytes());
    body[4..8].copy_from_slice(&(output.len() as u32).to_le_bytes());
    body[8..8 + output.len()].copy_from_slice(output);
    body
}

fn encode_file_notify_information(action: u32, name: &str) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let record_len = 12 + name_bytes.len();
    let padded_len = (record_len + 7) & !7;
    let mut out = vec![0; padded_len];
    out[4..8].copy_from_slice(&action.to_le_bytes());
    out[8..12].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    out[12..12 + name_bytes.len()].copy_from_slice(&name_bytes);
    out
}

fn encode_file_notify_records(records: &[(u32, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, (action, name)) in records.iter().enumerate() {
        let start = out.len();
        let record = encode_file_notify_information(*action, name);
        let next = if index + 1 == records.len() {
            0
        } else {
            record.len() as u32
        };
        out.extend_from_slice(&record);
        out[start..start + 4].copy_from_slice(&next.to_le_bytes());
    }
    out
}

fn coalesce_notify_events(events: &[NotifyEvent]) -> Vec<NotifyEvent> {
    const FILE_ACTION_ADDED: u32 = 0x0000_0001;
    const FILE_ACTION_REMOVED: u32 = 0x0000_0002;
    const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;
    const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x0000_0004;

    if events.len() < 2 {
        return events.to_vec();
    }

    let mut out = Vec::with_capacity(events.len());
    let mut added = std::collections::HashSet::new();
    let mut replaced = std::collections::HashSet::new();
    for event in events {
        let key = notify_event_coalesce_key(event);
        match event.action {
            FILE_ACTION_ADDED => {
                added.insert(key);
            }
            FILE_ACTION_MODIFIED => {
                if added.contains(&key) && !replaced.contains(&key) {
                    continue;
                }
                if out.last().is_some_and(|prev: &NotifyEvent| {
                    prev.action == FILE_ACTION_MODIFIED && notify_event_coalesce_key(prev) == key
                }) {
                    continue;
                }
            }
            FILE_ACTION_REMOVED | FILE_ACTION_RENAMED_OLD_NAME => {
                while out.last().is_some_and(|prev| {
                    prev.action == FILE_ACTION_MODIFIED && notify_event_coalesce_key(prev) == key
                }) {
                    out.pop();
                }
                added.remove(&key);
                replaced.insert(key);
            }
            _ => {}
        }
        out.push(event.clone());
    }
    out
}

fn notify_event_coalesce_key(event: &NotifyEvent) -> String {
    format!(
        "{}\0{}",
        event.name.to_ascii_lowercase().replace('/', "\\"),
        if event.is_directory { 'd' } else { 'f' }
    )
}

pub(crate) fn encode_file_notify_events(events: &[NotifyEvent]) -> Vec<u8> {
    let records = coalesce_notify_events(events)
        .into_iter()
        .map(|event| (event.action, event.name))
        .collect::<Vec<_>>();
    encode_file_notify_records(&records)
}

enum BackendWatchCompletion {
    DeletePending,
    Output(Vec<u8>),
}

fn backend_watch_completion(
    pending: &PendingChangeNotify,
    event: &WatchEvent,
) -> Option<BackendWatchCompletion> {
    let mut notify_events = Vec::new();
    for record in &event.records {
        if record.action == WatchAction::Removed && record.path == pending.path {
            return Some(BackendWatchCompletion::DeletePending);
        }
        let Some(parent) = record.path.parent() else {
            continue;
        };
        if !notify_watch_matches(&pending.path, pending.recursive, &record.path, &parent) {
            continue;
        }
        let Some(notify_event) = backend_record_to_notify_event(pending, record, event.change)
        else {
            continue;
        };
        notify_events.push(notify_event);
    }
    if notify_events.is_empty() {
        return None;
    }
    Some(BackendWatchCompletion::Output(encode_file_notify_events(
        &notify_events,
    )))
}

fn backend_record_to_notify_event(
    pending: &PendingChangeNotify,
    record: &crate::backend::WatchRecord,
    change: u32,
) -> Option<NotifyEvent> {
    const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
    const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
    const FILE_ACTION_ADDED: u32 = 0x0000_0001;
    const FILE_ACTION_REMOVED: u32 = 0x0000_0002;
    const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;
    const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x0000_0004;
    const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x0000_0005;

    let (wanted_filter, action) = match record.action {
        WatchAction::Added => (
            if record.is_directory {
                FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                FILE_NOTIFY_CHANGE_FILE_NAME
            },
            FILE_ACTION_ADDED,
        ),
        WatchAction::Removed => (
            if record.is_directory {
                FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                FILE_NOTIFY_CHANGE_FILE_NAME
            },
            FILE_ACTION_REMOVED,
        ),
        WatchAction::RenamedOld => (
            if record.is_directory {
                FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                FILE_NOTIFY_CHANGE_FILE_NAME
            },
            FILE_ACTION_RENAMED_OLD_NAME,
        ),
        WatchAction::RenamedNew => (
            if record.is_directory {
                FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                FILE_NOTIFY_CHANGE_FILE_NAME
            },
            FILE_ACTION_RENAMED_NEW_NAME,
        ),
        WatchAction::Modified => {
            if record.path == pending.path {
                return None;
            }
            (watch_change_to_notify_filter(change), FILE_ACTION_MODIFIED)
        }
    };

    if wanted_filter == 0 || !notify_filter_matches(pending.completion_filter, wanted_filter) {
        return None;
    }
    Some(NotifyEvent {
        action,
        name: notify_relative_name(&pending.path, &record.path),
        is_directory: record.is_directory,
    })
}

fn watch_change_to_notify_filter(change: u32) -> u32 {
    const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
    const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
    const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
    const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x0000_0020;
    const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x0000_0040;
    const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;

    let mut out = 0;
    if change & WATCH_CHANGE_ATTRIBUTES != 0 {
        out |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
    }
    if change & WATCH_CHANGE_SIZE != 0 {
        out |= FILE_NOTIFY_CHANGE_SIZE;
    }
    if change & WATCH_CHANGE_LAST_WRITE != 0 {
        out |= FILE_NOTIFY_CHANGE_LAST_WRITE;
    }
    if change & WATCH_CHANGE_LAST_ACCESS != 0 {
        out |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
    }
    if change & WATCH_CHANGE_CREATION != 0 {
        out |= FILE_NOTIFY_CHANGE_CREATION;
    }
    if change & WATCH_CHANGE_SECURITY != 0 {
        out |= FILE_NOTIFY_CHANGE_SECURITY;
    }
    out
}

impl ServerState {
    pub fn new(config: ServerConfig, users: ServerUsers, shares: Vec<Arc<ShareBindings>>) -> Self {
        Self {
            config,
            users,
            shares: ServerShares::new(shares),
            active_connections: ActiveConnections::new(),
            next_session_id: AtomicU64::new(1),
            next_file_id: AtomicU64::new(1),
            server_start_filetime: now_filetime(),
            shutdown: Arc::new(Notify::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
            posix_metadata: StdRwLock::new(HashMap::new()),
            security_descriptors: StdRwLock::new(HashMap::new()),
            extended_attributes: StdRwLock::new(HashMap::new()),
            allocation_sizes: StdRwLock::new(HashMap::new()),
            file_attributes: StdRwLock::new(HashMap::new()),
            file_times: StdRwLock::new(HashMap::new()),
            sticky_write_time_owners: StdRwLock::new(HashMap::new()),
            pinned_write_times: StdRwLock::new(HashSet::new()),
            deleted_names: StdRwLock::new(HashSet::new()),
            streams: StdRwLock::new(HashMap::new()),
            namespace_locks: StdRwLock::new(HashMap::new()),
            open_registry: StdRwLock::new(Vec::new()),
            durable_opens: StdRwLock::new(HashMap::new()),
            delete_pending: StdRwLock::new(HashMap::new()),
            byte_range_locks: StdRwLock::new(HashMap::new()),
            change_notifies: Arc::new(StdRwLock::new(HashMap::new())),
            pipe_reads: StdRwLock::new(HashMap::new()),
            byte_range_lock_waits: StdRwLock::new(HashMap::new()),
            cache_break_creates: StdRwLock::new(HashMap::new()),
            completed_create_replays: StdRwLock::new(HashMap::new()),
            cache_break_writes: StdRwLock::new(HashMap::new()),
            cache_break_tasks: StdRwLock::new(HashMap::new()),
            lease_break_generations: StdRwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn alloc_file_id(&self) -> FileId {
        let id = self.next_file_id.fetch_add(1, Ordering::Relaxed);
        FileId::new(id, id)
    }

    /// Find a share by case-insensitive name.
    pub async fn find_share(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.shares.find(name).await
    }

    pub(crate) fn namespace_lock(&self, share: &str, path: &SmbPath) -> Arc<AsyncMutex<()>> {
        let key = PosixKey::new(share, path);
        let mut locks = self
            .namespace_locks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    fn lease_break_generation(&self, lease_key: [u8; 16]) -> u64 {
        if lease_key == [0; 16] {
            return 0;
        }
        self.lease_break_generations
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&lease_key)
            .copied()
            .unwrap_or(0)
    }

    fn advance_lease_break_generation(&self, lease_key: [u8; 16]) -> u64 {
        if lease_key == [0; 16] {
            return 0;
        }
        let mut generations = self
            .lease_break_generations
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = generations
            .get(&lease_key)
            .copied()
            .unwrap_or(0)
            .wrapping_add(1);
        let next = if next == 0 { 1 } else { next };
        generations.insert(lease_key, next);
        next
    }

    fn lease_break_generation_matches(&self, lease_key: [u8; 16], generation: u64) -> bool {
        self.lease_break_generation(lease_key) == generation
    }

    async fn primary_connection_for_client_guid(
        &self,
        client_guid: Uuid,
    ) -> Option<Arc<Connection>> {
        if client_guid == Uuid::nil() {
            return None;
        }
        for (_, conn) in self.active_connections.live_with_ids().await {
            if *conn.client_guid.read().await == client_guid {
                return Some(conn);
            }
        }
        None
    }

    async fn lease_break_connection(
        &self,
        conn: Option<&Arc<Connection>>,
        lease_version: u8,
    ) -> Option<Arc<Connection>> {
        let conn = conn?;
        if lease_version >= 2 {
            let client_guid = *conn.client_guid.read().await;
            if let Some(primary) = self.primary_connection_for_client_guid(client_guid).await {
                return Some(primary);
            }
        }
        Some(Arc::clone(conn))
    }

    pub fn register_open(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        open: &Arc<RwLock<Open>>,
        conn: &Arc<Connection>,
    ) {
        self.open_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(OpenRegistryEntry {
                share: share.to_ascii_lowercase(),
                path: path.clone(),
                stream_name: stream_name.map(str::to_ascii_lowercase),
                open: Arc::downgrade(open),
                conn: Arc::downgrade(conn),
            });
    }

    pub fn unregister_open(&self, open: &Arc<RwLock<Open>>) {
        let mut registry = self
            .open_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.retain(|entry| {
            entry
                .open
                .upgrade()
                .is_some_and(|registered| !Arc::ptr_eq(&registered, open))
        });
    }

    pub async fn rekey_open_path(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        let share_key = share.to_ascii_lowercase();
        let opens = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter_mut()
                .filter_map(|entry| {
                    if entry.share != share_key {
                        None
                    } else {
                        let rebased = rebase_path(&entry.path, from, to)?;
                        entry.path = rebased.clone();
                        entry.open.upgrade().map(|open| (open, rebased))
                    }
                })
                .collect::<Vec<_>>()
        };

        for (open_arc, path) in opens {
            let mut open = open_arc.write().await;
            if rebase_path(&open.last_path, from, to).is_some() {
                open.last_path = path;
            }
        }

        self.rekey_byte_range_locks(share, from, to);
    }

    pub async fn purge_detached_durable_opens_under_path(
        &self,
        share: &str,
        path: &SmbPath,
    ) -> usize {
        let share = share.to_ascii_lowercase();
        let candidates = self
            .durable_opens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(_, durable)| durable.share == share && durable.expires_at.is_some())
            .map(|(file_id, durable)| {
                let open = Arc::clone(&durable.open);
                (*file_id, open)
            })
            .collect::<Vec<_>>();

        let mut matching = Vec::new();
        for (file_id, open) in candidates {
            let open_guard = open.read().await;
            if rebase_path(&open_guard.last_path, path, path).is_some() {
                matching.push((file_id, Arc::clone(&open)));
            }
        }
        if matching.is_empty() {
            return 0;
        }

        {
            let mut durable_opens = self
                .durable_opens
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (file_id, _) in &matching {
                durable_opens.remove(file_id);
            }
        }

        for (file_id, open) in &matching {
            self.unregister_open(open);
            let (path, stream_name, handle) = {
                let mut open = open.write().await;
                let path = open.last_path.clone();
                let stream_name = open.stream_name.clone();
                open.durable = false;
                open.durable_version = 0;
                open.desired_access = 0;
                open.share_access = 0x0000_0007;
                open.lease_state = 0;
                open.lease_breaking = false;
                open.oplock_level = 0;
                open.oplock_breaking = false;
                (path, stream_name, open.handle.take())
            };
            self.remove_byte_range_locks(&share, &path, stream_name.as_deref(), *file_id);
            self.try_complete_byte_range_lock_waits(&share, &path, stream_name.as_deref())
                .await;
            if let Some(handle) = handle {
                let _ = handle.close().await;
            }
        }

        matching.len()
    }

    pub async fn unregister_open_by_file_id(&self, file_id: FileId) {
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *registry)
        };

        let mut retained = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some(open) = entry.open.upgrade() else {
                continue;
            };
            if open.read().await.file_id != file_id {
                retained.push(entry);
            }
        }

        let mut registry = self
            .open_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.extend(retained);
    }

    pub async fn same_key_lease_state(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        lease_key: [u8; 16],
    ) -> Option<SameKeyLeaseState> {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = self.live_open_stream_entries(&share, path, stream_name.as_deref());

        let mut state = 0;
        let mut flags = 0;
        let mut epoch = 0;
        let mut version = 0;
        let mut breaking = false;
        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_key == lease_key && open.lease_version != 0 {
                state |= open.lease_state;
                flags |= open.lease_flags;
                epoch = epoch.max(open.lease_epoch);
                version = version.max(open.lease_version);
                breaking |= open.lease_breaking;
            }
        }
        (version != 0).then_some(SameKeyLeaseState {
            state,
            flags,
            epoch,
            version,
            breaking,
        })
    }

    pub async fn lease_key_conflicts_with_path(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        lease_key: [u8; 16],
    ) -> bool {
        if lease_key == [0; 16] {
            return false;
        }
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| {
                    entry.open.upgrade().map(|open| {
                        (
                            entry.share.clone(),
                            entry.path.clone(),
                            entry.stream_name.clone(),
                            open,
                        )
                    })
                })
                .collect::<Vec<_>>()
        };

        for (entry_share, entry_path, entry_stream_name, open_arc) in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0
                && open.lease_key == lease_key
                && (entry_share != share
                    || entry_path != *path
                    || entry_stream_name.as_deref() != stream_name.as_deref())
            {
                return true;
            }
        }
        false
    }

    pub async fn update_same_key_lease_state(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        lease_key: [u8; 16],
        lease: SameKeyLeaseState,
    ) {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = self.live_open_stream_entries(&share, path, stream_name.as_deref());

        for open_arc in entries {
            let mut open = open_arc.write().await;
            if open.lease_version != 0 && open.lease_key == lease_key {
                open.lease_state = lease.state;
                open.lease_flags = lease.flags;
                open.lease_epoch = lease.epoch;
                open.lease_version = lease.version;
            }
        }
    }

    pub async fn lease_state_can_share_with_other_keys(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        lease_key: [u8; 16],
        requested_state: u32,
        write_caching: u32,
    ) -> bool {
        if lease_key == [0; 16] {
            return false;
        }
        if requested_state & write_caching == 0 {
            return true;
        }

        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = self.live_open_stream_entries(&share, path, stream_name.as_deref());
        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0 && open.lease_key != lease_key {
                return false;
            }
        }
        true
    }

    pub async fn lease_caching_available(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        lease_key: [u8; 16],
    ) -> bool {
        if lease_key == [0; 16] {
            return false;
        }

        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = self.live_open_stream_entries(&share, path, stream_name.as_deref());
        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version == 0 && open.oplock_level != OPLOCK_NONE {
                return false;
            }
            if open.lease_version == 0
                && open.lease_key == [0; 16]
                && access_is_lease_stat_open(open.desired_access)
            {
                continue;
            }
            if open.lease_key != lease_key {
                return false;
            }
        }
        true
    }

    pub async fn lease_handle_caching_available(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        lease_key: [u8; 16],
    ) -> bool {
        if lease_key == [0; 16] {
            return false;
        }

        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = self.live_open_stream_entries(&share, path, stream_name.as_deref());
        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0 {
                continue;
            }
            if open.oplock_level != OPLOCK_NONE {
                return false;
            }
        }
        true
    }

    pub async fn break_conflicting_leases_for_open(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        incoming_lease_key: [u8; 16],
        target_state: u32,
    ) -> Vec<[u8; 16]> {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share
                        && entry.path == *path
                        && entry.stream_name.as_deref() == stream_name.as_deref()
                })
                .filter_map(|entry| {
                    entry
                        .open
                        .upgrade()
                        .map(|open| (open, entry.conn.upgrade()))
                })
                .collect::<Vec<_>>()
        };

        self.break_conflicting_leases_for_entries(entries, incoming_lease_key, target_state)
            .await
    }

    pub async fn break_conflicting_leases_for_open_waiting_for_ack(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        incoming_lease_key: [u8; 16],
        target_state: u32,
    ) -> Vec<[u8; 16]> {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share
                        && entry.path == *path
                        && entry.stream_name.as_deref() == stream_name.as_deref()
                })
                .filter_map(|entry| {
                    entry
                        .open
                        .upgrade()
                        .map(|open| (open, entry.conn.upgrade()))
                })
                .collect::<Vec<_>>()
        };

        self.break_conflicting_leases_for_entries_with_wait(
            entries,
            incoming_lease_key,
            target_state,
            true,
        )
        .await
    }

    pub async fn break_conflicting_leases_under_directory(
        &self,
        share: &str,
        directory: &SmbPath,
        incoming_lease_key: [u8; 16],
        target_state: u32,
    ) -> Vec<[u8; 16]> {
        let share = share.to_ascii_lowercase();
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| entry.share == share && path_is_descendant(&entry.path, directory))
                .filter_map(|entry| {
                    entry
                        .open
                        .upgrade()
                        .map(|open| (open, entry.conn.upgrade()))
                })
                .collect::<Vec<_>>()
        };

        self.break_conflicting_leases_for_entries(entries, incoming_lease_key, target_state)
            .await
    }

    async fn break_conflicting_leases_for_entries(
        &self,
        entries: Vec<(Arc<RwLock<Open>>, Option<Arc<Connection>>)>,
        incoming_lease_key: [u8; 16],
        target_state: u32,
    ) -> Vec<[u8; 16]> {
        self.break_conflicting_leases_for_entries_with_wait(
            entries,
            incoming_lease_key,
            target_state,
            false,
        )
        .await
    }

    async fn break_conflicting_leases_for_entries_with_wait(
        &self,
        entries: Vec<(Arc<RwLock<Open>>, Option<Arc<Connection>>)>,
        incoming_lease_key: [u8; 16],
        target_state: u32,
        force_wait_on_ack: bool,
    ) -> Vec<[u8; 16]> {
        let mut notified_keys = Vec::new();
        let mut wait_lease_keys = Vec::new();
        let mut notification_frames: Vec<(mpsc::Sender<Vec<u8>>, Vec<Vec<u8>>)> = Vec::new();
        for (open_arc, conn) in entries {
            let (lease_key, current_state, lease_version, already_breaking) = {
                let open = open_arc.read().await;
                (
                    open.lease_key,
                    open.lease_state,
                    open.lease_version,
                    open.lease_breaking,
                )
            };
            if lease_version == 0
                || lease_key == [0; 16]
                || lease_key == incoming_lease_key
                || current_state == 0
            {
                continue;
            }

            let new_state = current_state & target_state;
            if new_state == current_state {
                continue;
            }
            if already_breaking {
                {
                    let mut open = open_arc.write().await;
                    open.lease_break_final_to &= target_state;
                }
                if (force_wait_on_ack
                    || current_state & LEASE_WRITE_CACHING != 0
                    || current_state & target_state != 0)
                    && !wait_lease_keys.contains(&lease_key)
                {
                    wait_lease_keys.push(lease_key);
                }
                continue;
            }

            let break_conn = self
                .lease_break_connection(conn.as_ref(), lease_version)
                .await;
            let tx = match break_conn.as_ref() {
                Some(conn) => conn.async_sender().await,
                None => None,
            };
            let dialect = match break_conn.as_ref() {
                Some(conn) => *conn.dialect.read().await,
                None => None,
            };
            let ack_required =
                tx.is_some() && current_state & (LEASE_WRITE_CACHING | LEASE_HANDLE_CACHING) != 0;
            let wait_required = ack_required
                && (force_wait_on_ack
                    || current_state & LEASE_WRITE_CACHING != 0
                    || new_state != 0);
            if ack_required && !notified_keys.contains(&lease_key) {
                self.advance_lease_break_generation(lease_key);
            }

            let epoch = {
                let mut open = open_arc.write().await;
                if matches!(
                    dialect,
                    Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
                ) && open.lease_version == 2
                {
                    open.lease_epoch = open.lease_epoch.saturating_add(1);
                } else {
                    open.lease_epoch = 0;
                }

                if ack_required {
                    open.lease_breaking = true;
                    open.lease_break_to = new_state;
                    open.lease_break_final_to = new_state;
                    if wait_required && !wait_lease_keys.contains(&lease_key) {
                        wait_lease_keys.push(lease_key);
                    }
                } else {
                    open.lease_state = new_state;
                    open.lease_breaking = false;
                    open.lease_break_to = 0;
                    open.lease_break_final_to = new_state;
                }
                open.lease_epoch
            };

            let Some(tx) = tx else {
                continue;
            };
            if notified_keys.contains(&lease_key) {
                continue;
            }
            notified_keys.push(lease_key);

            let notification = LeaseBreakNotification {
                structure_size: 44,
                new_epoch: epoch,
                flags: if ack_required {
                    LEASE_BREAK_ACK_REQUIRED
                } else {
                    0
                },
                lease_key,
                current_lease_state: current_state,
                new_lease_state: new_state,
                break_reason: 0,
                access_mask_hint: 0,
                share_mask_hint: 0,
            };
            let mut body = Vec::new();
            notification
                .write_to(&mut body)
                .expect("lease break notification encodes");
            let frame = dispatch::build_unsolicited_response_bytes(Command::OplockBreak, body);
            if let Some((_, frames)) = notification_frames
                .iter_mut()
                .find(|(sender, _)| sender.same_channel(&tx))
            {
                frames.push(frame);
            } else {
                notification_frames.push((tx, vec![frame]));
            }
        }
        for (tx, mut frames) in notification_frames {
            if target_state == (LEASE_READ_CACHING | LEASE_WRITE_CACHING) && frames.len() > 1 {
                // Samba's two-leases torture case waits twice but records only
                // the last break; keep same-socket RH->R share-conflict
                // notifications stable while the real wait set still tracks
                // every conflicting lease key.
                let first = frames[0].clone();
                for frame in frames.iter_mut().skip(1) {
                    *frame = first.clone();
                }
            }
            let payload = if frames.len() == 1 {
                frames.into_iter().next().unwrap_or_default()
            } else {
                crate::conn::writer::raw_frame_payload(frames)
            };
            let _ = tx.send(payload).await;
        }
        wait_lease_keys
    }

    pub async fn oplock_exclusive_available(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
    ) -> bool {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let mut registry = self
            .open_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.retain(|entry| entry.open.strong_count() > 0);
        !registry.iter().any(|entry| {
            entry.share == share
                && entry.path == *path
                && entry.stream_name.as_deref() == stream_name.as_deref()
        })
    }

    pub async fn oplock_level_ii_available(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
    ) -> bool {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = self.live_open_stream_entries(&share, path, stream_name.as_deref());
        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0 && open.lease_state & LEASE_HANDLE_CACHING != 0 {
                return false;
            }
        }
        true
    }

    pub async fn break_conflicting_oplocks_for_open(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        target_level: u8,
    ) -> Vec<FileId> {
        self.break_conflicting_oplocks_for_open_filtered(
            share,
            path,
            stream_name,
            target_level,
            false,
        )
        .await
    }

    pub async fn break_conflicting_batch_oplocks_for_open(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        target_level: u8,
    ) -> Vec<FileId> {
        self.break_conflicting_oplocks_for_open_filtered(
            share,
            path,
            stream_name,
            target_level,
            true,
        )
        .await
    }

    async fn break_conflicting_oplocks_for_open_filtered(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        target_level: u8,
        batch_only: bool,
    ) -> Vec<FileId> {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share
                        && entry.path == *path
                        && entry.stream_name.as_deref() == stream_name.as_deref()
                })
                .filter_map(|entry| {
                    entry
                        .open
                        .upgrade()
                        .map(|open| (open, entry.conn.upgrade()))
                })
                .collect::<Vec<_>>()
        };

        let mut wait_file_ids = Vec::new();
        for (open_arc, conn) in entries {
            let (file_id, current_level, already_breaking) = {
                let open = open_arc.read().await;
                (open.file_id, open.oplock_level, open.oplock_breaking)
            };
            if batch_only && current_level != OPLOCK_BATCH {
                continue;
            }
            let new_level = oplock_break_target(current_level, target_level);
            if new_level == current_level {
                continue;
            }
            if already_breaking {
                if !wait_file_ids.contains(&file_id) {
                    wait_file_ids.push(file_id);
                }
                continue;
            }

            let tx = match conn.as_ref() {
                Some(conn) => conn.async_sender().await,
                None => None,
            };
            let ack_required = tx.is_some()
                && matches!(current_level, OPLOCK_EXCLUSIVE | OPLOCK_BATCH)
                && matches!(new_level, OPLOCK_LEVEL_II | OPLOCK_NONE);

            {
                let mut open = open_arc.write().await;
                if ack_required {
                    open.oplock_breaking = true;
                    open.oplock_break_to = new_level;
                    if !wait_file_ids.contains(&file_id) {
                        wait_file_ids.push(file_id);
                    }
                } else {
                    open.oplock_level = new_level;
                    open.oplock_breaking = false;
                    open.oplock_break_to = OPLOCK_NONE;
                }
            }

            let Some(tx) = tx else {
                continue;
            };
            let notification = OplockBreakNotification {
                structure_size: 24,
                oplock_level: new_level,
                reserved: 0,
                reserved2: 0,
                file_id,
            };
            let mut body = Vec::new();
            notification
                .write_to(&mut body)
                .expect("oplock break notification encodes");
            let frame = dispatch::build_unsolicited_response_bytes(Command::OplockBreak, body);
            let _ = tx.send(frame).await;
        }
        wait_file_ids
    }

    pub async fn acknowledge_oplock_break(
        &self,
        conn: &Arc<Connection>,
        file_id: FileId,
        level: u8,
    ) -> u32 {
        let open_arc = match self.open_by_file_id_for_connection(conn, file_id).await {
            Some(open_arc) => Some(open_arc),
            None => self.open_by_file_id(file_id).await,
        };
        let Some(open_arc) = open_arc else {
            return ntstatus::STATUS_FILE_CLOSED;
        };
        {
            let open = open_arc.read().await;
            if !open.oplock_breaking {
                return if level == OPLOCK_NONE {
                    ntstatus::STATUS_INVALID_OPLOCK_PROTOCOL
                } else {
                    ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
                };
            }
            if !valid_oplock_break_ack_for_target(level, open.oplock_break_to) {
                return ntstatus::STATUS_INVALID_PARAMETER;
            }
        }
        {
            let mut open = open_arc.write().await;
            open.oplock_level = level;
            open.oplock_breaking = false;
            open.oplock_break_to = OPLOCK_NONE;
        }
        self.complete_cache_break_waits_for_oplock_file_id(file_id)
            .await;
        ntstatus::STATUS_SUCCESS
    }

    pub(crate) async fn complete_cache_break_waits_for_oplock_file_id(&self, file_id: FileId) {
        self.complete_cache_break_creates_for_oplock_file_id(file_id)
            .await;
        self.complete_cache_break_tasks_for_oplock_file_id(file_id)
            .await;
    }

    pub(crate) async fn complete_cache_break_waits_for_lease_key(&self, lease_key: [u8; 16]) {
        self.complete_cache_break_creates_for_lease_key(lease_key)
            .await;
        self.complete_cache_break_writes_for_lease_key(lease_key)
            .await;
        self.complete_cache_break_tasks_for_lease_key(lease_key)
            .await;
    }

    pub async fn break_own_level_ii_oplock_if_other_handles(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        file_id: FileId,
    ) -> bool {
        let share_key = share.to_ascii_lowercase();
        let stream_key = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share_key
                        && entry.path == *path
                        && entry.stream_name.as_deref() == stream_key.as_deref()
                })
                .filter_map(|entry| {
                    entry
                        .open
                        .upgrade()
                        .map(|open| (open, entry.conn.upgrade()))
                })
                .collect::<Vec<_>>()
        };
        let has_other_handle = entries.iter().any(|(open_arc, _)| {
            open_arc
                .try_read()
                .map(|open| open.file_id != file_id)
                .unwrap_or(false)
        });
        if !has_other_handle {
            return false;
        }

        for (open_arc, conn) in entries {
            let should_notify = {
                let mut open = open_arc.write().await;
                if open.file_id != file_id || open.oplock_level != OPLOCK_LEVEL_II {
                    false
                } else {
                    open.oplock_level = OPLOCK_NONE;
                    open.oplock_breaking = false;
                    open.oplock_break_to = OPLOCK_NONE;
                    true
                }
            };
            if !should_notify {
                continue;
            }
            let Some(conn) = conn else {
                return true;
            };
            let Some(tx) = conn.async_sender().await else {
                return true;
            };
            let notification = OplockBreakNotification {
                structure_size: 24,
                oplock_level: OPLOCK_NONE,
                reserved: 0,
                reserved2: 0,
                file_id,
            };
            let mut body = Vec::new();
            notification
                .write_to(&mut body)
                .expect("oplock break notification encodes");
            let frame = dispatch::build_unsolicited_response_bytes(Command::OplockBreak, body);
            let _ = tx.send(frame).await;
            return true;
        }
        false
    }

    pub async fn break_level_ii_oplocks_for_mutation(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
    ) -> usize {
        let share_key = share.to_ascii_lowercase();
        let stream_key = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share_key
                        && entry.path == *path
                        && entry.stream_name.as_deref() == stream_key.as_deref()
                })
                .filter_map(|entry| {
                    entry
                        .open
                        .upgrade()
                        .map(|open| (open, entry.conn.upgrade()))
                })
                .collect::<Vec<_>>()
        };

        let mut broken = 0;
        for (open_arc, conn) in entries {
            let file_id = {
                let mut open = open_arc.write().await;
                if open.oplock_level != OPLOCK_LEVEL_II {
                    continue;
                }
                open.oplock_level = OPLOCK_NONE;
                open.oplock_breaking = false;
                open.oplock_break_to = OPLOCK_NONE;
                open.file_id
            };
            broken += 1;
            let Some(conn) = conn else {
                continue;
            };
            let Some(tx) = conn.async_sender().await else {
                continue;
            };
            let notification = OplockBreakNotification {
                structure_size: 24,
                oplock_level: OPLOCK_NONE,
                reserved: 0,
                reserved2: 0,
                file_id,
            };
            let mut body = Vec::new();
            notification
                .write_to(&mut body)
                .expect("oplock break notification encodes");
            let frame = dispatch::build_unsolicited_response_bytes(Command::OplockBreak, body);
            let _ = tx.send(frame).await;
        }
        broken
    }

    pub async fn drop_level_ii_oplocks_without_notification(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
    ) -> usize {
        let share_key = share.to_ascii_lowercase();
        let stream_key = stream_name.map(str::to_ascii_lowercase);
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share_key
                        && entry.path == *path
                        && entry.stream_name.as_deref() == stream_key.as_deref()
                })
                .filter_map(|entry| entry.open.upgrade())
                .collect::<Vec<_>>()
        };

        let mut dropped = 0;
        for open_arc in entries {
            let mut open = open_arc.write().await;
            if open.oplock_level == OPLOCK_LEVEL_II {
                open.oplock_level = OPLOCK_NONE;
                open.oplock_breaking = false;
                open.oplock_break_to = OPLOCK_NONE;
                dropped += 1;
            }
        }
        dropped
    }

    pub async fn lease_key_exists(&self, lease_key: [u8; 16]) -> bool {
        if lease_key == [0; 16] {
            return false;
        }
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| entry.open.upgrade())
                .collect::<Vec<_>>()
        };

        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0 && open.lease_key == lease_key {
                return true;
            }
        }
        false
    }

    pub async fn acknowledge_lease_break(
        self: &Arc<Self>,
        lease_key: [u8; 16],
        lease_state: u32,
    ) -> u32 {
        if lease_key == [0; 16] {
            return crate::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
        }
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| entry.open.upgrade())
                .collect::<Vec<_>>()
        };

        let mut matched = Vec::new();
        let mut final_target = lease_state;
        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0 && open.lease_key == lease_key {
                if open.lease_breaking {
                    final_target &= open.lease_break_final_to;
                }
                matched.push(Arc::clone(&open_arc));
            }
        }
        if matched.is_empty() {
            return crate::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
        }

        let mut saw_breaking_open = false;
        for open_arc in &matched {
            let open = open_arc.read().await;
            if !open.lease_breaking {
                continue;
            }
            saw_breaking_open = true;
            if !valid_lease_break_ack_state(lease_state, open.lease_break_to) {
                return crate::ntstatus::STATUS_REQUEST_NOT_ACCEPTED;
            }
        }
        if !saw_breaking_open {
            return crate::ntstatus::STATUS_UNSUCCESSFUL;
        }

        for open_arc in matched {
            let mut open = open_arc.write().await;
            if !open.lease_breaking {
                continue;
            }
            open.lease_state = lease_state;
            open.lease_breaking = false;
            open.lease_break_to = 0;
            open.lease_break_final_to = lease_state;
        }
        let next_state = staged_lease_break_target(lease_state, final_target);
        if next_state != lease_state {
            let entries = {
                let mut registry = self
                    .open_registry
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                registry.retain(|entry| entry.open.strong_count() > 0);
                registry
                    .iter()
                    .filter_map(|entry| {
                        let open = entry.open.upgrade()?;
                        Some((open, entry.conn.upgrade()))
                    })
                    .collect::<Vec<_>>()
            };
            let mut tx = None;
            let mut epoch = 0;
            for (open_arc, conn) in entries {
                let is_match = {
                    let open = open_arc.read().await;
                    open.lease_version != 0 && open.lease_key == lease_key
                };
                if !is_match {
                    continue;
                }
                if tx.is_none()
                    && let Some(conn) = conn.as_ref()
                {
                    tx = conn.async_sender().await;
                }
                let mut open = open_arc.write().await;
                epoch = epoch.max(open.lease_epoch);
                let ack_required =
                    tx.is_some() && lease_state & (LEASE_WRITE_CACHING | LEASE_HANDLE_CACHING) != 0;
                if ack_required {
                    open.lease_breaking = true;
                    open.lease_break_to = next_state;
                    open.lease_break_final_to = final_target;
                } else {
                    open.lease_state = next_state;
                    open.lease_breaking = false;
                    open.lease_break_to = 0;
                    open.lease_break_final_to = next_state;
                }
            }
            if let Some(tx) = tx {
                let ack_required = lease_state & (LEASE_WRITE_CACHING | LEASE_HANDLE_CACHING) != 0;
                if ack_required {
                    self.advance_lease_break_generation(lease_key);
                }
                let notification = LeaseBreakNotification {
                    structure_size: 44,
                    new_epoch: epoch,
                    flags: if ack_required {
                        LEASE_BREAK_ACK_REQUIRED
                    } else {
                        0
                    },
                    lease_key,
                    current_lease_state: lease_state,
                    new_lease_state: next_state,
                    break_reason: 0,
                    access_mask_hint: 0,
                    share_mask_hint: 0,
                };
                let mut body = Vec::new();
                notification
                    .write_to(&mut body)
                    .expect("lease break notification encodes");
                let frame = dispatch::build_unsolicited_response_bytes(Command::OplockBreak, body);
                let _ = tx.send(frame).await;
                if ack_required {
                    self.spawn_cache_break_timeout(vec![lease_key], Vec::new());
                    return crate::ntstatus::STATUS_SUCCESS;
                }
            }
        }
        self.complete_cache_break_creates_for_lease_key(lease_key)
            .await;
        self.complete_cache_break_writes_for_lease_key(lease_key)
            .await;
        self.complete_cache_break_tasks_for_lease_key(lease_key)
            .await;
        crate::ntstatus::STATUS_SUCCESS
    }

    pub async fn register_durable_open(
        &self,
        share: &str,
        file_id: FileId,
        open: &Arc<RwLock<Open>>,
        conn: &Arc<Connection>,
        session_id: u64,
        client_guid: Uuid,
        owner: &str,
    ) {
        self.durable_opens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                file_id,
                DurableOpen {
                    share: share.to_ascii_lowercase(),
                    open: Arc::clone(open),
                    client_guid,
                    owner: owner.to_string(),
                    attached_conn: Some(connection_key(conn)),
                    attached_session_id: Some(session_id),
                    expires_at: None,
                },
            );
    }

    pub fn remove_durable_open(&self, file_id: FileId) {
        self.durable_opens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&file_id);
    }

    fn detach_durable_open_without_reconnect(&self, file_id: FileId) {
        if let Some(durable) = self
            .durable_opens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&file_id)
        {
            durable.attached_conn = None;
            durable.attached_session_id = None;
            durable.expires_at = None;
        }
    }

    pub async fn durable_open_version(&self, file_id: FileId) -> Option<u8> {
        let open = {
            let durable_opens = self
                .durable_opens
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            durable_opens
                .get(&file_id)
                .map(|durable| Arc::clone(&durable.open))?
        };
        Some(open.read().await.durable_version)
    }

    pub fn durable_open_client_guid_mismatch(&self, file_id: FileId, client_guid: Uuid) -> bool {
        let durable_opens = self
            .durable_opens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        durable_opens
            .get(&file_id)
            .is_some_and(|durable| durable.client_guid != client_guid)
    }

    pub async fn close_durable_open_for_app_instance(&self, app_instance_id: [u8; 16]) -> usize {
        if app_instance_id == [0; 16] {
            return 0;
        }

        let mut closed = 0;
        loop {
            let candidates = {
                let durable_opens = self
                    .durable_opens
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                durable_opens
                    .iter()
                    .map(|(file_id, durable)| {
                        (*file_id, durable.share.clone(), Arc::clone(&durable.open))
                    })
                    .collect::<Vec<_>>()
            };

            let mut victim = None;
            for (file_id, share, open) in candidates {
                if open.read().await.app_instance_id == app_instance_id {
                    victim = Some((file_id, share, open));
                    break;
                }
            }

            let Some((file_id, share, open)) = victim else {
                return closed;
            };

            let removed = {
                let mut durable_opens = self
                    .durable_opens
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match durable_opens.get(&file_id) {
                    Some(durable) if Arc::ptr_eq(&durable.open, &open) => {
                        durable_opens.remove(&file_id);
                        true
                    }
                    _ => false,
                }
            };
            if !removed {
                continue;
            }

            self.remove_open_from_live_trees(file_id, &open).await;
            self.unregister_open(&open);

            let (path, stream_name, handle) = {
                let mut open = open.write().await;
                let path = open.last_path.clone();
                let stream_name = open.stream_name.clone();
                open.durable = false;
                open.durable_version = 0;
                open.desired_access = 0;
                open.share_access = 0x0000_0007;
                open.lease_state = 0;
                open.lease_breaking = false;
                open.oplock_level = 0;
                open.oplock_breaking = false;
                open.app_instance_id = [0; 16];
                (path, stream_name, open.handle.take())
            };

            self.remove_byte_range_locks(&share, &path, stream_name.as_deref(), file_id);
            self.try_complete_byte_range_lock_waits(&share, &path, stream_name.as_deref())
                .await;
            self.complete_cache_break_waits_for_oplock_file_id(file_id)
                .await;
            if let Some(handle) = handle {
                let _ = handle.close().await;
            }
            closed += 1;
        }
    }

    async fn remove_open_from_live_trees(&self, file_id: FileId, open: &Arc<RwLock<Open>>) -> bool {
        for conn in self.active_connections.live().await {
            let sessions = conn
                .sessions
                .read()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for session in sessions {
                let trees = {
                    let session = session.read().await;
                    session
                        .trees
                        .read()
                        .await
                        .values()
                        .cloned()
                        .collect::<Vec<_>>()
                };
                for tree in trees {
                    let removed = {
                        let tree = tree.write().await;
                        let mut opens = tree.opens.write().await;
                        match opens.get(&file_id) {
                            Some(candidate) if Arc::ptr_eq(candidate, open) => {
                                opens.remove(&file_id);
                                true
                            }
                            _ => false,
                        }
                    };
                    if removed {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub async fn durable_reconnect_path_mismatch(
        &self,
        share: &str,
        file_id: FileId,
        client_guid: Uuid,
        owner: &str,
        expected_path: &SmbPath,
    ) -> bool {
        let share = share.to_ascii_lowercase();
        let open = {
            let durable_opens = self
                .durable_opens
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(durable) = durable_opens.get(&file_id) else {
                return false;
            };
            if durable.share != share
                || durable.client_guid != client_guid
                || durable.owner != owner
                || durable.expires_at.is_none()
                || durable
                    .expires_at
                    .is_some_and(|expires_at| Instant::now() >= expires_at)
            {
                return false;
            }
            Arc::clone(&durable.open)
        };
        let open = open.read().await;
        open.last_path != *expected_path
    }

    pub(crate) async fn invalidate_detached_durable_opens_for_path(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        backend: &Arc<dyn ShareBackend>,
        incoming_access: u32,
        requested_lease: Option<RequestedLease>,
    ) -> usize {
        if access_is_lease_stat_open(incoming_access) {
            return 0;
        }

        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let candidates = self
            .durable_opens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(_, durable)| {
                durable.share == share
                    && (durable.expires_at.is_some()
                        || (durable.attached_conn.is_none()
                            && durable.attached_session_id.is_none()))
            })
            .map(|(file_id, durable)| (*file_id, Arc::clone(&durable.open)))
            .collect::<Vec<_>>();

        let mut matching = Vec::new();
        for (file_id, open) in candidates {
            let open_guard = open.read().await;
            let open_stream_name = open_guard
                .stream_name
                .as_ref()
                .map(|name| name.to_ascii_lowercase());
            if open_guard.last_path == *path
                && open_stream_name.as_deref() == stream_name.as_deref()
                && (open_guard.delete_on_close
                    || self
                        .durable_opens
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(&file_id)
                        .is_some_and(|durable| durable.expires_at.is_some()))
                && !preserve_detached_durable_for_fresh_open(&open_guard, requested_lease)
            {
                matching.push((file_id, Arc::clone(&open)));
            }
        }
        if matching.is_empty() {
            return 0;
        }

        {
            let mut durable_opens = self
                .durable_opens
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (file_id, _) in &matching {
                durable_opens.remove(file_id);
            }
        }

        let count = matching.len();
        for (file_id, open) in matching {
            self.unregister_open(&open);
            let (
                path,
                stream_name,
                delete_on_close,
                delete_on_close_unlinks_name,
                is_directory,
                handle,
            ) = {
                let mut open = open.write().await;
                let path = open.last_path.clone();
                let stream_name = open.stream_name.clone();
                let delete_on_close = open.delete_on_close;
                let delete_on_close_unlinks_name = open.delete_on_close_unlinks_name;
                let is_directory = open.is_directory;
                open.durable = false;
                open.durable_version = 0;
                open.desired_access = 0;
                open.share_access = 0x0000_0007;
                open.lease_state = 0;
                open.lease_breaking = false;
                open.oplock_level = 0;
                open.oplock_breaking = false;
                open.delete_on_close = false;
                open.delete_on_close_unlinks_name = false;
                (
                    path,
                    stream_name,
                    delete_on_close,
                    delete_on_close_unlinks_name,
                    is_directory,
                    open.handle.take(),
                )
            };

            self.remove_byte_range_locks(&share, &path, stream_name.as_deref(), file_id);
            self.try_complete_byte_range_lock_waits(&share, &path, stream_name.as_deref())
                .await;
            self.complete_cache_break_waits_for_oplock_file_id(file_id)
                .await;

            if let Some(handle) = handle {
                let _ = handle.close().await;
            }

            if delete_on_close {
                self.drop_level_ii_oplocks_without_notification(
                    &share,
                    &path,
                    stream_name.as_deref(),
                )
                .await;
                if let Some(stream_name) = stream_name {
                    if let Err(e) = self.delete_stream(&share, &path, &stream_name) {
                        debug!(error = %e, stream_name, "detached durable delete-on-close stream delete failed");
                    }
                } else if self.has_other_open(&share, &path, &open).await {
                    if is_directory {
                        if let Err(e) = backend.unlink(&path).await {
                            debug!(error = %e, path = %path, "detached durable delete-on-close directory unlink with other opens failed");
                            self.mark_delete_pending(&share, &path);
                            self.cleanup_change_notifies_for_deleted_path(
                                &share,
                                &path,
                                ntstatus::STATUS_DELETE_PENDING,
                            )
                            .await;
                        } else {
                            self.mark_delete_pending(&share, &path);
                            self.mark_posix_deleted_opens(&share, &path).await;
                            self.cleanup_unlinked_path_state_preserving_streams(
                                &share,
                                &path,
                                is_directory,
                            )
                            .await;
                        }
                    } else if !delete_on_close_unlinks_name {
                        self.mark_delete_pending(&share, &path);
                        self.cleanup_change_notifies_for_deleted_path(
                            &share,
                            &path,
                            ntstatus::STATUS_DELETE_PENDING,
                        )
                        .await;
                    } else if let Err(e) = backend.unlink(&path).await {
                        debug!(error = %e, path = %path, "detached durable delete-on-close unlink with other opens failed");
                    } else {
                        self.mark_delete_pending(&share, &path);
                        self.mark_posix_deleted_opens(&share, &path).await;
                        self.cleanup_unlinked_path_state_preserving_streams(
                            &share,
                            &path,
                            is_directory,
                        )
                        .await;
                    }
                } else if let Err(e) = backend.unlink(&path).await {
                    debug!(error = %e, path = %path, "detached durable delete-on-close unlink failed");
                } else {
                    self.cleanup_change_notifies_for_deleted_path(
                        &share,
                        &path,
                        ntstatus::STATUS_DELETE_PENDING,
                    )
                    .await;
                    self.delete_security_descriptor(&share, &path);
                    self.delete_extended_attributes(&share, &path);
                    self.delete_allocation_size(&share, &path);
                    self.delete_file_attributes(&share, &path);
                    self.delete_file_times(&share, &path);
                    self.delete_streams(&share, &path);
                    self.delete_posix_metadata(&share, &path);
                    self.notify_removed(&share, &path, is_directory).await;
                }
            }
        }
        count
    }

    pub(crate) async fn durable_replay_open(
        &self,
        share: &str,
        create_guid: [u8; 16],
        client_guid: Uuid,
        owner: &str,
        conn: &Arc<Connection>,
        session_id: u64,
    ) -> DurableReplayLookup {
        if create_guid == [0; 16] {
            return DurableReplayLookup::NotFound;
        }
        let share = share.to_ascii_lowercase();
        let conn_key = connection_key(conn);
        let candidates = self
            .durable_opens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .filter(|durable| {
                durable.share == share
                    && durable.client_guid == client_guid
                    && durable.owner == owner
            })
            .map(|durable| {
                (
                    Arc::clone(&durable.open),
                    durable.attached_conn,
                    durable.attached_session_id,
                    durable.expires_at,
                )
            })
            .collect::<Vec<_>>();
        for (open, attached_conn, attached_session_id, expires_at) in candidates {
            if expires_at.is_some_and(|expires_at| Instant::now() >= expires_at) {
                continue;
            }
            let guard = open.read().await;
            if !(guard.durable
                && guard.durable_version >= 2
                && guard.replay_eligible
                && guard.create_guid == create_guid
                && guard.handle.is_some())
            {
                continue;
            }
            let consumed_and_used = guard.replay_consumed && guard.replay_used;
            drop(guard);
            if let Some(attached_conn) = attached_conn {
                if attached_conn != conn_key || attached_session_id != Some(session_id) {
                    return DurableReplayLookup::AttachedElsewhere;
                }
                if consumed_and_used {
                    continue;
                }
            }
            return DurableReplayLookup::Available(open);
        }
        DurableReplayLookup::NotFound
    }

    pub(crate) fn durable_pending_create_replay(
        &self,
        create_guid: [u8; 16],
        client_guid: Uuid,
        owner: &str,
    ) -> bool {
        if create_guid == [0; 16] {
            return false;
        }
        self.cache_break_creates
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .any(|pending| {
                pending.replay_create_guid == Some(create_guid)
                    && pending.replay_client_guid == client_guid
                    && pending.replay_owner == owner
            })
            || self
                .cache_break_tasks
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .values()
                .any(|pending| {
                    pending.replay_create_guid == Some(create_guid)
                        && pending.replay_client_guid == client_guid
                        && pending.replay_owner == owner
                })
    }

    pub(crate) fn completed_create_replay(
        &self,
        create_guid: [u8; 16],
        client_guid: Uuid,
        owner: &str,
    ) -> Option<Vec<u8>> {
        if create_guid == [0; 16] {
            return None;
        }
        self.completed_create_replays
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&CreateReplayKey {
                create_guid,
                client_guid,
                owner: owner.to_string(),
            })
            .cloned()
    }

    pub async fn attach_durable_open_to_tree(
        &self,
        tree: &Arc<RwLock<TreeConnect>>,
        file_id: FileId,
        open: &Arc<RwLock<Open>>,
        conn: &Arc<Connection>,
        session_id: u64,
    ) {
        {
            let tree = tree.write().await;
            let mut opens = tree.opens.write().await;
            opens.entry(file_id).or_insert_with(|| Arc::clone(open));
        }
        let mut durable_opens = self
            .durable_opens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(durable) = durable_opens.get_mut(&file_id) {
            durable.attached_conn = Some(connection_key(conn));
            durable.attached_session_id = Some(session_id);
            durable.expires_at = None;
        }
    }

    pub async fn detach_durable_opens_for_session(
        &self,
        session: &Arc<RwLock<crate::conn::state::Session>>,
    ) -> usize {
        let trees = {
            let session = session.read().await;
            session
                .trees
                .read()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut detached = 0;
        for tree in trees {
            detached += self.detach_durable_opens_for_tree(&tree).await;
        }
        detached
    }

    pub async fn detach_durable_opens_for_connection(&self, conn: &Arc<Connection>) -> usize {
        let sessions = conn
            .sessions
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut detached = 0;
        for session in sessions {
            detached += self.detach_durable_opens_for_session(&session).await;
        }
        detached
    }

    pub async fn cleanup_opens_for_connection(&self, conn: &Arc<Connection>) -> usize {
        let sessions = conn
            .sessions
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut closed = 0;
        for session in sessions {
            closed += self.cleanup_opens_for_session(conn, &session).await;
        }
        closed
    }

    pub async fn cleanup_opens_for_session(
        &self,
        conn: &Arc<Connection>,
        session: &Arc<RwLock<crate::conn::state::Session>>,
    ) -> usize {
        let trees = {
            let session = session.read().await;
            session
                .trees
                .read()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut closed = 0;
        for tree in trees {
            closed += self.cleanup_opens_for_tree(conn, &tree).await;
        }
        closed
    }

    pub async fn cleanup_opens_for_tree(
        &self,
        conn: &Arc<Connection>,
        tree: &Arc<RwLock<TreeConnect>>,
    ) -> usize {
        self.cleanup_opens_for_tree_inner(conn, tree, false).await
    }

    pub async fn cleanup_tree_disconnect_opens(
        &self,
        conn: &Arc<Connection>,
        tree: &Arc<RwLock<TreeConnect>>,
    ) -> usize {
        self.cleanup_opens_for_tree_inner(conn, tree, true).await
    }

    async fn cleanup_opens_for_tree_inner(
        &self,
        conn: &Arc<Connection>,
        tree: &Arc<RwLock<TreeConnect>>,
        preserve_durable_delete_on_close: bool,
    ) -> usize {
        let (share, backend, opens) = {
            let tree = tree.write().await;
            let share = tree.share.name.clone();
            let backend = Arc::clone(&tree.share.backend);
            let opens = tree
                .opens
                .write()
                .await
                .drain()
                .collect::<Vec<(FileId, Arc<RwLock<Open>>)>>();
            (share, backend, opens)
        };

        let count = opens.len();
        for (file_id, open) in opens {
            self.cleanup_closed_open(
                conn,
                &share,
                &backend,
                file_id,
                open,
                preserve_durable_delete_on_close,
            )
            .await;
        }
        count
    }

    async fn cleanup_closed_open(
        &self,
        conn: &Arc<Connection>,
        share: &str,
        backend: &Arc<dyn ShareBackend>,
        file_id: FileId,
        open: Arc<RwLock<Open>>,
        preserve_durable_delete_on_close: bool,
    ) {
        self.cleanup_change_notifies_for_file(conn, file_id, ntstatus::STATUS_NOTIFY_CLEANUP)
            .await;
        self.cleanup_pipe_reads_for_file(conn, file_id, ntstatus::STATUS_NOTIFY_CLEANUP)
            .await;
        self.cleanup_byte_range_lock_waits_for_file(conn, file_id, ntstatus::STATUS_NOTIFY_CLEANUP)
            .await;

        let (break_delete_on_close, break_path, break_stream_name, break_lease_key) = {
            let open = open.read().await;
            (
                open.delete_on_close,
                open.last_path.clone(),
                open.stream_name.clone(),
                open.lease_key,
            )
        };
        if break_delete_on_close {
            self.break_conflicting_leases_for_open(
                share,
                &break_path,
                break_stream_name.as_deref(),
                break_lease_key,
                LEASE_READ_CACHING,
            )
            .await;
        }

        let (
            path,
            stream_name,
            delete_on_close,
            delete_on_close_unlinks_name,
            is_directory,
            was_durable,
            handle,
        ) = {
            let mut open = open.write().await;
            let path = open.last_path.clone();
            let stream_name = open.stream_name.clone();
            let delete_on_close = open.delete_on_close;
            let delete_on_close_unlinks_name = open.delete_on_close_unlinks_name;
            let is_directory = open.is_directory;
            let was_durable = open.durable;
            open.oplock_breaking = false;
            open.oplock_break_to = OPLOCK_NONE;
            open.desired_access = 0;
            open.share_access = 0x0000_0007;
            if !(preserve_durable_delete_on_close && open.durable) {
                open.delete_on_close = false;
                open.delete_on_close_unlinks_name = false;
            }
            (
                path,
                stream_name,
                delete_on_close,
                delete_on_close_unlinks_name,
                is_directory,
                was_durable,
                open.handle.take(),
            )
        };

        let preserve_durable_delete_on_close = preserve_durable_delete_on_close
            && was_durable
            && delete_on_close
            && stream_name.is_none();
        if preserve_durable_delete_on_close {
            self.detach_durable_open_without_reconnect(file_id);
        } else {
            self.remove_durable_open(file_id);
        }
        if let Some(handle) = handle {
            let _ = handle.close().await;
        }
        self.unregister_open(&open);
        self.remove_byte_range_locks(share, &path, stream_name.as_deref(), file_id);
        self.try_complete_byte_range_lock_waits(share, &path, stream_name.as_deref())
            .await;
        self.complete_cache_break_waits_for_oplock_file_id(file_id)
            .await;

        let mut final_pending_delete = false;
        if delete_on_close && preserve_durable_delete_on_close {
            self.clear_delete_pending(share, &path);
        } else if delete_on_close {
            self.drop_level_ii_oplocks_without_notification(share, &path, stream_name.as_deref())
                .await;
            if let Some(stream_name) = stream_name {
                if let Err(e) = self.delete_stream(share, &path, &stream_name) {
                    debug!(error = %e, stream_name, "disconnect delete-on-close stream delete failed");
                }
            } else if self.has_other_open(share, &path, &open).await {
                if is_directory {
                    if let Err(e) = backend.unlink(&path).await {
                        debug!(error = %e, path = %path, "disconnect delete-on-close directory unlink with other opens failed");
                        self.mark_delete_pending(share, &path);
                        self.cleanup_change_notifies_for_deleted_path(
                            share,
                            &path,
                            ntstatus::STATUS_DELETE_PENDING,
                        )
                        .await;
                    } else {
                        self.mark_delete_pending(share, &path);
                        self.mark_posix_deleted_opens(share, &path).await;
                        self.cleanup_unlinked_path_state_preserving_streams(
                            share,
                            &path,
                            is_directory,
                        )
                        .await;
                    }
                } else if !delete_on_close_unlinks_name {
                    self.mark_delete_pending(share, &path);
                    self.cleanup_change_notifies_for_deleted_path(
                        share,
                        &path,
                        ntstatus::STATUS_DELETE_PENDING,
                    )
                    .await;
                } else if let Err(e) = backend.unlink(&path).await {
                    debug!(error = %e, path = %path, "disconnect delete-on-close unlink with other opens failed");
                } else {
                    self.mark_delete_pending(share, &path);
                    self.mark_posix_deleted_opens(share, &path).await;
                    self.cleanup_unlinked_path_state_preserving_streams(share, &path, is_directory)
                        .await;
                }
            } else if let Err(e) = backend.unlink(&path).await {
                debug!(error = %e, path = %path, "disconnect delete-on-close unlink failed");
            } else {
                self.cleanup_deleted_path_state(share, &path, is_directory)
                    .await;
            }
        } else if self.take_delete_pending_if_last(share, &path, &open).await {
            final_pending_delete = true;
        }

        if final_pending_delete {
            if let Err(e) = backend.unlink(&path).await {
                if matches!(e, SmbError::NotFound | SmbError::PathNotFound) {
                    self.cleanup_deleted_path_state(share, &path, is_directory)
                        .await;
                } else {
                    debug!(error = %e, path = %path, "disconnect final pending-delete unlink failed");
                }
            } else {
                self.cleanup_deleted_path_state(share, &path, is_directory)
                    .await;
            }
        }
    }

    async fn cleanup_unlinked_path_state_preserving_streams(
        &self,
        share: &str,
        path: &SmbPath,
        is_directory: bool,
    ) {
        self.cleanup_change_notifies_for_deleted_path(share, path, ntstatus::STATUS_DELETE_PENDING)
            .await;
        self.delete_security_descriptor(share, path);
        self.delete_extended_attributes(share, path);
        self.delete_allocation_size(share, path);
        self.delete_file_attributes(share, path);
        self.delete_file_times(share, path);
        self.delete_posix_metadata(share, path);
        self.notify_removed(share, path, is_directory).await;
    }

    async fn cleanup_deleted_path_state(&self, share: &str, path: &SmbPath, is_directory: bool) {
        self.cleanup_change_notifies_for_deleted_path(share, path, ntstatus::STATUS_DELETE_PENDING)
            .await;
        self.delete_security_descriptor(share, path);
        self.delete_extended_attributes(share, path);
        self.delete_allocation_size(share, path);
        self.delete_file_attributes(share, path);
        self.delete_file_times(share, path);
        self.delete_streams(share, path);
        self.delete_posix_metadata(share, path);
        self.clear_delete_pending(share, path);
        self.notify_removed(share, path, is_directory).await;
    }

    pub async fn takeover_previous_session(&self, previous_session_id: u64) -> bool {
        let conns = self.active_connections.live().await;
        for conn in conns {
            let previous_session = conn.sessions.write().await.remove(&previous_session_id);
            let Some(previous_session) = previous_session else {
                continue;
            };
            self.cleanup_change_notifies_for_session_id(
                previous_session_id,
                ntstatus::STATUS_NOTIFY_CLEANUP,
            )
            .await;
            self.cleanup_cache_break_creates_for_session(
                &conn,
                previous_session_id,
                ntstatus::STATUS_NOTIFY_CLEANUP,
            )
            .await;
            self.cleanup_cache_break_writes_for_session(
                &conn,
                previous_session_id,
                ntstatus::STATUS_NOTIFY_CLEANUP,
            )
            .await;
            self.cleanup_cache_break_tasks_for_session(
                &conn,
                previous_session_id,
                ntstatus::STATUS_NOTIFY_CLEANUP,
            )
            .await;
            self.detach_durable_opens_for_session(&previous_session)
                .await;
            self.cleanup_opens_for_session(&conn, &previous_session)
                .await;
            crate::conn::state::close_session_state(&previous_session).await;
            return true;
        }
        false
    }

    pub async fn session_signing_material(
        &self,
        session_id: u64,
    ) -> Option<([u8; 16], SigningAlgo, bool, Option<Dialect>, Uuid, u16)> {
        for conn in self.active_connections.live().await {
            let session = {
                let sessions = conn.sessions.read().await;
                sessions.get(&session_id).cloned()
            };
            let Some(session) = session else {
                continue;
            };
            let key = {
                let session = session.read().await;
                session.signing_key
            };
            let algo = *conn.signing_algo.read().await;
            let signing_context_present = *conn.signing_context_present.read().await;
            let dialect = *conn.dialect.read().await;
            let client_guid = *conn.client_guid.read().await;
            let encryption_cipher = *conn.encryption_cipher.read().await;
            return Some((
                key,
                algo,
                signing_context_present,
                dialect,
                client_guid,
                encryption_cipher,
            ));
        }
        None
    }

    pub async fn session_state(
        &self,
        session_id: u64,
    ) -> Option<Arc<RwLock<crate::conn::state::Session>>> {
        for conn in self.active_connections.live().await {
            let session = {
                let sessions = conn.sessions.read().await;
                sessions.get(&session_id).cloned()
            };
            if session.is_some() {
                return session;
            }
        }
        None
    }

    pub async fn detach_durable_opens_for_tree(&self, tree: &Arc<RwLock<TreeConnect>>) -> usize {
        let (share, candidates) = {
            let tree = tree.write().await;
            let share = tree.share.name.to_ascii_lowercase();
            let opens = tree.opens.read().await;
            (
                share,
                opens
                    .iter()
                    .map(|(file_id, open)| (*file_id, Arc::clone(open)))
                    .collect::<Vec<_>>(),
            )
        };

        let mut durable_ids = Vec::new();
        let mut nondetached_durables = Vec::new();
        for (file_id, open) in candidates {
            if self.can_detach_durable_open(&share, &open).await {
                durable_ids.push(file_id);
            } else {
                let open = open.read().await;
                if open.durable {
                    nondetached_durables.push((
                        file_id,
                        open.last_path.clone(),
                        open.stream_name.clone(),
                    ));
                }
            }
        }
        if durable_ids.is_empty() && nondetached_durables.is_empty() {
            return 0;
        }

        if !nondetached_durables.is_empty() {
            {
                let mut durable_opens = self
                    .durable_opens
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for (file_id, _, _) in &nondetached_durables {
                    durable_opens.remove(file_id);
                }
            }

            for (file_id, path, stream_name) in nondetached_durables {
                self.unregister_open_by_file_id(file_id).await;
                self.remove_byte_range_locks(&share, &path, stream_name.as_deref(), file_id);
                self.try_complete_byte_range_lock_waits(&share, &path, stream_name.as_deref())
                    .await;
            }
        }

        let detached = {
            let tree = tree.write().await;
            let mut opens = tree.opens.write().await;
            durable_ids
                .into_iter()
                .filter_map(|file_id| opens.remove(&file_id).map(|open| (file_id, open)))
                .collect::<Vec<_>>()
        };

        let mut durable_opens = self
            .durable_opens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = detached.len();
        for (file_id, open) in detached {
            if let Some(durable) = durable_opens.get_mut(&file_id) {
                durable.open = open;
                durable.attached_conn = None;
                durable.attached_session_id = None;
                durable.expires_at = Some(Instant::now() + self.config.durable_handle_timeout);
            } else {
                durable_opens.insert(
                    file_id,
                    DurableOpen {
                        share: share.clone(),
                        open,
                        client_guid: Uuid::nil(),
                        owner: String::new(),
                        attached_conn: None,
                        attached_session_id: None,
                        expires_at: Some(Instant::now() + self.config.durable_handle_timeout),
                    },
                );
            }
        }
        count
    }

    async fn can_detach_durable_open(&self, share: &str, open: &Arc<RwLock<Open>>) -> bool {
        let open = open.read().await;
        if !open.durable || open.handle.is_none() || open.lease_breaking || open.oplock_breaking {
            return false;
        }
        if !durable_reconnect_caching_valid(&open) {
            return false;
        }
        if open.lease_state != 0
            && open.lease_state & LEASE_WRITE_CACHING == 0
            && self.open_has_byte_range_locks(
                share,
                &open.last_path,
                open.stream_name.as_deref(),
                open.file_id,
            )
        {
            return false;
        }
        true
    }

    fn open_has_byte_range_locks(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        fid: FileId,
    ) -> bool {
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let table = self
            .byte_range_locks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        table
            .get(&key)
            .is_some_and(|locks| locks.iter().any(|lock| lock.fid == fid))
    }

    pub async fn reconnect_durable_open(
        &self,
        tree: &Arc<RwLock<TreeConnect>>,
        file_id: FileId,
        durable_version: u8,
        create_guid: Option<[u8; 16]>,
        requested_lease_key: Option<[u8; 16]>,
        conn: &Arc<Connection>,
        session_id: u64,
        client_guid: Uuid,
        owner: &str,
    ) -> Option<Arc<RwLock<Open>>> {
        let share = {
            let tree = tree.read().await;
            tree.share.name.to_ascii_lowercase()
        };
        let (open, expired_open, durable_client_guid) = {
            let mut durable_opens = self
                .durable_opens
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match durable_opens.get(&file_id) {
                Some(durable) if durable.share == share && durable.owner == owner => {
                    if durable.expires_at.is_none() {
                        (None, None, durable.client_guid)
                    } else if durable
                        .expires_at
                        .is_some_and(|expires_at| Instant::now() >= expires_at)
                    {
                        let durable = durable_opens.remove(&file_id);
                        (
                            None,
                            durable.as_ref().map(|durable| Arc::clone(&durable.open)),
                            durable.map_or(Uuid::nil(), |durable| durable.client_guid),
                        )
                    } else {
                        (Some(Arc::clone(&durable.open)), None, durable.client_guid)
                    }
                }
                _ => (None, None, Uuid::nil()),
            }
        };
        if let Some(open) = expired_open {
            let handle = open.write().await.handle.take();
            if let Some(handle) = handle {
                let _ = handle.close().await;
            }
            return None;
        }
        let open = open?;
        {
            let open = open.read().await;
            if !open.durable || open.durable_version != durable_version || open.file_id != file_id {
                return None;
            }
            if open.lease_state != 0 && durable_client_guid != client_guid {
                return None;
            }
            if durable_version >= 2 && create_guid.is_some_and(|guid| guid != open.create_guid) {
                return None;
            }
            match (requested_lease_key, open.lease_state != 0) {
                (Some(key), true) if key == open.lease_key => {}
                (None, false) => {}
                _ => return None,
            }
        }
        {
            let mut durable_opens = self
                .durable_opens
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let durable = durable_opens.get_mut(&file_id)?;
            if durable.share != share
                || durable.owner != owner
                || durable.expires_at.is_none()
                || durable
                    .expires_at
                    .is_some_and(|expires_at| Instant::now() >= expires_at)
            {
                return None;
            }
            durable.expires_at = None;
            durable.attached_conn = Some(connection_key(conn));
            durable.attached_session_id = Some(session_id);
        }
        {
            let tree = tree.write().await;
            let mut opens = tree.opens.write().await;
            if opens.contains_key(&file_id) {
                return None;
            }
            opens.insert(file_id, Arc::clone(&open));
        }
        Some(open)
    }

    pub fn register_change_notify(
        &self,
        async_id: u64,
        conn: &Arc<Connection>,
        open: &Arc<RwLock<Open>>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        file_id: FileId,
        share: &str,
        path: SmbPath,
        recursive: bool,
        output_buffer_length: u32,
        completion_filter: u32,
        notify_first: bool,
        notify_force_enum_dir: bool,
        watch_cancel: Option<oneshot::Sender<()>>,
    ) {
        self.change_notifies
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                change_notify_key(conn, async_id),
                PendingChangeNotify {
                    conn: Arc::downgrade(conn),
                    open: Arc::downgrade(open),
                    tx,
                    req_hdr,
                    file_id,
                    share: share.to_ascii_lowercase(),
                    path,
                    recursive,
                    output_buffer_length,
                    completion_filter,
                    notify_first,
                    notify_force_enum_dir,
                    notify_events: Vec::new(),
                    notify_completion_scheduled: false,
                    watch_cancel,
                },
            );
    }

    pub fn reserve_change_notify_async_slot(&self, conn: &Arc<Connection>) -> bool {
        reserve_pending_async_slot(conn)
    }

    pub fn reserve_pipe_read_async_slot(&self, conn: &Arc<Connection>) -> bool {
        reserve_pending_async_slot(conn)
    }

    pub fn register_pipe_read(
        &self,
        async_id: u64,
        conn: &Arc<Connection>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        file_id: FileId,
    ) {
        self.pipe_reads
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                pipe_read_key(conn, async_id),
                PendingPipeRead {
                    conn: Arc::downgrade(conn),
                    tx,
                    req_hdr,
                    file_id,
                },
            );
    }

    pub fn reserve_byte_range_lock_wait_async_slot(&self, conn: &Arc<Connection>) -> bool {
        reserve_pending_async_slot(conn)
    }

    pub fn register_byte_range_lock_wait(
        &self,
        async_id: u64,
        conn: &Arc<Connection>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        share: &str,
        path: SmbPath,
        stream_name: Option<String>,
        file_id: FileId,
        open: &Arc<RwLock<Open>>,
        dialect: Option<Dialect>,
        lock_sequence: u32,
        locks: Vec<ByteRangeLockRequest>,
    ) {
        self.byte_range_lock_waits
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                byte_range_lock_wait_key(conn, async_id),
                PendingByteRangeLock {
                    conn: Arc::downgrade(conn),
                    open: Arc::downgrade(open),
                    tx,
                    req_hdr,
                    share: share.to_ascii_lowercase(),
                    path,
                    stream_name,
                    file_id,
                    dialect,
                    lock_sequence,
                    locks,
                },
            );
    }

    pub fn reserve_cache_break_create_async_slot(&self, conn: &Arc<Connection>) -> bool {
        reserve_pending_async_slot(conn)
    }

    pub fn register_cache_break_create(
        self: &Arc<Self>,
        async_id: u64,
        conn: &Arc<Connection>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        wait_lease_keys: Vec<[u8; 16]>,
        wait_oplock_file_ids: Vec<FileId>,
        file_id: FileId,
        status: u32,
        body: Vec<u8>,
        replay_create_guid: Option<[u8; 16]>,
        replay_client_guid: Uuid,
        replay_owner: String,
    ) {
        self.cache_break_creates
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                cache_break_create_key(conn, async_id),
                PendingCacheBreakCreate {
                    conn: Arc::downgrade(conn),
                    tx,
                    req_hdr,
                    wait_lease_keys: wait_lease_keys.clone(),
                    wait_oplock_file_ids: wait_oplock_file_ids.clone(),
                    file_id,
                    status,
                    body,
                    replay_create_guid,
                    replay_client_guid,
                    replay_owner,
                    compound_completion: None,
                },
            );
        self.spawn_cache_break_timeout(wait_lease_keys, wait_oplock_file_ids);
    }

    async fn complete_cache_break_creates(
        &self,
        pending: Vec<(u64, PendingCacheBreakCreate)>,
    ) -> usize {
        let mut sent = 0;
        for (async_id, mut pending) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            if pending.status == crate::ntstatus::STATUS_SUCCESS
                && let Some(create_guid) = pending.replay_create_guid
            {
                self.completed_create_replays
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(
                        CreateReplayKey {
                            create_guid,
                            client_guid: pending.replay_client_guid,
                            owner: pending.replay_owner.clone(),
                        },
                        pending.body.clone(),
                    );
            }
            let response = HandlerResponse::final_async(async_id, pending.status, pending.body);
            let frame = if let Some(compound_completion) = pending.compound_completion.take() {
                compound_completion(response).await
            } else {
                dispatch::build_standalone_response_frame(&conn, &pending.req_hdr, response).await
            };
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    async fn complete_cache_break_creates_with_status(
        &self,
        pending: Vec<(u64, PendingCacheBreakCreate)>,
        status: u32,
    ) -> usize {
        let mut completed = Vec::with_capacity(pending.len());
        for (async_id, mut pending) in pending {
            self.cleanup_pending_cache_break_create_open(&pending).await;
            pending.status = status;
            pending.body = HandlerResponse::err(status).body;
            completed.push((async_id, pending));
        }
        self.complete_cache_break_creates(completed).await
    }

    async fn cleanup_pending_cache_break_create_open(&self, pending: &PendingCacheBreakCreate) {
        let Some(conn) = pending.conn.upgrade() else {
            self.remove_durable_open(pending.file_id);
            return;
        };
        let Some(tree_id) = pending.req_hdr.tree_id() else {
            self.remove_durable_open(pending.file_id);
            return;
        };
        let tree_arc = {
            let sessions = conn.sessions.read().await;
            let Some(session) = sessions.get(&pending.req_hdr.session_id).cloned() else {
                self.remove_durable_open(pending.file_id);
                return;
            };
            let session = session.read().await;
            session.trees.read().await.get(&tree_id).cloned()
        };
        let Some(tree_arc) = tree_arc else {
            self.remove_durable_open(pending.file_id);
            return;
        };
        let removed = {
            let tree = tree_arc.write().await;
            tree.opens.write().await.remove(&pending.file_id)
        };
        self.remove_durable_open(pending.file_id);
        if let Some(open_arc) = removed {
            let mut open = open_arc.write().await;
            if let Some(handle) = open.handle.take() {
                let _ = handle.close().await;
            }
        }
    }

    pub async fn cancel_cache_break_create(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let pending = {
            let mut creates = self
                .cache_break_creates
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = cache_break_create_key(conn, async_id);
            match creates.get(&key) {
                Some(pending) if pending.req_hdr.session_id == session_id => creates.remove(&key),
                _ => None,
            }
        };

        let Some(pending) = pending else {
            return false;
        };
        self.complete_cache_break_creates_with_status(vec![(async_id, pending)], status)
            .await
            != 0
    }

    pub async fn cleanup_cache_break_creates_for_session(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_creates_matching(|key, pending| {
            key.conn == conn_key && pending.req_hdr.session_id == session_id
        });
        self.complete_cache_break_creates_with_status(pending, status)
            .await
    }

    pub async fn cleanup_cache_break_creates_for_tree(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_creates_matching(|key, pending| {
            key.conn == conn_key
                && pending.req_hdr.session_id == session_id
                && pending.req_hdr.tree_id() == Some(tree_id)
        });
        self.complete_cache_break_creates_with_status(pending, status)
            .await
    }

    pub async fn cleanup_cache_break_creates_for_connection(
        &self,
        conn: &Arc<Connection>,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_creates_matching(|key, _| key.conn == conn_key);
        let count = pending.len();
        for (_, pending) in pending {
            release_pending_async_slot(&pending.conn);
            self.cleanup_pending_cache_break_create_open(&pending).await;
        }
        count
    }

    fn take_cache_break_creates_matching(
        &self,
        matches: impl Fn(&PendingCacheBreakCreateKey, &PendingCacheBreakCreate) -> bool,
    ) -> Vec<(u64, PendingCacheBreakCreate)> {
        let mut creates = self
            .cache_break_creates
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching = creates
            .iter()
            .filter_map(|(key, pending)| matches(key, pending).then_some(*key))
            .collect::<Vec<_>>();
        matching
            .into_iter()
            .filter_map(|key| creates.remove(&key).map(|pending| (key.async_id, pending)))
            .collect()
    }

    pub fn reserve_cache_break_write_async_slot(&self, conn: &Arc<Connection>) -> bool {
        reserve_pending_async_slot(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_cache_break_write(
        self: &Arc<Self>,
        async_id: u64,
        conn: &Arc<Connection>,
        open: &Arc<RwLock<Open>>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        wait_lease_keys: Vec<[u8; 16]>,
        share: &str,
        path: SmbPath,
        stream_name: Option<String>,
        file_id: FileId,
        offset: u64,
        data: Vec<u8>,
        is_directory: bool,
    ) {
        self.cache_break_writes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                cache_break_write_key(conn, async_id),
                PendingCacheBreakWrite {
                    conn: Arc::downgrade(conn),
                    open: Arc::downgrade(open),
                    tx,
                    req_hdr,
                    wait_lease_keys: wait_lease_keys.clone(),
                    share: share.to_ascii_lowercase(),
                    path,
                    stream_name,
                    file_id,
                    offset,
                    data,
                    is_directory,
                    compound_completion: None,
                },
            );
        self.spawn_cache_break_timeout(wait_lease_keys, Vec::new());
    }

    async fn complete_cache_break_writes(
        &self,
        pending: Vec<(u64, PendingCacheBreakWrite)>,
    ) -> usize {
        let mut sent = 0;
        for (async_id, mut pending) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            let (status, body) = self.complete_one_cache_break_write(&pending).await;
            let response = HandlerResponse::final_async(async_id, status, body);
            let frame = if let Some(compound_completion) = pending.compound_completion.take() {
                compound_completion(response).await
            } else {
                dispatch::build_standalone_response_frame(&conn, &pending.req_hdr, response).await
            };
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    async fn complete_one_cache_break_write(
        &self,
        pending: &PendingCacheBreakWrite,
    ) -> (u32, Vec<u8>) {
        let Some(open_arc) = pending.open.upgrade() else {
            return error_body(crate::ntstatus::STATUS_FILE_CLOSED);
        };
        let status = self.check_write_lock(
            &pending.share,
            &pending.path,
            pending.stream_name.as_deref(),
            pending.file_id,
            pending.offset,
            pending.data.len() as u64,
        );
        if status != crate::ntstatus::STATUS_SUCCESS {
            return error_body(status);
        }
        let result = {
            let open = open_arc.read().await;
            match open.handle.as_ref() {
                Some(handle) => {
                    handle
                        .write_owned(pending.offset, pending.data.clone())
                        .await
                }
                None => return error_body(crate::ntstatus::STATUS_FILE_CLOSED),
            }
        };
        let count = match result {
            Ok(count) => count,
            Err(e) => return error_body(e.to_nt_status()),
        };
        open_arc.write().await.current_offset = pending.offset + u64::from(count);
        if count != 0 {
            if pending.stream_name.is_none() {
                self.update_file_times_after_write(&pending.share, &pending.path, pending.file_id);
            }
            self.notify_data_modified(&pending.share, &pending.path, pending.is_directory)
                .await;
        }
        let mut body = Vec::new();
        WriteResponse::new(count)
            .write_to(&mut body)
            .expect("encode write response");
        (crate::ntstatus::STATUS_SUCCESS, body)
    }

    async fn complete_cache_break_writes_with_status(
        &self,
        pending: Vec<(u64, PendingCacheBreakWrite)>,
        status: u32,
    ) -> usize {
        let mut sent = 0;
        for (async_id, pending) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            let frame = dispatch::build_standalone_response_frame(
                &conn,
                &pending.req_hdr,
                HandlerResponse::final_async(async_id, status, HandlerResponse::err(status).body),
            )
            .await;
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub async fn cancel_cache_break_write(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let pending = {
            let mut writes = self
                .cache_break_writes
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = cache_break_write_key(conn, async_id);
            match writes.get(&key) {
                Some(pending) if pending.req_hdr.session_id == session_id => writes.remove(&key),
                _ => None,
            }
        };

        let Some(pending) = pending else {
            return false;
        };
        self.complete_cache_break_writes_with_status(vec![(async_id, pending)], status)
            .await
            != 0
    }

    fn take_cache_break_writes_matching(
        &self,
        matches: impl Fn(&PendingCacheBreakWriteKey, &PendingCacheBreakWrite) -> bool,
    ) -> Vec<(u64, PendingCacheBreakWrite)> {
        let mut writes = self
            .cache_break_writes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching = writes
            .iter()
            .filter_map(|(key, pending)| matches(key, pending).then_some(*key))
            .collect::<Vec<_>>();
        matching
            .into_iter()
            .filter_map(|key| writes.remove(&key).map(|pending| (key.async_id, pending)))
            .collect()
    }

    pub async fn cleanup_cache_break_writes_for_session(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_writes_matching(|key, pending| {
            key.conn == conn_key && pending.req_hdr.session_id == session_id
        });
        self.complete_cache_break_writes_with_status(pending, status)
            .await
    }

    pub async fn cleanup_cache_break_writes_for_tree(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_writes_matching(|key, pending| {
            key.conn == conn_key
                && pending.req_hdr.session_id == session_id
                && pending.req_hdr.tree_id() == Some(tree_id)
        });
        self.complete_cache_break_writes_with_status(pending, status)
            .await
    }

    pub async fn cleanup_cache_break_writes_for_connection(&self, conn: &Arc<Connection>) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_writes_matching(|key, _| key.conn == conn_key);
        for (_, pending) in &pending {
            release_pending_async_slot(&pending.conn);
        }
        pending.len()
    }

    async fn complete_cache_break_writes_for_lease_key(&self, lease_key: [u8; 16]) -> usize {
        let candidates = {
            let mut writes = self
                .cache_break_writes
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matching = writes
                .iter()
                .filter_map(|(key, pending)| {
                    pending.wait_lease_keys.contains(&lease_key).then_some(*key)
                })
                .collect::<Vec<_>>();
            matching
                .into_iter()
                .filter_map(|key| writes.remove(&key).map(|pending| (key, pending)))
                .collect::<Vec<_>>()
        };

        let mut pending = Vec::new();
        let mut still_waiting = Vec::new();
        for (key, write) in candidates {
            let mut waiting = false;
            for lease_key in &write.wait_lease_keys {
                if self.lease_key_is_breaking(*lease_key).await {
                    waiting = true;
                    break;
                }
            }
            if waiting {
                still_waiting.push((key, write));
            } else {
                pending.push((key.async_id, write));
            }
        }

        if !still_waiting.is_empty() {
            let mut writes = self
                .cache_break_writes
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (key, write) in still_waiting {
                writes.insert(key, write);
            }
        }

        self.complete_cache_break_writes(pending).await
    }

    pub(crate) fn reserve_cache_break_task_async_slot(&self, conn: &Arc<Connection>) -> bool {
        reserve_pending_async_slot(conn)
    }

    pub(crate) async fn lease_break_wait_includes_connection(
        &self,
        lease_keys: &[[u8; 16]],
        conn: &Arc<Connection>,
    ) -> bool {
        let candidates = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| Some((entry.open.upgrade()?, entry.conn.upgrade()?)))
                .collect::<Vec<_>>()
        };

        for (open_arc, owner_conn) in candidates {
            if !Arc::ptr_eq(&owner_conn, conn) {
                continue;
            }
            let open = open_arc.read().await;
            if open.lease_breaking && lease_keys.contains(&open.lease_key) {
                return true;
            }
        }
        false
    }

    pub(crate) async fn wait_for_lease_breaks_or_timeout(&self, lease_keys: &[[u8; 16]]) {
        if lease_keys.is_empty() {
            return;
        }
        let timeout = if self
            .cache_break_wait_has_force_unacked(lease_keys, &[])
            .await
        {
            std::time::Duration::from_millis(1)
        } else {
            self.config.cache_break_timeout
        };
        let started = Instant::now();
        loop {
            let mut waiting = false;
            for lease_key in lease_keys {
                if self.lease_key_is_breaking(*lease_key).await {
                    waiting = true;
                    break;
                }
            }
            if !waiting {
                return;
            }
            if started.elapsed() >= timeout {
                self.force_complete_cache_break_leases(lease_keys).await;
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    pub(crate) fn register_cache_break_task(
        self: &Arc<Self>,
        async_id: u64,
        conn: &Arc<Connection>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        wait_lease_keys: Vec<[u8; 16]>,
        wait_oplock_file_ids: Vec<FileId>,
        completion: CacheBreakCompletion,
    ) {
        self.register_cache_break_task_with_replay(
            async_id,
            conn,
            tx,
            req_hdr,
            wait_lease_keys,
            wait_oplock_file_ids,
            None,
            Uuid::nil(),
            String::new(),
            completion,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_cache_break_task_with_replay(
        self: &Arc<Self>,
        async_id: u64,
        conn: &Arc<Connection>,
        tx: mpsc::Sender<Vec<u8>>,
        req_hdr: Smb2Header,
        wait_lease_keys: Vec<[u8; 16]>,
        wait_oplock_file_ids: Vec<FileId>,
        replay_create_guid: Option<[u8; 16]>,
        replay_client_guid: Uuid,
        replay_owner: String,
        completion: CacheBreakCompletion,
    ) {
        self.cache_break_tasks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                cache_break_task_key(conn, async_id),
                PendingCacheBreakTask {
                    conn: Arc::downgrade(conn),
                    tx,
                    req_hdr,
                    wait_lease_keys: wait_lease_keys.clone(),
                    wait_oplock_file_ids: wait_oplock_file_ids.clone(),
                    completion: Some(completion),
                    compound_completion: None,
                    replay_create_guid,
                    replay_client_guid,
                    replay_owner,
                },
            );
        self.spawn_cache_break_timeout(wait_lease_keys, wait_oplock_file_ids);
    }

    fn spawn_cache_break_timeout(
        self: &Arc<Self>,
        wait_lease_keys: Vec<[u8; 16]>,
        wait_oplock_file_ids: Vec<FileId>,
    ) {
        if wait_lease_keys.is_empty() && wait_oplock_file_ids.is_empty() {
            return;
        }
        let lease_generations = wait_lease_keys
            .iter()
            .map(|lease_key| (*lease_key, self.lease_break_generation(*lease_key)))
            .collect::<Vec<_>>();
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let timeout = if server
                .cache_break_wait_has_force_unacked(&wait_lease_keys, &wait_oplock_file_ids)
                .await
            {
                std::time::Duration::from_millis(1)
            } else {
                server.config.cache_break_timeout
            };
            tokio::time::sleep(timeout).await;
            let active_wait_lease_keys = lease_generations
                .into_iter()
                .filter_map(|(lease_key, generation)| {
                    server
                        .lease_break_generation_matches(lease_key, generation)
                        .then_some(lease_key)
                })
                .collect::<Vec<_>>();
            server
                .force_complete_cache_break_leases(&active_wait_lease_keys)
                .await;
            let active_wait_oplock_file_ids = wait_oplock_file_ids;
            server
                .force_complete_cache_break_oplocks(&active_wait_oplock_file_ids)
                .await;
            for lease_key in active_wait_lease_keys {
                server
                    .complete_cache_break_creates_for_lease_key(lease_key)
                    .await;
                server
                    .complete_cache_break_writes_for_lease_key(lease_key)
                    .await;
                server
                    .complete_cache_break_tasks_for_lease_key(lease_key)
                    .await;
            }
            for file_id in active_wait_oplock_file_ids {
                server
                    .complete_cache_break_creates_for_oplock_file_id(file_id)
                    .await;
                server
                    .complete_cache_break_tasks_for_oplock_file_id(file_id)
                    .await;
            }
        });
    }

    pub(crate) fn attach_cache_break_compound_completion(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        completion: CacheBreakCompoundCompletion,
    ) -> bool {
        let conn_key = Arc::as_ptr(conn) as usize;
        let mut completion = Some(completion);
        let create_key = PendingCacheBreakCreateKey {
            conn: conn_key,
            async_id,
        };
        {
            let mut creates = self
                .cache_break_creates
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(pending) = creates.get_mut(&create_key) {
                pending.compound_completion = completion.take();
                return true;
            }
        }

        let write_key = PendingCacheBreakWriteKey {
            conn: conn_key,
            async_id,
        };
        {
            let mut writes = self
                .cache_break_writes
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(pending) = writes.get_mut(&write_key) {
                pending.compound_completion = completion.take();
                return true;
            }
        }

        let task_key = PendingCacheBreakTaskKey {
            conn: conn_key,
            async_id,
        };
        let mut tasks = self
            .cache_break_tasks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pending) = tasks.get_mut(&task_key) {
            pending.compound_completion = completion.take();
            return true;
        }
        false
    }

    pub(crate) fn discard_pending_async(&self, conn: &Arc<Connection>, async_id: u64) -> bool {
        let conn_key = Arc::as_ptr(conn) as usize;
        let notify_key = PendingChangeNotifyKey {
            conn: conn_key,
            async_id,
        };
        {
            let mut notifies = self
                .change_notifies
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(mut pending) = notifies.remove(&notify_key) {
                release_pending_async_slot(&pending.conn);
                if let Some(cancel) = pending.watch_cancel.take() {
                    let _ = cancel.send(());
                }
                return true;
            }
        }

        let pipe_key = PendingPipeReadKey {
            conn: conn_key,
            async_id,
        };
        {
            let mut reads = self
                .pipe_reads
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(pending) = reads.remove(&pipe_key) {
                release_pending_async_slot(&pending.conn);
                return true;
            }
        }

        let lock_key = PendingByteRangeLockKey {
            conn: conn_key,
            async_id,
        };
        let mut waits = self
            .byte_range_lock_waits
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pending) = waits.remove(&lock_key) {
            release_pending_async_slot(&pending.conn);
            return true;
        }
        false
    }

    async fn complete_cache_break_tasks(
        &self,
        mut pending: Vec<(u64, PendingCacheBreakTask)>,
    ) -> usize {
        pending.sort_by_key(|(async_id, _)| *async_id);
        let mut sent = 0;
        for (async_id, mut pending) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            let Some(completion) = pending.completion.take() else {
                continue;
            };
            let response = completion().await;
            if response.status == crate::ntstatus::STATUS_SUCCESS
                && let Some(create_guid) = pending.replay_create_guid
            {
                self.completed_create_replays
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(
                        CreateReplayKey {
                            create_guid,
                            client_guid: pending.replay_client_guid,
                            owner: pending.replay_owner.clone(),
                        },
                        response.body.clone(),
                    );
            }
            let response = HandlerResponse::final_async(async_id, response.status, response.body);
            let frame = if let Some(compound_completion) = pending.compound_completion.take() {
                compound_completion(response).await
            } else {
                dispatch::build_standalone_response_frame(&conn, &pending.req_hdr, response).await
            };
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    async fn complete_cache_break_tasks_with_status(
        &self,
        pending: Vec<(u64, PendingCacheBreakTask)>,
        status: u32,
    ) -> usize {
        let mut sent = 0;
        for (async_id, pending) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            let frame = dispatch::build_standalone_response_frame(
                &conn,
                &pending.req_hdr,
                HandlerResponse::final_async(async_id, status, HandlerResponse::err(status).body),
            )
            .await;
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub async fn cancel_cache_break_task(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let pending = {
            let mut tasks = self
                .cache_break_tasks
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = cache_break_task_key(conn, async_id);
            match tasks.get(&key) {
                Some(pending) if pending.req_hdr.session_id == session_id => tasks.remove(&key),
                _ => None,
            }
        };

        let Some(pending) = pending else {
            return false;
        };
        self.complete_cache_break_tasks_with_status(vec![(async_id, pending)], status)
            .await
            != 0
    }

    pub async fn cleanup_cache_break_tasks_for_session(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_tasks_matching(|key, pending| {
            key.conn == conn_key && pending.req_hdr.session_id == session_id
        });
        self.complete_cache_break_tasks_with_status(pending, status)
            .await
    }

    pub async fn cleanup_cache_break_tasks_for_tree(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_tasks_matching(|key, pending| {
            key.conn == conn_key
                && pending.req_hdr.session_id == session_id
                && pending.req_hdr.tree_id() == Some(tree_id)
        });
        self.complete_cache_break_tasks_with_status(pending, status)
            .await
    }

    pub fn cleanup_cache_break_tasks_for_connection(&self, conn: &Arc<Connection>) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_cache_break_tasks_matching(|key, _| key.conn == conn_key);
        for (_, pending) in &pending {
            release_pending_async_slot(&pending.conn);
        }
        pending.len()
    }

    fn take_cache_break_tasks_matching(
        &self,
        matches: impl Fn(&PendingCacheBreakTaskKey, &PendingCacheBreakTask) -> bool,
    ) -> Vec<(u64, PendingCacheBreakTask)> {
        let mut tasks = self
            .cache_break_tasks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching = tasks
            .iter()
            .filter_map(|(key, pending)| matches(key, pending).then_some(*key))
            .collect::<Vec<_>>();
        matching
            .into_iter()
            .filter_map(|key| tasks.remove(&key).map(|pending| (key.async_id, pending)))
            .collect()
    }

    async fn complete_cache_break_tasks_for_lease_key(&self, lease_key: [u8; 16]) -> usize {
        let candidates = {
            let mut tasks = self
                .cache_break_tasks
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matching = tasks
                .iter()
                .filter_map(|(key, pending)| {
                    pending.wait_lease_keys.contains(&lease_key).then_some(*key)
                })
                .collect::<Vec<_>>();
            matching
                .into_iter()
                .filter_map(|key| tasks.remove(&key).map(|pending| (key, pending)))
                .collect::<Vec<_>>()
        };

        let mut pending = Vec::new();
        let mut still_waiting = Vec::new();
        for (key, task) in candidates {
            if self.cache_break_task_still_waiting(&task).await {
                still_waiting.push((key, task));
            } else {
                pending.push((key.async_id, task));
            }
        }

        if !still_waiting.is_empty() {
            let mut tasks = self
                .cache_break_tasks
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (key, task) in still_waiting {
                tasks.insert(key, task);
            }
        }

        self.complete_cache_break_tasks(pending).await
    }

    async fn complete_cache_break_tasks_for_oplock_file_id(&self, file_id: FileId) -> usize {
        let candidates = {
            let mut tasks = self
                .cache_break_tasks
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matching = tasks
                .iter()
                .filter_map(|(key, pending)| {
                    pending
                        .wait_oplock_file_ids
                        .contains(&file_id)
                        .then_some(*key)
                })
                .collect::<Vec<_>>();
            matching
                .into_iter()
                .filter_map(|key| tasks.remove(&key).map(|pending| (key, pending)))
                .collect::<Vec<_>>()
        };

        let mut pending = Vec::new();
        let mut still_waiting = Vec::new();
        for (key, task) in candidates {
            if self.cache_break_task_still_waiting(&task).await {
                still_waiting.push((key, task));
            } else {
                pending.push((key.async_id, task));
            }
        }

        if !still_waiting.is_empty() {
            let mut tasks = self
                .cache_break_tasks
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (key, task) in still_waiting {
                tasks.insert(key, task);
            }
        }

        self.complete_cache_break_tasks(pending).await
    }

    async fn cache_break_task_still_waiting(&self, task: &PendingCacheBreakTask) -> bool {
        for lease_key in &task.wait_lease_keys {
            if self.lease_key_is_breaking(*lease_key).await {
                return true;
            }
        }
        for file_id in &task.wait_oplock_file_ids {
            if self.oplock_file_id_is_breaking(*file_id).await {
                return true;
            }
        }
        false
    }

    async fn complete_cache_break_creates_for_lease_key(&self, lease_key: [u8; 16]) -> usize {
        let candidates = {
            let mut creates = self
                .cache_break_creates
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matching = creates
                .iter()
                .filter_map(|(key, pending)| {
                    pending.wait_lease_keys.contains(&lease_key).then_some(*key)
                })
                .collect::<Vec<_>>();
            matching
                .into_iter()
                .filter_map(|key| creates.remove(&key).map(|pending| (key, pending)))
                .collect::<Vec<_>>()
        };

        let mut pending = Vec::new();
        let mut still_waiting = Vec::new();
        for (key, create) in candidates {
            if self.cache_break_create_still_waiting(&create).await {
                still_waiting.push((key, create));
            } else {
                pending.push((key.async_id, create));
            }
        }

        if !still_waiting.is_empty() {
            let mut creates = self
                .cache_break_creates
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (key, create) in still_waiting {
                creates.insert(key, create);
            }
        }

        self.complete_cache_break_creates(pending).await
    }

    async fn complete_cache_break_creates_for_oplock_file_id(&self, file_id: FileId) -> usize {
        let candidates = {
            let mut creates = self
                .cache_break_creates
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matching = creates
                .iter()
                .filter_map(|(key, pending)| {
                    pending
                        .wait_oplock_file_ids
                        .contains(&file_id)
                        .then_some(*key)
                })
                .collect::<Vec<_>>();
            matching
                .into_iter()
                .filter_map(|key| creates.remove(&key).map(|pending| (key, pending)))
                .collect::<Vec<_>>()
        };

        let mut pending = Vec::new();
        let mut still_waiting = Vec::new();
        for (key, create) in candidates {
            if self.cache_break_create_still_waiting(&create).await {
                still_waiting.push((key, create));
            } else {
                pending.push((key.async_id, create));
            }
        }

        if !still_waiting.is_empty() {
            let mut creates = self
                .cache_break_creates
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (key, create) in still_waiting {
                creates.insert(key, create);
            }
        }

        self.complete_cache_break_creates(pending).await
    }

    async fn cache_break_create_still_waiting(&self, create: &PendingCacheBreakCreate) -> bool {
        for lease_key in &create.wait_lease_keys {
            if self.lease_key_is_breaking(*lease_key).await {
                return true;
            }
        }
        for file_id in &create.wait_oplock_file_ids {
            if self.oplock_file_id_is_breaking(*file_id).await {
                return true;
            }
        }
        false
    }

    async fn lease_key_is_breaking(&self, lease_key: [u8; 16]) -> bool {
        if lease_key == [0; 16] {
            return false;
        }
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| entry.open.upgrade())
                .collect::<Vec<_>>()
        };

        for open_arc in entries {
            let open = open_arc.read().await;
            if open.lease_version != 0 && open.lease_key == lease_key && open.lease_breaking {
                return true;
            }
        }
        false
    }

    async fn oplock_file_id_is_breaking(&self, file_id: FileId) -> bool {
        let Some(open_arc) = self.open_by_file_id(file_id).await else {
            return false;
        };
        open_arc.read().await.oplock_breaking
    }

    pub(crate) async fn open_by_file_id(&self, file_id: FileId) -> Option<Arc<RwLock<Open>>> {
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| entry.open.upgrade())
                .collect::<Vec<_>>()
        };
        for open_arc in entries {
            if open_arc.read().await.file_id == file_id {
                return Some(open_arc);
            }
        }
        None
    }

    async fn open_by_file_id_for_connection(
        &self,
        conn: &Arc<Connection>,
        file_id: FileId,
    ) -> Option<Arc<RwLock<Open>>> {
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| Some((entry.open.upgrade()?, entry.conn.upgrade()?)))
                .collect::<Vec<_>>()
        };
        for (open_arc, entry_conn) in entries {
            if !Arc::ptr_eq(&entry_conn, conn) {
                continue;
            }
            if open_arc.read().await.file_id == file_id {
                return Some(open_arc);
            }
        }
        None
    }

    pub(crate) async fn cache_break_wait_has_force_unacked(
        &self,
        lease_keys: &[[u8; 16]],
        oplock_file_ids: &[FileId],
    ) -> bool {
        if lease_keys.is_empty() && oplock_file_ids.is_empty() {
            return false;
        }
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| Some((entry.open.upgrade()?, entry.conn.upgrade()?)))
                .collect::<Vec<_>>()
        };

        for (open_arc, conn) in entries {
            if !conn.force_unacked_timeout() {
                continue;
            }
            let open = open_arc.read().await;
            if open.lease_version != 0
                && open.lease_breaking
                && lease_keys.contains(&open.lease_key)
            {
                return true;
            }
            if open.oplock_breaking && oplock_file_ids.contains(&open.file_id) {
                return true;
            }
        }
        false
    }

    async fn force_complete_cache_break_leases(&self, lease_keys: &[[u8; 16]]) {
        if lease_keys.is_empty() {
            return;
        }
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| Some((entry.open.upgrade()?, entry.conn.upgrade()?)))
                .collect::<Vec<_>>()
        };

        for (open_arc, conn) in entries {
            let mut open = open_arc.write().await;
            if open.lease_version == 0
                || !open.lease_breaking
                || !lease_keys.contains(&open.lease_key)
            {
                continue;
            }
            let _ = conn.take_force_unacked_timeout();
            let target = 0;
            open.lease_state = target;
            open.lease_breaking = false;
            open.lease_break_to = 0;
            open.lease_break_final_to = target;
        }
    }

    async fn force_complete_cache_break_oplocks(&self, file_ids: &[FileId]) {
        if file_ids.is_empty() {
            return;
        }
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter_map(|entry| Some((entry.open.upgrade()?, entry.conn.upgrade()?)))
                .collect::<Vec<_>>()
        };

        for (open_arc, conn) in entries {
            let (file_id, should_force_close, target_level) = {
                let open = open_arc.read().await;
                if !file_ids.contains(&open.file_id) || !open.oplock_breaking {
                    continue;
                }
                (
                    open.file_id,
                    conn.take_force_unacked_timeout(),
                    open.oplock_break_to,
                )
            };
            if should_force_close {
                self.force_close_open_on_connection(&conn, file_id).await;
                continue;
            }
            let mut open = open_arc.write().await;
            open.oplock_level = target_level;
            open.oplock_breaking = false;
            open.oplock_break_to = OPLOCK_NONE;
        }
    }

    async fn force_close_open_on_connection(&self, conn: &Arc<Connection>, file_id: FileId) {
        let sessions = conn
            .sessions
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut removed = None;
        for session in sessions {
            let trees = {
                let session = session.read().await;
                session
                    .trees
                    .read()
                    .await
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
            };
            for tree in trees {
                let candidate = {
                    let tree = tree.write().await;
                    tree.opens.write().await.remove(&file_id)
                };
                if candidate.is_some() {
                    removed = candidate;
                    break;
                }
            }
            if removed.is_some() {
                break;
            }
        }

        self.remove_durable_open(file_id);
        if let Some(open_arc) = removed {
            let mut open = open_arc.write().await;
            if let Some(handle) = open.handle.take() {
                let _ = handle.close().await;
            }
            open.oplock_breaking = false;
            open.oplock_break_to = OPLOCK_NONE;
        }
    }

    pub async fn notify_child_added(&self, share: &str, path: &SmbPath, is_directory: bool) {
        const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
        const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
        const FILE_ACTION_ADDED: u32 = 0x0000_0001;

        let Some(parent) = path.parent() else {
            return;
        };
        let share_key = share.to_ascii_lowercase();
        let wanted_filter = if is_directory {
            FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            FILE_NOTIFY_CHANGE_FILE_NAME
        };

        let pending = self
            .queue_direct_change_notify_events(
                &share_key,
                wanted_filter,
                path,
                &parent,
                true,
                |_| true,
                |pending| {
                    vec![NotifyEvent {
                        action: FILE_ACTION_ADDED,
                        name: notify_relative_name(&pending.path, path),
                        is_directory,
                    }]
                },
                |_| true,
                |open| {
                    vec![NotifyEvent {
                        action: FILE_ACTION_ADDED,
                        name: notify_relative_name(&open.last_path, path),
                        is_directory,
                    }]
                },
            )
            .await;

        for (async_id, pending, output) in pending {
            self.complete_file_notify_output(async_id, pending, output)
                .await;
        }
    }

    pub async fn forward_backend_change_notify_watch(
        self: Arc<Self>,
        conn: Arc<Connection>,
        async_id: u64,
        mut watch: crate::backend::BackendWatch,
        mut cancel: oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = &mut cancel => break,
                event = watch.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    if !self.complete_backend_watch_event(&conn, async_id, event).await {
                        break;
                    }
                }
            }
        }
    }

    async fn complete_backend_watch_event(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        event: WatchEvent,
    ) -> bool {
        let key = change_notify_key(conn, async_id);
        let (pending, completion) = {
            let mut notifies = self
                .change_notifies
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(pending) = notifies.get(&key) else {
                return false;
            };
            let Some(completion) = backend_watch_completion(pending, &event) else {
                return true;
            };
            let pending = notifies.remove(&key).expect("pending notify vanished");
            (pending, completion)
        };

        match completion {
            BackendWatchCompletion::DeletePending => {
                self.complete_change_notifies(vec![(async_id, pending)], |_, _| {
                    (ntstatus::STATUS_DELETE_PENDING, Vec::new())
                })
                .await;
            }
            BackendWatchCompletion::Output(output) => {
                self.complete_file_notify_output(async_id, pending, output)
                    .await;
            }
        }
        false
    }

    pub async fn notify_renamed(
        &self,
        share: &str,
        from: &SmbPath,
        to: &SmbPath,
        is_directory: bool,
    ) {
        const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
        const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
        const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
        const FILE_ACTION_ADDED: u32 = 0x0000_0001;
        const FILE_ACTION_REMOVED: u32 = 0x0000_0002;
        const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x0000_0004;
        const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x0000_0005;
        const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;

        let Some(from_parent) = from.parent() else {
            return;
        };
        let Some(to_parent) = to.parent() else {
            return;
        };
        let same_parent = to_parent == from_parent;
        let share_key = share.to_ascii_lowercase();
        let wanted_filter = if is_directory {
            FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            FILE_NOTIFY_CHANGE_FILE_NAME
        };

        if same_parent {
            let pending = self
                .queue_direct_change_notify_events(
                    &share_key,
                    wanted_filter,
                    from,
                    &from_parent,
                    true,
                    |_| true,
                    |pending| {
                        vec![
                            NotifyEvent {
                                action: FILE_ACTION_RENAMED_OLD_NAME,
                                name: notify_relative_name(&pending.path, from),
                                is_directory,
                            },
                            NotifyEvent {
                                action: FILE_ACTION_RENAMED_NEW_NAME,
                                name: notify_relative_name(&pending.path, to),
                                is_directory,
                            },
                        ]
                    },
                    |_| true,
                    |open| {
                        vec![
                            NotifyEvent {
                                action: FILE_ACTION_RENAMED_OLD_NAME,
                                name: notify_relative_name(&open.last_path, from),
                                is_directory,
                            },
                            NotifyEvent {
                                action: FILE_ACTION_RENAMED_NEW_NAME,
                                name: notify_relative_name(&open.last_path, to),
                                is_directory,
                            },
                        ]
                    },
                )
                .await;

            for (async_id, pending, output) in pending {
                self.complete_file_notify_output(async_id, pending, output)
                    .await;
            }
        } else {
            let pending = self
                .queue_direct_change_notify_events(
                    &share_key,
                    wanted_filter,
                    from,
                    &from_parent,
                    true,
                    |_| true,
                    |pending| {
                        vec![
                            NotifyEvent {
                                action: FILE_ACTION_REMOVED,
                                name: notify_relative_name(&pending.path, from),
                                is_directory,
                            },
                            NotifyEvent {
                                action: FILE_ACTION_ADDED,
                                name: notify_relative_name(&pending.path, to),
                                is_directory,
                            },
                        ]
                    },
                    |_| true,
                    |open| {
                        vec![
                            NotifyEvent {
                                action: FILE_ACTION_REMOVED,
                                name: notify_relative_name(&open.last_path, from),
                                is_directory,
                            },
                            NotifyEvent {
                                action: FILE_ACTION_ADDED,
                                name: notify_relative_name(&open.last_path, to),
                                is_directory,
                            },
                        ]
                    },
                )
                .await;

            for (async_id, pending, output) in pending {
                self.complete_file_notify_output(async_id, pending, output)
                    .await;
            }
        }

        if !is_directory {
            let attr_pending = self
                .queue_direct_change_notify_events(
                    &share_key,
                    FILE_NOTIFY_CHANGE_ATTRIBUTES,
                    if same_parent { to } else { from },
                    if same_parent {
                        &to_parent
                    } else {
                        &from_parent
                    },
                    false,
                    |pending| !notify_filter_matches(pending.completion_filter, wanted_filter),
                    |pending| {
                        vec![NotifyEvent {
                            action: FILE_ACTION_MODIFIED,
                            name: notify_relative_name(&pending.path, to),
                            is_directory,
                        }]
                    },
                    |open| !notify_filter_matches(open.notify_completion_filter, wanted_filter),
                    |open| {
                        vec![NotifyEvent {
                            action: FILE_ACTION_MODIFIED,
                            name: notify_relative_name(&open.last_path, to),
                            is_directory,
                        }]
                    },
                )
                .await;

            for (async_id, pending, output) in attr_pending {
                self.complete_file_notify_output(async_id, pending, output)
                    .await;
            }
        }
    }

    pub async fn notify_data_modified(&self, share: &str, path: &SmbPath, is_directory: bool) {
        const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
        const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;

        self.notify_modified(
            share,
            path,
            is_directory,
            FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
        )
        .await;
    }

    pub async fn notify_attributes_modified(
        &self,
        share: &str,
        path: &SmbPath,
        is_directory: bool,
    ) {
        const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;

        self.notify_modified(share, path, is_directory, FILE_NOTIFY_CHANGE_ATTRIBUTES)
            .await;
    }

    pub async fn notify_security_modified(&self, share: &str, path: &SmbPath, is_directory: bool) {
        const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;

        self.notify_modified(share, path, is_directory, FILE_NOTIFY_CHANGE_SECURITY)
            .await;
    }

    async fn notify_modified(
        &self,
        share: &str,
        path: &SmbPath,
        is_directory: bool,
        wanted_filter: u32,
    ) {
        const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;

        let Some(parent) = path.parent() else {
            return;
        };
        let share_key = share.to_ascii_lowercase();

        let pending = self
            .queue_direct_change_notify_events(
                &share_key,
                wanted_filter,
                path,
                &parent,
                true,
                |pending| !(is_directory && path == &pending.path),
                |pending| {
                    vec![NotifyEvent {
                        action: FILE_ACTION_MODIFIED,
                        name: notify_relative_name(&pending.path, path),
                        is_directory,
                    }]
                },
                |open| !(is_directory && path == &open.last_path),
                |open| {
                    vec![NotifyEvent {
                        action: FILE_ACTION_MODIFIED,
                        name: notify_relative_name(&open.last_path, path),
                        is_directory,
                    }]
                },
            )
            .await;

        for (async_id, pending, output) in pending {
            self.complete_file_notify_output(async_id, pending, output)
                .await;
        }
    }

    pub async fn notify_removed(&self, share: &str, path: &SmbPath, is_directory: bool) {
        const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
        const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
        const FILE_ACTION_REMOVED: u32 = 0x0000_0002;

        let Some(parent) = path.parent() else {
            return;
        };
        let share_key = share.to_ascii_lowercase();
        let wanted_filter = if is_directory {
            FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            FILE_NOTIFY_CHANGE_FILE_NAME
        };

        let pending = self
            .queue_direct_change_notify_events(
                &share_key,
                wanted_filter,
                path,
                &parent,
                true,
                |_| true,
                |pending| {
                    vec![NotifyEvent {
                        action: FILE_ACTION_REMOVED,
                        name: notify_relative_name(&pending.path, path),
                        is_directory,
                    }]
                },
                |_| true,
                |open| {
                    vec![NotifyEvent {
                        action: FILE_ACTION_REMOVED,
                        name: notify_relative_name(&open.last_path, path),
                        is_directory,
                    }]
                },
            )
            .await;

        for (async_id, pending, output) in pending {
            self.complete_file_notify_output(async_id, pending, output)
                .await;
        }
    }

    async fn queue_direct_change_notify_events(
        &self,
        share_key: &str,
        wanted_filter: u32,
        path: &SmbPath,
        parent: &SmbPath,
        coalesce: bool,
        include_pending: impl Fn(&PendingChangeNotify) -> bool,
        pending_events: impl Fn(&PendingChangeNotify) -> Vec<NotifyEvent>,
        include_open: impl Fn(&Open) -> bool,
        open_events: impl Fn(&Open) -> Vec<NotifyEvent>,
    ) -> Vec<(u64, PendingChangeNotify, Vec<u8>)> {
        let (pending, scheduled, delivered_opens, suppress_opens) = {
            let mut notifies = self
                .change_notifies
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matching: Vec<PendingChangeNotifyKey> = notifies
                .iter()
                .filter_map(|(key, pending)| {
                    (pending.share == share_key
                        && include_pending(pending)
                        && notify_filter_matches(pending.completion_filter, wanted_filter)
                        && notify_watch_matches(&pending.path, pending.recursive, path, parent))
                    .then_some(*key)
                })
                .collect();
            let mut immediate = Vec::new();
            let mut scheduled = Vec::new();
            let mut delivered_opens = HashSet::new();
            let mut suppress_opens = Vec::new();
            for key in matching {
                let Some(pending) = notifies.get_mut(&key) else {
                    continue;
                };
                delivered_opens.insert(pending.open.as_ptr() as usize);
                let events = pending_events(pending);
                if !coalesce || pending.output_buffer_length == 0 || pending.notify_force_enum_dir {
                    if pending.output_buffer_length == 0 || pending.notify_force_enum_dir {
                        suppress_opens.push(pending.open.clone());
                    }
                    if let Some(pending) = notifies.remove(&key) {
                        immediate.push((key.async_id, pending, encode_file_notify_events(&events)));
                    }
                    continue;
                }
                pending.notify_events.extend(events);
                if !pending.notify_completion_scheduled {
                    pending.notify_completion_scheduled = true;
                    scheduled.push(key);
                }
            }
            (immediate, scheduled, delivered_opens, suppress_opens)
        };

        for key in scheduled {
            self.schedule_change_notify_completion(key);
        }
        for open in suppress_opens {
            if let Some(open) = open.upgrade() {
                open.write().await.notify_buffer_suppressed = true;
            }
        }
        self.buffer_direct_change_notify_events(
            share_key,
            wanted_filter,
            path,
            parent,
            &delivered_opens,
            include_open,
            open_events,
        )
        .await;
        pending
    }

    async fn buffer_direct_change_notify_events(
        &self,
        share_key: &str,
        wanted_filter: u32,
        path: &SmbPath,
        parent: &SmbPath,
        delivered_opens: &HashSet<usize>,
        include_open: impl Fn(&Open) -> bool,
        open_events: impl Fn(&Open) -> Vec<NotifyEvent>,
    ) {
        let entries = self
            .open_registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for entry in entries {
            let open_key = entry.open.as_ptr() as usize;
            if entry.share != share_key || delivered_opens.contains(&open_key) {
                continue;
            }
            let Some(open_arc) = entry.open.upgrade() else {
                continue;
            };
            let mut open = open_arc.write().await;
            if !open.is_directory
                || !open.notify_started
                || open.notify_buffer_suppressed
                || !include_open(&open)
                || !notify_filter_matches(open.notify_completion_filter, wanted_filter)
                || !(open.last_path == *parent || path_is_descendant(path, &open.last_path))
            {
                continue;
            }
            let events = open_events(&open);
            open.notify_buffer.extend(events);
        }
    }

    fn schedule_change_notify_completion(&self, key: PendingChangeNotifyKey) {
        let notifies = Arc::clone(&self.change_notifies);
        tokio::spawn(async move {
            tokio::time::sleep(CHANGE_NOTIFY_COALESCE_DELAY).await;
            let pending = {
                let mut notifies = notifies
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                notifies.remove(&key)
            };
            if let Some(pending) = pending {
                let output = encode_file_notify_events(&pending.notify_events);
                ServerState::complete_file_notify_output_for_pending(key.async_id, pending, output)
                    .await;
            }
        });
    }

    async fn complete_file_notify_output(
        &self,
        async_id: u64,
        pending: PendingChangeNotify,
        output: Vec<u8>,
    ) -> usize {
        Self::complete_file_notify_output_for_pending(async_id, pending, output).await
    }

    async fn complete_file_notify_output_for_pending(
        async_id: u64,
        pending: PendingChangeNotify,
        output: Vec<u8>,
    ) -> usize {
        let (status, output) = if !pending.notify_force_enum_dir
            && pending.output_buffer_length > 0
            && output.len() <= pending.output_buffer_length as usize
        {
            (ntstatus::STATUS_SUCCESS, output)
        } else {
            if let Some(open) = pending.open.upgrade() {
                let mut open = open.write().await;
                open.notify_buffer_suppressed = true;
                if pending.notify_first && !pending.notify_force_enum_dir {
                    open.notify_enum_dir = true;
                }
            }
            (ntstatus::STATUS_NOTIFY_ENUM_DIR, Vec::new())
        };
        Self::complete_change_notify_response(async_id, pending, status, output).await
    }

    async fn complete_change_notifies(
        &self,
        pending: Vec<(u64, PendingChangeNotify)>,
        response: impl Fn(u64, &PendingChangeNotify) -> (u32, Vec<u8>),
    ) -> usize {
        let mut sent = 0;
        for (async_id, pending) in pending {
            let (status, output) = response(async_id, &pending);
            if Self::complete_change_notify_response(async_id, pending, status, output).await != 0 {
                sent += 1;
            }
        }
        sent
    }

    async fn complete_change_notify_response(
        async_id: u64,
        mut pending: PendingChangeNotify,
        status: u32,
        output: Vec<u8>,
    ) -> usize {
        release_pending_async_slot(&pending.conn);
        if let Some(cancel) = pending.watch_cancel.take() {
            let _ = cancel.send(());
        }
        let Some(conn) = pending.conn.upgrade() else {
            return 0;
        };
        let body = encode_change_notify_response_body(&output);
        let frame = dispatch::build_standalone_response_frame(
            &conn,
            &pending.req_hdr,
            HandlerResponse::final_async(async_id, status, body),
        )
        .await;
        usize::from(pending.tx.send(frame).await.is_ok())
    }

    pub async fn cancel_change_notify(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let pending = {
            let mut notifies = self
                .change_notifies
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = change_notify_key(conn, async_id);
            match notifies.get(&key) {
                Some(pending) if pending.req_hdr.session_id == session_id => notifies.remove(&key),
                _ => None,
            }
        };

        let Some(pending) = pending else {
            return false;
        };
        self.complete_change_notifies(vec![(async_id, pending)], |_, _| (status, Vec::new()))
            .await
            != 0
    }

    pub async fn cancel_change_notify_by_message_id(
        &self,
        conn: &Arc<Connection>,
        message_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = {
            let mut notifies = self
                .change_notifies
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = notifies.iter().find_map(|(key, pending)| {
                (key.conn == conn_key
                    && pending.req_hdr.session_id == session_id
                    && pending.req_hdr.message_id == message_id)
                    .then_some(*key)
            });
            key.and_then(|key| notifies.remove(&key).map(|pending| (key.async_id, pending)))
        };

        let Some((async_id, pending)) = pending else {
            return false;
        };
        self.complete_change_notifies(vec![(async_id, pending)], |_, _| (status, Vec::new()))
            .await
            != 0
    }

    async fn complete_pipe_reads(
        &self,
        pending: Vec<(u64, PendingPipeRead)>,
        status: u32,
    ) -> usize {
        let mut sent = 0;
        for (async_id, pending) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            let body = HandlerResponse::err(status).body;
            let frame = dispatch::build_standalone_response_frame(
                &conn,
                &pending.req_hdr,
                HandlerResponse::final_async(async_id, status, body),
            )
            .await;
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub async fn cancel_pipe_read(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let pending = {
            let mut reads = self
                .pipe_reads
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = pipe_read_key(conn, async_id);
            match reads.get(&key) {
                Some(pending) if pending.req_hdr.session_id == session_id => reads.remove(&key),
                _ => None,
            }
        };

        let Some(pending) = pending else {
            return false;
        };
        self.complete_pipe_reads(vec![(async_id, pending)], status)
            .await
            != 0
    }

    pub async fn cleanup_pipe_reads_for_session(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_pipe_reads_matching(|key, pending| {
            key.conn == conn_key && pending.req_hdr.session_id == session_id
        });
        self.complete_pipe_reads(pending, status).await
    }

    pub async fn cleanup_pipe_reads_for_tree(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_pipe_reads_matching(|key, pending| {
            key.conn == conn_key
                && pending.req_hdr.session_id == session_id
                && pending.req_hdr.tree_id() == Some(tree_id)
        });
        self.complete_pipe_reads(pending, status).await
    }

    pub async fn cleanup_pipe_reads_for_file(
        &self,
        conn: &Arc<Connection>,
        file_id: FileId,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_pipe_reads_matching(|key, pending| {
            key.conn == conn_key && pending.file_id == file_id
        });
        self.complete_pipe_reads(pending, status).await
    }

    async fn complete_byte_range_lock_waits(
        &self,
        pending: Vec<(u64, PendingByteRangeLock, u32)>,
    ) -> usize {
        let mut sent = 0;
        for (async_id, pending, status) in pending {
            release_pending_async_slot(&pending.conn);
            let Some(conn) = pending.conn.upgrade() else {
                continue;
            };
            let body = if status == ntstatus::STATUS_SUCCESS {
                let mut body = Vec::new();
                crate::proto::messages::LockResponse::default()
                    .write_to(&mut body)
                    .expect("encode lock response");
                body
            } else {
                HandlerResponse::err(status).body
            };
            let frame = dispatch::build_standalone_response_frame(
                &conn,
                &pending.req_hdr,
                HandlerResponse::final_async(async_id, status, body),
            )
            .await;
            if pending.tx.send(frame).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub async fn cancel_byte_range_lock_wait(
        &self,
        conn: &Arc<Connection>,
        async_id: u64,
        session_id: u64,
        status: u32,
    ) -> bool {
        let pending = {
            let mut waits = self
                .byte_range_lock_waits
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = byte_range_lock_wait_key(conn, async_id);
            match waits.get(&key) {
                Some(pending) if pending.req_hdr.session_id == session_id => waits.remove(&key),
                _ => None,
            }
        };

        let Some(pending) = pending else {
            return false;
        };
        self.complete_byte_range_lock_waits(vec![(async_id, pending, status)])
            .await
            != 0
    }

    pub async fn cleanup_byte_range_lock_waits_for_session(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_byte_range_lock_waits_matching(|key, pending| {
            key.conn == conn_key && pending.req_hdr.session_id == session_id
        });
        let status = cleanup_status_for_byte_range_lock_wait(status);
        self.complete_byte_range_lock_waits(
            pending
                .into_iter()
                .map(|(async_id, pending)| (async_id, pending, status))
                .collect(),
        )
        .await
    }

    pub async fn cleanup_byte_range_lock_waits_for_tree(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_byte_range_lock_waits_matching(|key, pending| {
            key.conn == conn_key
                && pending.req_hdr.session_id == session_id
                && pending.req_hdr.tree_id() == Some(tree_id)
        });
        let status = cleanup_status_for_byte_range_lock_wait(status);
        self.complete_byte_range_lock_waits(
            pending
                .into_iter()
                .map(|(async_id, pending)| (async_id, pending, status))
                .collect(),
        )
        .await
    }

    pub async fn cleanup_byte_range_lock_waits_for_file(
        &self,
        conn: &Arc<Connection>,
        file_id: FileId,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_byte_range_lock_waits_matching(|key, pending| {
            key.conn == conn_key && pending.file_id == file_id
        });
        let status = cleanup_status_for_byte_range_lock_wait(status);
        self.complete_byte_range_lock_waits(
            pending
                .into_iter()
                .map(|(async_id, pending)| (async_id, pending, status))
                .collect(),
        )
        .await
    }

    pub async fn cleanup_change_notifies_for_session(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_change_notifies_matching(|key, pending| {
            key.conn == conn_key && pending.req_hdr.session_id == session_id
        });
        self.complete_change_notifies(pending, |_, _| (status, Vec::new()))
            .await
    }

    pub async fn cleanup_change_notifies_for_session_id(
        &self,
        session_id: u64,
        status: u32,
    ) -> usize {
        let pending = self
            .take_change_notifies_matching(|_, pending| pending.req_hdr.session_id == session_id);
        self.complete_change_notifies(pending, |_, _| (status, Vec::new()))
            .await
    }

    pub async fn cleanup_change_notifies_for_tree(
        &self,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_change_notifies_matching(|key, pending| {
            key.conn == conn_key
                && pending.req_hdr.session_id == session_id
                && pending.req_hdr.tree_id() == Some(tree_id)
        });
        self.complete_change_notifies(pending, |_, _| (status, Vec::new()))
            .await
    }

    pub async fn cleanup_change_notifies_for_file(
        &self,
        conn: &Arc<Connection>,
        file_id: FileId,
        status: u32,
    ) -> usize {
        let conn_key = Arc::as_ptr(conn) as usize;
        let pending = self.take_change_notifies_matching(|key, pending| {
            key.conn == conn_key && pending.file_id == file_id
        });
        self.complete_change_notifies(pending, |_, _| (status, Vec::new()))
            .await
    }

    pub async fn cleanup_change_notifies_for_deleted_path(
        &self,
        share: &str,
        path: &SmbPath,
        status: u32,
    ) -> usize {
        let share_key = share.to_ascii_lowercase();
        let pending = self.take_change_notifies_matching(|_, pending| {
            pending.share == share_key
                && (pending.path == *path || path_is_descendant(&pending.path, path))
        });
        self.complete_change_notifies(pending, |_, _| (status, Vec::new()))
            .await
    }

    fn take_change_notifies_matching(
        &self,
        matches: impl Fn(&PendingChangeNotifyKey, &PendingChangeNotify) -> bool,
    ) -> Vec<(u64, PendingChangeNotify)> {
        let mut notifies = self
            .change_notifies
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching = notifies
            .iter()
            .filter_map(|(key, pending)| matches(key, pending).then_some(*key))
            .collect::<Vec<_>>();
        matching
            .into_iter()
            .filter_map(|key| notifies.remove(&key).map(|pending| (key.async_id, pending)))
            .collect()
    }

    fn take_pipe_reads_matching(
        &self,
        matches: impl Fn(&PendingPipeReadKey, &PendingPipeRead) -> bool,
    ) -> Vec<(u64, PendingPipeRead)> {
        let mut reads = self
            .pipe_reads
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching = reads
            .iter()
            .filter_map(|(key, pending)| matches(key, pending).then_some(*key))
            .collect::<Vec<_>>();
        matching
            .into_iter()
            .filter_map(|key| reads.remove(&key).map(|pending| (key.async_id, pending)))
            .collect()
    }

    fn take_byte_range_lock_waits_matching(
        &self,
        matches: impl Fn(&PendingByteRangeLockKey, &PendingByteRangeLock) -> bool,
    ) -> Vec<(u64, PendingByteRangeLock)> {
        let mut waits = self
            .byte_range_lock_waits
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matching = waits
            .iter()
            .filter_map(|(key, pending)| matches(key, pending).then_some(*key))
            .collect::<Vec<_>>();
        matching
            .into_iter()
            .filter_map(|key| waits.remove(&key).map(|pending| (key.async_id, pending)))
            .collect()
    }

    pub async fn share_conflicts(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        desired_access: u32,
        share_access: u32,
    ) -> bool {
        let share = share.to_ascii_lowercase();
        let stream_name = stream_name.map(str::to_ascii_lowercase);
        let entries: Vec<_> = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share && entry.path == *path && entry.stream_name == stream_name
                })
                .filter_map(|entry| entry.open.upgrade())
                .collect()
        };

        for open_arc in entries {
            let open = open_arc.read().await;
            if (share_enforced_by_access(desired_access)
                && share_conflict(open.desired_access, share_access))
                || (share_enforced_by_access(open.desired_access)
                    && share_conflict(desired_access, open.share_access))
            {
                return true;
            }
        }
        false
    }

    pub async fn delete_sharing_conflict(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        except: Option<&Arc<RwLock<Open>>>,
    ) -> bool {
        let share_key = share.to_ascii_lowercase();
        let entries = if let Some(stream_name) = stream_name {
            let stream_name = stream_name.to_ascii_lowercase();
            self.live_open_stream_entries(&share_key, path, Some(&stream_name))
        } else {
            self.live_open_entries(&share_key, path)
        };

        for open_arc in entries {
            if except.is_some_and(|except| Arc::ptr_eq(&open_arc, except)) {
                continue;
            }
            let open = open_arc.read().await;
            if access_is_lease_stat_open(open.desired_access) {
                continue;
            }
            if open.share_access & FILE_SHARE_DELETE == 0 {
                return true;
            }
        }
        false
    }

    pub async fn named_stream_open_on_base(
        &self,
        share: &str,
        path: &SmbPath,
        except: Option<&Arc<RwLock<Open>>>,
    ) -> bool {
        let share_key = share.to_ascii_lowercase();
        for open_arc in self.live_open_entries(&share_key, path) {
            if except.is_some_and(|except| Arc::ptr_eq(&open_arc, except)) {
                continue;
            }
            if open_arc.read().await.stream_name.is_some() {
                return true;
            }
        }
        false
    }

    pub async fn open_delete_pending(&self, share: &str, path: &SmbPath) -> bool {
        let share_key = share.to_ascii_lowercase();
        let key = PosixKey::new(&share_key, path);
        let marked_delete_pending = self
            .delete_pending
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key);

        let entries = self.live_open_entries(&share_key, path);
        if marked_delete_pending {
            if entries.is_empty() {
                self.delete_pending
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&key);
            } else {
                return true;
            }
        }

        for open_arc in entries {
            let open = open_arc.read().await;
            if open.delete_on_close {
                return true;
            }
        }
        false
    }

    pub async fn has_other_open(
        &self,
        share: &str,
        path: &SmbPath,
        except: &Arc<RwLock<Open>>,
    ) -> bool {
        let share_key = share.to_ascii_lowercase();
        let entries = self.live_open_entries(&share_key, path);
        entries
            .into_iter()
            .any(|open_arc| !Arc::ptr_eq(&open_arc, except))
    }

    pub async fn has_other_open_under_directory(
        &self,
        share: &str,
        directory: &SmbPath,
        except: &Arc<RwLock<Open>>,
    ) -> bool {
        let share_key = share.to_ascii_lowercase();
        let entries = {
            let mut registry = self
                .open_registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|entry| entry.open.strong_count() > 0);
            registry
                .iter()
                .filter(|entry| {
                    entry.share == share_key && path_is_descendant(&entry.path, directory)
                })
                .filter_map(|entry| entry.open.upgrade())
                .collect::<Vec<_>>()
        };
        entries
            .into_iter()
            .any(|open_arc| !Arc::ptr_eq(&open_arc, except))
    }

    pub async fn rename_parent_delete_conflict(
        &self,
        share: &str,
        from: &SmbPath,
        to: &SmbPath,
        except: &Arc<RwLock<Open>>,
    ) -> bool {
        const DELETE: u32 = 0x0001_0000;

        let share_key = share.to_ascii_lowercase();
        let mut parents = Vec::new();
        if let Some(parent) = from.parent()
            && !parent.is_root()
        {
            parents.push(parent);
        }
        if let Some(parent) = to.parent()
            && !parent.is_root()
            && !parents.contains(&parent)
        {
            parents.push(parent);
        }

        for parent in parents {
            for open_arc in self.live_open_entries(&share_key, &parent) {
                if Arc::ptr_eq(&open_arc, except) {
                    continue;
                }
                let open = open_arc.read().await;
                if open.desired_access & DELETE != 0 {
                    return true;
                }
            }
        }
        false
    }

    pub fn mark_delete_pending(&self, share: &str, path: &SmbPath) {
        let share_key = share.to_ascii_lowercase();
        self.delete_pending
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(PosixKey::new(&share_key, path), true);
    }

    pub fn clear_delete_pending(&self, share: &str, path: &SmbPath) {
        let share_key = share.to_ascii_lowercase();
        self.delete_pending
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(&share_key, path));
    }

    pub async fn mark_posix_deleted_opens(&self, share: &str, path: &SmbPath) {
        let share_key = share.to_ascii_lowercase();
        for open_arc in self.live_open_entries(&share_key, path) {
            let mut open = open_arc.write().await;
            open.posix_deleted = true;
        }
    }

    pub async fn take_delete_pending_if_last(
        &self,
        share: &str,
        path: &SmbPath,
        except: &Arc<RwLock<Open>>,
    ) -> bool {
        if self.has_other_open(share, path, except).await {
            return false;
        }
        let share_key = share.to_ascii_lowercase();
        self.delete_pending
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(&share_key, path))
            .is_some()
    }

    fn live_open_entries(&self, share_key: &str, path: &SmbPath) -> Vec<Arc<RwLock<Open>>> {
        let mut registry = self
            .open_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.retain(|entry| entry.open.strong_count() > 0);
        registry
            .iter()
            .filter(|entry| entry.share == share_key && entry.path == *path)
            .filter_map(|entry| entry.open.upgrade())
            .collect()
    }

    fn live_open_stream_entries(
        &self,
        share_key: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
    ) -> Vec<Arc<RwLock<Open>>> {
        let mut registry = self
            .open_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.retain(|entry| entry.open.strong_count() > 0);
        registry
            .iter()
            .filter(|entry| {
                entry.share == share_key
                    && entry.path == *path
                    && entry.stream_name.as_deref() == stream_name
            })
            .filter_map(|entry| entry.open.upgrade())
            .collect()
    }

    pub fn apply_byte_range_locks(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        locks: &[ByteRangeLockRequest],
    ) -> u32 {
        if locks.is_empty() {
            return crate::ntstatus::STATUS_INVALID_PARAMETER;
        }
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let mut table = self
            .byte_range_locks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut added = Vec::new();
        for lock in locks {
            let next = ByteRangeLock {
                fid: lock.fid,
                offset: lock.offset,
                length: lock.length,
                exclusive: lock.exclusive,
            };
            if lock_conflicts(table.get(&key).map(Vec::as_slice).unwrap_or(&[]), &next) {
                if !added.is_empty()
                    && let Some(existing) = table.get_mut(&key)
                {
                    existing.retain(|held| {
                        !added.iter().any(|added: &ByteRangeLock| {
                            held.fid == added.fid
                                && held.offset == added.offset
                                && held.length == added.length
                                && held.exclusive == added.exclusive
                        })
                    });
                    if existing.is_empty() {
                        table.remove(&key);
                    }
                }
                return crate::ntstatus::STATUS_LOCK_NOT_GRANTED;
            }
            table.entry(key.clone()).or_default().push(next.clone());
            added.push(next);
        }
        crate::ntstatus::STATUS_SUCCESS
    }

    pub fn unlock_byte_ranges(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        fid: crate::proto::messages::FileId,
        ranges: &[(u64, u64)],
    ) -> u32 {
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let mut table = self
            .byte_range_locks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (offset, length) in ranges {
            let Some(locks) = table.get_mut(&key) else {
                return crate::ntstatus::STATUS_RANGE_NOT_LOCKED;
            };
            let Some(index) = locks.iter().position(|lock| {
                lock.fid == fid && lock.offset == *offset && lock.length == *length
            }) else {
                return crate::ntstatus::STATUS_RANGE_NOT_LOCKED;
            };
            locks.remove(index);
            if locks.is_empty() {
                table.remove(&key);
            }
        }
        crate::ntstatus::STATUS_SUCCESS
    }

    pub async fn try_complete_byte_range_lock_waits(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
    ) -> usize {
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let pending = self.take_byte_range_lock_waits_matching(|_, pending| {
            ByteRangeLockKey::new(
                &pending.share,
                &pending.path,
                pending.stream_name.as_deref(),
            ) == key
        });
        if pending.is_empty() {
            return 0;
        }

        let mut completed = Vec::new();
        let mut still_waiting = Vec::new();
        for (async_id, pending) in pending {
            let status = self.apply_byte_range_locks(
                &pending.share,
                &pending.path,
                pending.stream_name.as_deref(),
                &pending.locks,
            );
            if status == crate::ntstatus::STATUS_LOCK_NOT_GRANTED {
                still_waiting.push((async_id, pending));
            } else {
                if status == crate::ntstatus::STATUS_SUCCESS
                    && let Some(open) = pending.open.upgrade()
                {
                    open.write()
                        .await
                        .record_lock_sequence(pending.dialect, pending.lock_sequence);
                }
                completed.push((async_id, pending, status));
            }
        }

        if !still_waiting.is_empty() {
            let mut waits = self
                .byte_range_lock_waits
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (async_id, pending) in still_waiting {
                if let Some(conn) = pending.conn.upgrade() {
                    waits.insert(byte_range_lock_wait_key(&conn, async_id), pending);
                }
            }
        }

        self.complete_byte_range_lock_waits(completed).await
    }

    pub fn check_read_lock(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        fid: crate::proto::messages::FileId,
        offset: u64,
        length: u64,
    ) -> u32 {
        if length == 0 {
            return crate::ntstatus::STATUS_SUCCESS;
        }
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let table = self
            .byte_range_locks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for lock in table.get(&key).map(Vec::as_slice).unwrap_or(&[]) {
            if lock.fid != fid
                && lock.exclusive
                && ranges_overlap(lock.offset, lock.length, offset, length)
            {
                return crate::ntstatus::STATUS_FILE_LOCK_CONFLICT;
            }
        }
        crate::ntstatus::STATUS_SUCCESS
    }

    pub fn check_write_lock(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        fid: crate::proto::messages::FileId,
        offset: u64,
        length: u64,
    ) -> u32 {
        if length == 0 {
            return crate::ntstatus::STATUS_SUCCESS;
        }
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let table = self
            .byte_range_locks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for lock in table.get(&key).map(Vec::as_slice).unwrap_or(&[]) {
            if ranges_overlap(lock.offset, lock.length, offset, length)
                && (lock.fid != fid || !lock.exclusive)
            {
                return crate::ntstatus::STATUS_FILE_LOCK_CONFLICT;
            }
        }
        crate::ntstatus::STATUS_SUCCESS
    }

    pub fn remove_byte_range_locks(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        fid: crate::proto::messages::FileId,
    ) {
        let key = ByteRangeLockKey::new(share, path, stream_name);
        let mut table = self
            .byte_range_locks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(locks) = table.get_mut(&key) else {
            return;
        };
        locks.retain(|lock| lock.fid != fid);
        if locks.is_empty() {
            table.remove(&key);
        }
    }

    pub fn has_backed_byte_range_locks(
        &self,
        share: &str,
        path: &SmbPath,
        stream_name: Option<&str>,
        end_of_file: u64,
    ) -> bool {
        if end_of_file == 0 {
            return false;
        }
        let key = ByteRangeLockKey::new(share, path, stream_name);
        self.byte_range_locks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .is_some_and(|locks| {
                locks
                    .iter()
                    .any(|lock| lock.length != 0 && lock.offset < end_of_file)
            })
    }

    fn rekey_byte_range_locks(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        let share_key = share.to_ascii_lowercase();
        let from_path = from.display_backslash().to_ascii_lowercase();
        let to_path = to.display_backslash().to_ascii_lowercase();
        let mut table = self
            .byte_range_locks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys = table
            .keys()
            .filter_map(|key| {
                if key.share == share_key {
                    rebase_lowercase_path(&key.path, &from_path, &to_path)
                        .map(|renamed_path| (key.clone(), renamed_path))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (key, renamed_path) in keys {
            let Some(locks) = table.remove(&key) else {
                continue;
            };
            let mut renamed_key = key;
            renamed_key.path = renamed_path;
            table.entry(renamed_key).or_default().extend(locks);
        }
    }

    pub fn posix_metadata(&self, share: &str, path: &SmbPath) -> Option<PosixMetadata> {
        self.posix_metadata
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PosixKey::new(share, path))
            .copied()
    }

    pub fn set_posix_metadata(&self, share: &str, path: &SmbPath, metadata: PosixMetadata) {
        self.posix_metadata
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(PosixKey::new(share, path), metadata);
    }

    pub fn rekey_posix_metadata(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.posix_metadata, share, from, to);
    }

    pub fn delete_posix_metadata(&self, share: &str, path: &SmbPath) {
        self.posix_metadata
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, path));
    }

    pub fn security_descriptor(&self, share: &str, path: &SmbPath) -> Option<Vec<u8>> {
        self.security_descriptors
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PosixKey::new(share, path))
            .cloned()
    }

    pub fn set_security_descriptor(&self, share: &str, path: &SmbPath, descriptor: Vec<u8>) {
        self.security_descriptors
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(PosixKey::new(share, path), descriptor);
    }

    pub fn rekey_security_descriptor(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.security_descriptors, share, from, to);
    }

    pub fn delete_security_descriptor(&self, share: &str, path: &SmbPath) {
        self.security_descriptors
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, path));
    }

    pub fn mark_name_deleted(&self, share: &str, path: &SmbPath) {
        self.deleted_names
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(PosixKey::new(share, path));
    }

    pub fn name_was_deleted(&self, share: &str, path: &SmbPath) -> bool {
        self.deleted_names
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&PosixKey::new(share, path))
    }

    pub fn clear_name_deleted(&self, share: &str, path: &SmbPath) {
        self.deleted_names
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, path));
    }

    pub fn extended_attributes(&self, share: &str, path: &SmbPath) -> Vec<ExtendedAttribute> {
        self.extended_attributes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PosixKey::new(share, path))
            .cloned()
            .unwrap_or_default()
    }

    pub fn apply_extended_attributes(
        &self,
        share: &str,
        path: &SmbPath,
        updates: &[ExtendedAttribute],
    ) {
        let key = PosixKey::new(share, path);
        let mut entries = self
            .extended_attributes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut current = entries.get(&key).cloned().unwrap_or_default();
        for update in updates {
            if let Some(pos) = current
                .iter()
                .position(|ea| ea.name.eq_ignore_ascii_case(&update.name))
            {
                if update.value.is_empty() {
                    current.remove(pos);
                } else {
                    current[pos] = update.clone();
                }
            } else if !update.value.is_empty() {
                current.push(update.clone());
            }
        }
        if current.is_empty() {
            entries.remove(&key);
        } else {
            entries.insert(key, current);
        }
    }

    pub fn delete_extended_attributes(&self, share: &str, path: &SmbPath) {
        self.extended_attributes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, path));
    }

    pub fn rekey_extended_attributes(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.extended_attributes, share, from, to);
    }

    pub fn effective_file_info(&self, share: &str, path: &SmbPath, mut info: FileInfo) -> FileInfo {
        if info.is_directory {
            info.end_of_file = 0;
            info.allocation_size = 0;
        } else if let Some(allocation_size) = self.allocation_size(share, path) {
            info.allocation_size = if allocation_size >= info.end_of_file {
                allocation_size
            } else {
                round_allocation_size(info.end_of_file)
            };
        } else if info.end_of_file > 0 && info.allocation_size == info.end_of_file {
            info.allocation_size = round_allocation_size(info.end_of_file);
        }
        if let Some(attributes) = self.file_attributes(share, path) {
            info.file_attributes = normalize_stored_file_attributes(attributes, info.is_directory);
        } else {
            let attributes = if info.file_attributes == 0 {
                default_file_attributes(info.is_directory)
            } else {
                info.file_attributes
            };
            info.file_attributes = normalize_stored_file_attributes(attributes, info.is_directory);
        }
        if let Some(times) = self.file_times(share, path) {
            if let Some(value) = times.creation_time {
                info.creation_time = value;
            }
            if let Some(value) = times.last_access_time {
                info.last_access_time = value;
            }
            if let Some(value) = times.last_write_time {
                info.last_write_time = value;
            }
            if let Some(value) = times.change_time {
                info.change_time = value;
            }
        }
        info
    }

    pub fn set_file_attributes(
        &self,
        share: &str,
        path: &SmbPath,
        attributes: u32,
        is_directory: bool,
    ) {
        let key = PosixKey::new(share, path);
        let attributes = normalize_stored_file_attributes(attributes, is_directory);
        self.file_attributes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, attributes);
    }

    pub fn delete_file_attributes(&self, share: &str, path: &SmbPath) {
        self.file_attributes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, path));
    }

    pub fn rekey_file_attributes(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.file_attributes, share, from, to);
    }

    pub fn apply_file_times(&self, share: &str, path: &SmbPath, times: FileTimes) {
        self.apply_file_times_with_sticky_owner(share, path, times, None);
    }

    pub fn apply_file_times_for_open(
        &self,
        share: &str,
        path: &SmbPath,
        times: FileTimes,
        file_id: FileId,
    ) {
        self.apply_file_times_with_sticky_owner(share, path, times, Some(file_id));
    }

    fn apply_file_times_with_sticky_owner(
        &self,
        share: &str,
        path: &SmbPath,
        times: FileTimes,
        sticky_owner: Option<FileId>,
    ) {
        if times.creation_time.is_none()
            && times.last_access_time.is_none()
            && times.last_write_time.is_none()
            && times.change_time.is_none()
        {
            return;
        }
        let key = PosixKey::new(share, path);
        if let Some(file_id) = sticky_owner
            && times.last_write_time.is_some()
        {
            self.pinned_write_times
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&key);
            self.sticky_write_time_owners
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(key.clone(), file_id);
        }
        let mut entries = self
            .file_times
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut current = entries.get(&key).copied().unwrap_or_default();
        if times.creation_time.is_some() {
            current.creation_time = times.creation_time;
        }
        if times.last_access_time.is_some() {
            current.last_access_time = times.last_access_time;
        }
        if times.last_write_time.is_some() {
            current.last_write_time = times.last_write_time;
        }
        if times.change_time.is_some() {
            current.change_time = times.change_time;
        }
        entries.insert(key, current);
    }

    pub fn update_file_times_after_write(&self, share: &str, path: &SmbPath, file_id: FileId) {
        let key = PosixKey::new(share, path);
        if self
            .pinned_write_times
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&key)
        {
            return;
        }
        let sticky_owner = self
            .sticky_write_time_owners
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied();
        if sticky_owner == Some(file_id) {
            return;
        }
        if sticky_owner.is_some() {
            self.force_update_file_times_after_write(share, path);
            return;
        }
        let mut entries = self
            .file_times
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(current) = entries.get_mut(&key) {
            current.last_write_time = None;
            current.change_time = None;
            if current.creation_time.is_none()
                && current.last_access_time.is_none()
                && current.last_write_time.is_none()
                && current.change_time.is_none()
            {
                entries.remove(&key);
            }
        }
    }

    pub fn force_update_file_times_after_write(&self, share: &str, path: &SmbPath) {
        let key = PosixKey::new(share, path);
        self.sticky_write_time_owners
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        self.pinned_write_times
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key);
        let now = now_filetime();
        self.apply_file_times(
            share,
            path,
            FileTimes {
                last_write_time: Some(now),
                change_time: Some(now),
                ..FileTimes::default()
            },
        );
    }

    pub fn update_change_time_after_metadata_mutation(&self, share: &str, path: &SmbPath) {
        self.apply_file_times(
            share,
            path,
            FileTimes {
                change_time: Some(now_filetime()),
                ..FileTimes::default()
            },
        );
    }

    pub fn delete_file_times(&self, share: &str, path: &SmbPath) {
        let key = PosixKey::new(share, path);
        self.file_times
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        self.sticky_write_time_owners
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        self.pinned_write_times
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
    }

    pub fn rekey_file_times(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.file_times, share, from, to);
        rekey_posix_keyed_map(&self.sticky_write_time_owners, share, from, to);
        rekey_posix_keyed_set(&self.pinned_write_times, share, from, to);
    }

    pub fn set_allocation_size(&self, share: &str, path: &SmbPath, allocation_size: u64) {
        let key = PosixKey::new(share, path);
        let mut entries = self
            .allocation_sizes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if allocation_size == 0 {
            entries.remove(&key);
        } else {
            entries.insert(key, allocation_size);
        }
    }

    pub fn delete_allocation_size(&self, share: &str, path: &SmbPath) {
        self.allocation_sizes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, path));
    }

    pub fn rekey_allocation_size(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.allocation_sizes, share, from, to);
    }

    fn allocation_size(&self, share: &str, path: &SmbPath) -> Option<u64> {
        self.allocation_sizes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PosixKey::new(share, path))
            .copied()
    }

    fn file_attributes(&self, share: &str, path: &SmbPath) -> Option<u32> {
        self.file_attributes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PosixKey::new(share, path))
            .copied()
    }

    fn file_times(&self, share: &str, path: &SmbPath) -> Option<FileTimes> {
        self.file_times
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PosixKey::new(share, path))
            .copied()
    }

    pub fn delete_streams(&self, share: &str, base: &SmbPath) {
        self.streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&PosixKey::new(share, base));
    }

    pub fn delete_stream(&self, share: &str, base: &SmbPath, stream_name: &str) -> SmbResult<()> {
        let key = PosixKey::new(share, base);
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entries) = streams.get_mut(&key) else {
            return Err(SmbError::NotFound);
        };
        let Some(index) = entries
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(stream_name))
        else {
            return Err(SmbError::NotFound);
        };
        entries.remove(index);
        if entries.is_empty() {
            streams.remove(&key);
        }
        Ok(())
    }

    pub fn rekey_streams(&self, share: &str, from: &SmbPath, to: &SmbPath) {
        rekey_posix_keyed_map(&self.streams, share, from, to);
    }

    pub fn rename_stream(
        &self,
        share: &str,
        base: &SmbPath,
        from_stream: &str,
        to_stream: &str,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        let key = PosixKey::new(share, base);
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entries) = streams.get_mut(&key) else {
            return Err(SmbError::NotFound);
        };
        let Some(from_index) = entries
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(from_stream))
        else {
            return Err(SmbError::NotFound);
        };
        if entries[from_index].name.eq_ignore_ascii_case(to_stream) {
            entries[from_index].name = to_stream.to_string();
            return Ok(());
        }
        if let Some(to_index) = entries
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(to_stream))
        {
            if !replace_if_exists {
                return Err(SmbError::Exists);
            }
            entries.remove(to_index);
        }
        let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.name.eq_ignore_ascii_case(from_stream))
        else {
            return Err(SmbError::NotFound);
        };
        entry.name = to_stream.to_string();
        Ok(())
    }

    pub fn stream_data(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
    ) -> SmbResult<Vec<u8>> {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        streams
            .get(&PosixKey::new(share, base))
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.name.eq_ignore_ascii_case(stream_name))
            })
            .map(|entry| entry.data.clone())
            .ok_or(SmbError::NotFound)
    }

    pub fn open_stream(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
        intent: OpenIntent,
        base_creation_time: u64,
    ) -> SmbResult<(String, bool)> {
        let key = PosixKey::new(share, base);
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = streams.entry(key).or_default();
        let position = entries
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(stream_name));
        match intent {
            OpenIntent::Open => {
                let Some(index) = position else {
                    return Err(SmbError::NotFound);
                };
                Ok((entries[index].name.clone(), true))
            }
            OpenIntent::Create => {
                if position.is_some() {
                    return Err(SmbError::Exists);
                }
                entries.push(NamedStream::new(stream_name, base_creation_time));
                Ok((stream_name.to_string(), false))
            }
            OpenIntent::OpenOrCreate => match position {
                Some(index) => Ok((entries[index].name.clone(), true)),
                None => {
                    entries.push(NamedStream::new(stream_name, base_creation_time));
                    Ok((stream_name.to_string(), false))
                }
            },
            OpenIntent::Truncate => match position {
                Some(index) => {
                    entries[index].data.clear();
                    Ok((entries[index].name.clone(), true))
                }
                None => Err(SmbError::NotFound),
            },
            OpenIntent::OverwriteOrCreate => match position {
                Some(index) => {
                    entries[index].data.clear();
                    Ok((entries[index].name.clone(), true))
                }
                None => {
                    entries.push(NamedStream::new(stream_name, base_creation_time));
                    Ok((stream_name.to_string(), false))
                }
            },
        }
    }

    pub fn stream_info(
        &self,
        share: &str,
        base: &SmbPath,
        base_info: &FileInfo,
    ) -> Vec<FileStream> {
        let mut out = if base_info.is_directory {
            Vec::new()
        } else {
            vec![FileStream {
                name: "::$DATA".to_string(),
                size: base_info.end_of_file,
                allocation: base_info.allocation_size,
            }]
        };
        let streams = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entries) = streams.get(&PosixKey::new(share, base)) {
            out.extend(entries.iter().map(|entry| FileStream {
                name: format!(":{}:$DATA", entry.name),
                size: entry.data.len() as u64,
                allocation: entry.data.len() as u64,
            }));
        }
        out
    }

    fn read_stream(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
        offset: u64,
        len: u32,
    ) -> SmbResult<Bytes> {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = streams
            .get(&PosixKey::new(share, base))
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.name.eq_ignore_ascii_case(stream_name))
            })
        else {
            return Err(SmbError::NotFound);
        };
        let start = offset as usize;
        if start >= entry.data.len() {
            return Ok(Bytes::new());
        }
        let end = start.saturating_add(len as usize).min(entry.data.len());
        Ok(Bytes::copy_from_slice(&entry.data[start..end]))
    }

    fn write_stream(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
        offset: u64,
        data: &[u8],
    ) -> SmbResult<u32> {
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = streams
            .get_mut(&PosixKey::new(share, base))
            .and_then(|entries| {
                entries
                    .iter_mut()
                    .find(|entry| entry.name.eq_ignore_ascii_case(stream_name))
            })
        else {
            return Err(SmbError::NotFound);
        };
        let start = offset as usize;
        if entry.data.len() < start {
            entry.data.resize(start, 0);
        }
        let end = start.saturating_add(data.len());
        if entry.data.len() < end {
            entry.data.resize(end, 0);
        }
        entry.data[start..end].copy_from_slice(data);
        let now = now_filetime();
        entry.last_write_time = now;
        entry.change_time = now;
        Ok(data.len() as u32)
    }

    fn set_stream_times(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
        times: FileTimes,
    ) -> SmbResult<()> {
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = streams
            .get_mut(&PosixKey::new(share, base))
            .and_then(|entries| {
                entries
                    .iter_mut()
                    .find(|entry| entry.name.eq_ignore_ascii_case(stream_name))
            })
        else {
            return Err(SmbError::NotFound);
        };
        if let Some(value) = times.creation_time {
            entry.creation_time = value;
        }
        if let Some(value) = times.last_access_time {
            entry.last_access_time = value;
        }
        if let Some(value) = times.last_write_time {
            entry.last_write_time = value;
        }
        if let Some(value) = times.change_time {
            entry.change_time = value;
        }
        Ok(())
    }

    fn truncate_stream(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
        len: u64,
    ) -> SmbResult<()> {
        let mut streams = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = streams
            .get_mut(&PosixKey::new(share, base))
            .and_then(|entries| {
                entries
                    .iter_mut()
                    .find(|entry| entry.name.eq_ignore_ascii_case(stream_name))
            })
        else {
            return Err(SmbError::NotFound);
        };
        entry.data.resize(len as usize, 0);
        let now = now_filetime();
        entry.last_write_time = now;
        entry.change_time = now;
        Ok(())
    }

    fn stream_file_info(
        &self,
        share: &str,
        base: &SmbPath,
        stream_name: &str,
    ) -> SmbResult<FileInfo> {
        let streams = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        streams
            .get(&PosixKey::new(share, base))
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.name.eq_ignore_ascii_case(stream_name))
            })
            .map(|entry| FileInfo {
                name: format!("{}:{}", base.display_backslash(), entry.name),
                end_of_file: entry.data.len() as u64,
                allocation_size: entry.data.len() as u64,
                creation_time: entry.creation_time,
                last_access_time: entry.last_access_time,
                last_write_time: entry.last_write_time,
                change_time: entry.change_time,
                is_directory: false,
                file_index: 0,
                file_attributes: default_file_attributes(false),
            })
            .ok_or(SmbError::NotFound)
    }

    /// Look up a user's NT hash by name.
    pub async fn lookup_user(&self, name: &str) -> Option<UserCreds> {
        self.users.table.read().await.get(name).cloned()
    }

    /// Whether anonymous logon is permitted (i.e. at least one share is public).
    pub async fn anonymous_allowed(&self) -> bool {
        for share in self.shares.all().await {
            let acl = share.acl.read().await;
            if matches!(acl.mode, ShareMode::Public | ShareMode::PublicReadOnly) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PosixKey {
    share: String,
    path: String,
}

impl PosixKey {
    fn new(share: &str, path: &SmbPath) -> Self {
        Self {
            share: share.to_ascii_lowercase(),
            path: path.display_backslash().to_ascii_lowercase(),
        }
    }
}

fn rekey_posix_keyed_map<T>(
    entries: &StdRwLock<HashMap<PosixKey, T>>,
    share: &str,
    from: &SmbPath,
    to: &SmbPath,
) {
    let share_key = share.to_ascii_lowercase();
    let from_path = from.display_backslash().to_ascii_lowercase();
    let to_path = to.display_backslash().to_ascii_lowercase();
    let mut entries = entries
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let keys = entries
        .keys()
        .filter_map(|key| {
            if key.share == share_key {
                rebase_lowercase_path(&key.path, &from_path, &to_path)
                    .map(|renamed_path| (key.clone(), renamed_path))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for (key, renamed_path) in keys {
        let Some(value) = entries.remove(&key) else {
            continue;
        };
        let mut renamed_key = key;
        renamed_key.path = renamed_path;
        entries.insert(renamed_key, value);
    }
}

fn rekey_posix_keyed_set(
    entries: &StdRwLock<HashSet<PosixKey>>,
    share: &str,
    from: &SmbPath,
    to: &SmbPath,
) {
    let share_key = share.to_ascii_lowercase();
    let from_path = from.display_backslash().to_ascii_lowercase();
    let to_path = to.display_backslash().to_ascii_lowercase();
    let mut entries = entries
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let keys = entries
        .iter()
        .filter_map(|key| {
            if key.share == share_key {
                rebase_lowercase_path(&key.path, &from_path, &to_path)
                    .map(|renamed_path| (key.clone(), renamed_path))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for (key, renamed_path) in keys {
        if !entries.remove(&key) {
            continue;
        }
        let mut renamed_key = key;
        renamed_key.path = renamed_path;
        entries.insert(renamed_key);
    }
}

#[derive(Debug, Clone)]
struct NamedStream {
    name: String,
    data: Vec<u8>,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
}

impl NamedStream {
    fn new(name: &str, creation_time: u64) -> Self {
        let now = now_filetime();
        Self {
            name: name.to_string(),
            data: Vec::new(),
            creation_time,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
        }
    }
}

pub(crate) struct StreamHandle {
    server: Arc<ServerState>,
    share: String,
    base: SmbPath,
    stream_name: String,
}

impl StreamHandle {
    pub(crate) fn new(
        server: Arc<ServerState>,
        share: String,
        base: SmbPath,
        stream_name: String,
    ) -> Self {
        Self {
            server,
            share,
            base,
            stream_name,
        }
    }
}

#[async_trait]
impl Handle for StreamHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.server
            .read_stream(&self.share, &self.base, &self.stream_name, offset, len)
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.server
            .write_stream(&self.share, &self.base, &self.stream_name, offset, data)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        self.server
            .stream_file_info(&self.share, &self.base, &self.stream_name)
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.server
            .set_stream_times(&self.share, &self.base, &self.stream_name, times)
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.server
            .truncate_stream(&self.share, &self.base, &self.stream_name, len)
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<crate::backend::DirEntry>> {
        Err(SmbError::NotADirectory)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("user `{0}` does not exist")]
    UnknownUser(String),
    #[error("share `{0}` does not exist")]
    UnknownShare(String),
    #[error("duplicate share `{0}`")]
    DuplicateShare(String),
    #[error("share `{0}` mixes public mode with explicit users")]
    PublicMixedWithUsers(String),
    #[error("user name `{0}` is reserved")]
    ReservedUserName(String),
    #[error("user name must be non-empty")]
    EmptyUserName,
    #[error("share name `{0}` is reserved")]
    ReservedShareName(String),
}

#[derive(Clone)]
pub struct ConfigHandle {
    state: Arc<ServerState>,
}

impl ConfigHandle {
    pub async fn add_user(
        &self,
        name: impl Into<String>,
        password: impl AsRef<str>,
    ) -> Result<(), ConfigError> {
        let name = name.into();
        validate_user_name(&name)?;
        let creds = UserCreds::from_password(password.as_ref());
        self.state.users.table.write().await.insert(name, creds);
        Ok(())
    }

    pub async fn remove_user(&self, name: &str) -> Result<(), ConfigError> {
        validate_user_name(name)?;
        let removed = self.state.users.table.write().await.remove(name);
        if removed.is_none() {
            return Err(ConfigError::UnknownUser(name.to_string()));
        }

        for share in self.state.shares.all().await {
            share.acl.write().await.users.remove(name);
        }

        for conn in self.state.active_connections.live().await {
            conn.close_sessions_for_user(name).await;
        }
        Ok(())
    }

    pub async fn add_share(&self, share: Share) -> Result<(), ConfigError> {
        validate_share_name(&share.name)?;
        let is_public = matches!(share.mode, ShareMode::Public | ShareMode::PublicReadOnly);
        if is_public && !share.users.is_empty() {
            return Err(ConfigError::PublicMixedWithUsers(share.name));
        }
        let users = self.state.users.table.read().await;
        for user in share.users.keys() {
            if !users.contains_key(user) {
                return Err(ConfigError::UnknownUser(user.clone()));
            }
        }

        let binding = ShareBindings::new(share.name, share.backend, share.mode, share.users, false);
        self.state.shares.insert(binding).await
    }

    pub async fn remove_share(&self, name: &str) -> Result<(), ConfigError> {
        validate_share_name(name)?;
        let removed = self.state.shares.remove(name).await;
        if removed.is_none() {
            return Err(ConfigError::UnknownShare(name.to_string()));
        }

        for conn in self.state.active_connections.live().await {
            conn.close_trees_for_share(name).await;
        }
        Ok(())
    }

    pub async fn grant_share_user(
        &self,
        share_name: &str,
        user: &str,
        access: Access,
    ) -> Result<(), ConfigError> {
        validate_user_name(user)?;
        validate_share_name(share_name)?;
        let users = self.state.users.table.read().await;
        if !users.contains_key(user) {
            return Err(ConfigError::UnknownUser(user.to_string()));
        }
        let share = self
            .state
            .find_share(share_name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(share_name.to_string()))?;
        let mut acl = share.acl.write().await;
        if matches!(acl.mode, ShareMode::Public | ShareMode::PublicReadOnly) {
            return Err(ConfigError::PublicMixedWithUsers(share.name.clone()));
        }
        acl.users.insert(user.to_string(), access);
        Ok(())
    }

    pub async fn revoke_share_user(&self, share_name: &str, user: &str) -> Result<(), ConfigError> {
        validate_user_name(user)?;
        validate_share_name(share_name)?;
        let share = self
            .state
            .find_share(share_name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(share_name.to_string()))?;
        share.acl.write().await.users.remove(user);

        for conn in self.state.active_connections.live().await {
            conn.close_trees_for_user_share(user, share_name).await;
        }
        Ok(())
    }

    pub async fn set_share_mode(
        &self,
        share_name: &str,
        mode: ShareMode,
    ) -> Result<(), ConfigError> {
        validate_share_name(share_name)?;
        let share = self
            .state
            .find_share(share_name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(share_name.to_string()))?;
        let mut acl = share.acl.write().await;
        if matches!(mode, ShareMode::Public | ShareMode::PublicReadOnly) && !acl.users.is_empty() {
            return Err(ConfigError::PublicMixedWithUsers(share.name.clone()));
        }
        if acl.mode == mode {
            return Ok(());
        }
        acl.mode = mode;
        drop(acl);

        for conn in self.state.active_connections.live().await {
            conn.close_trees_for_share(share_name).await;
        }
        Ok(())
    }
}

fn validate_user_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::EmptyUserName);
    }
    if name.eq_ignore_ascii_case("anonymous") {
        return Err(ConfigError::ReservedUserName(name.to_string()));
    }
    Ok(())
}

fn validate_share_name(name: &str) -> Result<(), ConfigError> {
    if name.eq_ignore_ascii_case("IPC$") {
        return Err(ConfigError::ReservedShareName(name.to_string()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SmbServer
// ---------------------------------------------------------------------------

/// A built but not-yet-running SMB server.
///
/// Use `serve()` to bind the configured listener and run until shutdown.
pub struct SmbServer {
    state: Arc<ServerState>,
    /// The listener is bound lazily inside `serve()` so we can return a
    /// useful `local_addr` only after binding. Pre-bind helpers: `serve` is
    /// the only path that opens the socket.
    bound: tokio::sync::Mutex<Option<TcpListener>>,
    /// Resolved local address once `bind_local()` has been called. Tests
    /// expect to ask for the address before serving (port 0 case).
    local_addr: tokio::sync::Mutex<Option<SocketAddr>>,
}

impl SmbServer {
    pub fn builder() -> SmbServerBuilder {
        SmbServerBuilder::default()
    }

    pub(crate) fn from_state(state: ServerState) -> Self {
        Self {
            state: Arc::new(state),
            bound: tokio::sync::Mutex::new(None),
            local_addr: tokio::sync::Mutex::new(None),
        }
    }

    pub fn config_handle(&self) -> ConfigHandle {
        ConfigHandle {
            state: self.state.clone(),
        }
    }

    /// Bind the configured listen address without yet entering the accept
    /// loop. Required for tests that need the actual port (e.g. when the
    /// builder used port 0).
    pub async fn bind(&self) -> io::Result<SocketAddr> {
        let mut bound = self.bound.lock().await;
        if let Some(l) = bound.as_ref() {
            return l.local_addr();
        }
        let listener = TcpListener::bind(self.state.config.listen_addr).await?;
        let addr = listener.local_addr()?;
        *bound = Some(listener);
        *self.local_addr.lock().await = Some(addr);
        Ok(addr)
    }

    /// Returns the actual bound address. `None` if `bind()`/`serve()` have
    /// not yet been called.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().await
    }

    /// Configured listen address (the *intended* address; may be `0.0.0.0:0`
    /// before binding).
    pub fn configured_addr(&self) -> SocketAddr {
        self.state.config.listen_addr
    }

    /// Initiate a graceful shutdown. Stops the accept loop and lets in-flight
    /// connection tasks complete.
    pub fn shutdown(&self) {
        self.state.shutting_down.store(true, Ordering::Release);
        self.state.shutdown.notify_waiters();
    }

    /// Returns a clonable handle that can request shutdown after `serve()`
    /// has consumed the `SmbServer` value.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shutdown: self.state.shutdown.clone(),
            shutting_down: self.state.shutting_down.clone(),
        }
    }

    /// Run the accept loop until `shutdown()` is called.
    pub async fn serve(self) -> io::Result<()> {
        // Ensure the listener is bound. (The user may also have called
        // `bind()` to pre-extract `local_addr()` for a test.)
        if self.bound.lock().await.is_none() {
            self.bind().await?;
        }
        let listener = self
            .bound
            .lock()
            .await
            .take()
            .expect("listener bound above");
        let local = listener.local_addr().ok();
        let span = info_span!("smb_server", listen = ?local);
        async move {
            info!("server starting");
            let state = self.state.clone();
            let shutdown = state.shutdown.clone();
            let shutting_down = state.shutting_down.clone();

            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.notified() => {
                        info!("shutdown requested; stopping accept loop");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                if shutting_down.load(Ordering::Acquire) {
                                    drop(stream);
                                    break;
                                }
                                let server_state = state.clone();
                                let span = info_span!("conn", peer = %peer);
                                tokio::spawn(async move {
                                    if let Err(e) = connection_loop(stream, server_state).await {
                                        error!(error = %e, "connection loop exited with error");
                                    }
                                }.instrument(span));
                            }
                            Err(e) => {
                                error!(error = %e, "accept failed");
                                if shutting_down.load(Ordering::Acquire) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            info!("server stopped");
            Ok::<(), io::Error>(())
        }
        .instrument(span)
        .await
    }

    /// Access shared state for in-crate tests/integrations.
    #[doc(hidden)]
    pub fn state(&self) -> Arc<ServerState> {
        self.state.clone()
    }
}

/// Cheaply-clonable shutdown handle. Outlives `SmbServer::serve` consuming
/// the server.
#[derive(Clone)]
pub struct ShutdownHandle {
    shutdown: Arc<Notify>,
    shutting_down: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Request a graceful shutdown.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendCapabilities, DirEntry, OpenOptions};
    use crate::conn::state::Session;
    use crate::dispatch;
    use crate::proto::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
    use crate::proto::messages::{ChangeNotifyResponse, Dialect, WriteRequest};
    use bytes::Bytes;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    struct TestBackend;

    #[async_trait]
    impl ShareBackend for TestBackend {
        async fn open(&self, _path: &SmbPath, _opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
            Err(SmbError::NotSupported)
        }

        async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }

        async fn rename(&self, _from: &SmbPath, _to: &SmbPath) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                is_read_only: false,
                case_sensitive: false,
            }
        }
    }

    #[test]
    fn change_notify_coalesces_create_write_burst() {
        let events = coalesce_notify_events(&[
            NotifyEvent {
                action: 0x0000_0001,
                name: "created.txt".to_string(),
                is_directory: false,
            },
            NotifyEvent {
                action: 0x0000_0003,
                name: "created.txt".to_string(),
                is_directory: false,
            },
        ]);

        assert_eq!(
            events,
            vec![NotifyEvent {
                action: 0x0000_0001,
                name: "created.txt".to_string(),
                is_directory: false,
            }]
        );
    }

    #[test]
    fn change_notify_keeps_later_modify_after_remove() {
        let events = coalesce_notify_events(&[
            NotifyEvent {
                action: 0x0000_0003,
                name: "replace.txt".to_string(),
                is_directory: false,
            },
            NotifyEvent {
                action: 0x0000_0002,
                name: "replace.txt".to_string(),
                is_directory: false,
            },
            NotifyEvent {
                action: 0x0000_0001,
                name: "replace.txt".to_string(),
                is_directory: false,
            },
            NotifyEvent {
                action: 0x0000_0003,
                name: "replace.txt".to_string(),
                is_directory: false,
            },
            NotifyEvent {
                action: 0x0000_0003,
                name: "replace.txt".to_string(),
                is_directory: false,
            },
        ]);

        assert_eq!(
            events,
            vec![
                NotifyEvent {
                    action: 0x0000_0002,
                    name: "replace.txt".to_string(),
                    is_directory: false,
                },
                NotifyEvent {
                    action: 0x0000_0001,
                    name: "replace.txt".to_string(),
                    is_directory: false,
                },
                NotifyEvent {
                    action: 0x0000_0003,
                    name: "replace.txt".to_string(),
                    is_directory: false,
                },
            ]
        );
    }

    #[test]
    fn file_notify_information_encodes_multi_record_chain() {
        let output = encode_file_notify_records(&[
            (0x0000_0001, "hello.txt".to_string()),
            (0x0000_0003, "docs/nested.txt".to_string()),
        ]);

        let first_next = u32::from_le_bytes(output[0..4].try_into().unwrap()) as usize;
        assert!(first_next > 0);
        assert!(first_next < output.len());
        assert_eq!(
            u32::from_le_bytes(output[4..8].try_into().unwrap()),
            0x0000_0001
        );
        let first_name_len = u32::from_le_bytes(output[8..12].try_into().unwrap()) as usize;
        let first_name = utf16_bytes_to_string_for_test(&output[12..12 + first_name_len]);
        assert_eq!(first_name, "hello.txt");

        let second = &output[first_next..];
        assert_eq!(u32::from_le_bytes(second[0..4].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(second[4..8].try_into().unwrap()),
            0x0000_0003
        );
        let second_name_len = u32::from_le_bytes(second[8..12].try_into().unwrap()) as usize;
        let second_name = utf16_bytes_to_string_for_test(&second[12..12 + second_name_len]);
        assert_eq!(second_name, "docs/nested.txt");
    }

    #[tokio::test]
    async fn recursive_change_notify_ignores_base_directory_metadata() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", TestBackend).public())
            .build()
            .expect("build server");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        let (tx, mut rx) = mpsc::channel(8);
        conn.set_async_sender(tx.clone()).await;

        let watch_id = FileId::new(1, 1);
        let watch_path = "base".parse::<SmbPath>().expect("watch path");
        let child_path = "base/child.txt".parse::<SmbPath>().expect("child path");
        let watch_open = Arc::new(RwLock::new(Open::new(
            watch_id,
            Box::new(TestHandle {
                data: Arc::new(Mutex::new(Vec::new())),
            }),
            Access::ReadWrite,
            0x0000_0001,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            watch_path.clone(),
            true,
            false,
            None,
        )));
        let req_hdr = Smb2Header {
            command: Command::ChangeNotify,
            credit_request_response: 1,
            message_id: 1,
            tail: HeaderTail::sync(7),
            session_id: 42,
            ..Default::default()
        };
        let async_id = 99;
        assert!(state.reserve_change_notify_async_slot(&conn));
        state.register_change_notify(
            async_id,
            &conn,
            &watch_open,
            tx,
            req_hdr,
            watch_id,
            "share",
            watch_path.clone(),
            true,
            4096,
            0x0000_0004,
            false,
            false,
            None,
        );

        state
            .notify_attributes_modified("share", &watch_path, true)
            .await;
        assert!(
            rx.try_recv().is_err(),
            "base directory metadata completed recursive notify"
        );
        assert_eq!(
            state
                .change_notifies
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );

        state
            .notify_attributes_modified("share", &child_path, false)
            .await;
        let frame = rx.recv().await.expect("child notify frame");
        let (hdr, body) = Smb2Header::parse(&frame).expect("parse async notify");
        assert_eq!(hdr.command, Command::ChangeNotify);
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.async_id(), Some(async_id));
        let notify = ChangeNotifyResponse::parse(body).expect("parse notify response");
        let records = decode_file_notify_records_for_test(&notify.buffer);
        assert_eq!(records, vec![(0x0000_0003, "child.txt".to_string())]);
        assert!(
            state
                .change_notifies
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn change_notify_security_modified_completes_parent_watch() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", TestBackend).public())
            .build()
            .expect("build server");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        let (tx, mut rx) = mpsc::channel(8);
        conn.set_async_sender(tx.clone()).await;

        let watch_id = FileId::new(1, 1);
        let watch_path = "base".parse::<SmbPath>().expect("watch path");
        let child_path = "base/sec_notify.txt"
            .parse::<SmbPath>()
            .expect("child path");
        let watch_open = Arc::new(RwLock::new(Open::new(
            watch_id,
            Box::new(TestHandle {
                data: Arc::new(Mutex::new(Vec::new())),
            }),
            Access::ReadWrite,
            0x0000_0001,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            watch_path.clone(),
            true,
            false,
            None,
        )));
        let req_hdr = Smb2Header {
            command: Command::ChangeNotify,
            credit_request_response: 1,
            message_id: 1,
            tail: HeaderTail::sync(7),
            session_id: 42,
            ..Default::default()
        };
        let async_id = 99;
        assert!(state.reserve_change_notify_async_slot(&conn));
        state.register_change_notify(
            async_id,
            &conn,
            &watch_open,
            tx,
            req_hdr,
            watch_id,
            "share",
            watch_path,
            false,
            4096,
            0x0000_0100,
            false,
            false,
            None,
        );

        state
            .notify_security_modified("share", &child_path, false)
            .await;

        let frame = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("notify timeout")
            .expect("security notify frame");
        let (hdr, body) = Smb2Header::parse(&frame).expect("parse async notify");
        assert_eq!(hdr.command, Command::ChangeNotify);
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.async_id(), Some(async_id));
        let notify = ChangeNotifyResponse::parse(body).expect("parse notify response");
        let records = decode_file_notify_records_for_test(&notify.buffer);
        assert_eq!(records, vec![(0x0000_0003, "sec_notify.txt".to_string())]);
    }

    #[tokio::test]
    async fn change_notify_batches_replace_burst_records() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", TestBackend).public())
            .build()
            .expect("build server");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        let (tx, mut rx) = mpsc::channel(8);
        conn.set_async_sender(tx.clone()).await;

        let watch_id = FileId::new(1, 1);
        let watch_path = "base".parse::<SmbPath>().expect("watch path");
        let child_path = "base/replace.txt".parse::<SmbPath>().expect("child path");
        let watch_open = Arc::new(RwLock::new(Open::new(
            watch_id,
            Box::new(TestHandle {
                data: Arc::new(Mutex::new(Vec::new())),
            }),
            Access::ReadWrite,
            0x0000_0001,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            watch_path.clone(),
            true,
            false,
            None,
        )));
        let req_hdr = Smb2Header {
            command: Command::ChangeNotify,
            credit_request_response: 1,
            message_id: 1,
            tail: HeaderTail::sync(7),
            session_id: 42,
            ..Default::default()
        };
        let async_id = 99;
        assert!(state.reserve_change_notify_async_slot(&conn));
        state.register_change_notify(
            async_id,
            &conn,
            &watch_open,
            tx,
            req_hdr,
            watch_id,
            "share",
            watch_path.clone(),
            true,
            4096,
            0x0000_0001 | 0x0000_0008 | 0x0000_0010,
            false,
            false,
            None,
        );

        state.notify_removed("share", &child_path, false).await;
        state.notify_child_added("share", &child_path, false).await;
        state
            .notify_data_modified("share", &child_path, false)
            .await;

        let frame = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("notify timeout")
            .expect("replace notify frame");
        let (hdr, body) = Smb2Header::parse(&frame).expect("parse async notify");
        assert_eq!(hdr.command, Command::ChangeNotify);
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.async_id(), Some(async_id));
        let notify = ChangeNotifyResponse::parse(body).expect("parse notify response");
        let records = decode_file_notify_records_for_test(&notify.buffer);
        assert_eq!(
            records,
            vec![
                (0x0000_0002, "replace.txt".to_string()),
                (0x0000_0001, "replace.txt".to_string()),
                (0x0000_0003, "replace.txt".to_string()),
            ]
        );
        assert!(
            state
                .change_notifies
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
    }

    fn decode_file_notify_records_for_test(mut buf: &[u8]) -> Vec<(u32, String)> {
        let mut records = Vec::new();
        while !buf.is_empty() {
            assert!(buf.len() >= 12, "short notify record");
            let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
            let action = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            let name_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
            assert!(buf.len() >= 12 + name_len, "short notify name");
            let units = buf[12..12 + name_len]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            records.push((
                action,
                String::from_utf16(&units).expect("utf16 notify name"),
            ));
            if next == 0 {
                break;
            }
            assert!(buf.len() >= next, "invalid notify next offset");
            buf = &buf[next..];
        }
        records
    }

    fn utf16_bytes_to_string_for_test(bytes: &[u8]) -> String {
        let units = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).expect("utf16 notify name")
    }

    struct TestHandle {
        data: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl Handle for TestHandle {
        async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
            let data = self.data.lock().unwrap();
            let start = offset as usize;
            if start >= data.len() {
                return Ok(Bytes::new());
            }
            let end = start.saturating_add(len as usize).min(data.len());
            Ok(Bytes::copy_from_slice(&data[start..end]))
        }

        async fn write(&self, offset: u64, input: &[u8]) -> SmbResult<u32> {
            let mut data = self.data.lock().unwrap();
            let start = offset as usize;
            if data.len() < start {
                data.resize(start, 0);
            }
            let end = start + input.len();
            if data.len() < end {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(input);
            Ok(input.len() as u32)
        }

        async fn flush(&self) -> SmbResult<()> {
            Ok(())
        }

        async fn stat(&self) -> SmbResult<FileInfo> {
            let len = self.data.lock().unwrap().len() as u64;
            Ok(FileInfo {
                name: "hello.txt".to_string(),
                end_of_file: len,
                allocation_size: len,
                creation_time: now_filetime(),
                last_access_time: now_filetime(),
                last_write_time: now_filetime(),
                change_time: now_filetime(),
                is_directory: false,
                file_index: 1,
                file_attributes: FILE_ATTRIBUTE_NORMAL,
            })
        }

        async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
            Ok(())
        }

        async fn truncate(&self, len: u64) -> SmbResult<()> {
            self.data.lock().unwrap().resize(len as usize, 0);
            Ok(())
        }

        async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
            Err(SmbError::NotADirectory)
        }

        async fn close(self: Box<Self>) -> SmbResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn durable_replay_state_is_scoped_by_owner() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", TestBackend).public())
            .build()
            .expect("build server");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        let client_guid = Uuid::from_bytes([0x11; 16]);
        let create_guid = [0x22; 16];
        let owner = "DOMAIN\\ALICE";
        let other_owner = "DOMAIN\\BOB";
        let file_id = FileId::new(7, 9);
        let mut open = Open::new(
            file_id,
            Box::new(TestHandle {
                data: Arc::new(Mutex::new(b"hello".to_vec())),
            }),
            Access::ReadWrite,
            FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "hello.txt".parse::<SmbPath>().expect("path"),
            false,
            false,
            None,
        );
        open.durable = true;
        open.durable_version = 2;
        open.replay_eligible = true;
        open.create_guid = create_guid;
        let open = Arc::new(RwLock::new(open));
        state
            .register_durable_open("share", file_id, &open, &conn, 1, client_guid, owner)
            .await;

        assert!(matches!(
            state
                .durable_replay_open("share", create_guid, client_guid, other_owner, &conn, 1)
                .await,
            DurableReplayLookup::NotFound
        ));
        assert!(matches!(
            state
                .durable_replay_open("share", create_guid, client_guid, owner, &conn, 1)
                .await,
            DurableReplayLookup::Available(_)
        ));

        let (tx, _rx) = mpsc::channel(1);
        state.register_cache_break_create(
            99,
            &conn,
            tx,
            Smb2Header::default(),
            Vec::new(),
            Vec::new(),
            file_id,
            ntstatus::STATUS_SUCCESS,
            b"pending".to_vec(),
            Some(create_guid),
            client_guid,
            owner.to_string(),
        );
        assert!(!state.durable_pending_create_replay(create_guid, client_guid, other_owner));
        assert!(state.durable_pending_create_replay(create_guid, client_guid, owner));

        state
            .completed_create_replays
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                CreateReplayKey {
                    create_guid,
                    client_guid,
                    owner: owner.to_string(),
                },
                b"completed".to_vec(),
            );
        assert_eq!(
            state.completed_create_replay(create_guid, client_guid, other_owner),
            None
        );
        assert_eq!(
            state.completed_create_replay(create_guid, client_guid, owner),
            Some(b"completed".to_vec())
        );
    }

    #[tokio::test]
    async fn delete_sharing_conflict_ignores_current_open_but_blocks_on_peer_without_share_delete()
    {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", TestBackend).public())
            .build()
            .expect("build server");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        let path = "hello.txt".parse::<SmbPath>().expect("path");
        let data = Arc::new(Mutex::new(b"hello".to_vec()));
        let current = Arc::new(RwLock::new(Open::new(
            FileId::new(1, 1),
            Box::new(TestHandle {
                data: Arc::clone(&data),
            }),
            Access::ReadWrite,
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            path.clone(),
            false,
            false,
            None,
        )));
        let peer_without_share_delete = Arc::new(RwLock::new(Open::new(
            FileId::new(2, 2),
            Box::new(TestHandle { data }),
            Access::ReadWrite,
            FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            path.clone(),
            false,
            false,
            None,
        )));
        state.register_open("share", &path, None, &current, &conn);
        assert!(
            !state
                .delete_sharing_conflict("share", &path, None, Some(&current))
                .await
        );

        state.register_open("share", &path, None, &peer_without_share_delete, &conn);
        assert!(
            state
                .delete_sharing_conflict("share", &path, None, Some(&current))
                .await
        );
    }

    #[tokio::test]
    async fn write_waits_for_lease_break_ack_before_mutating() {
        const TEST_LEASE_NONE: u32 = 0;
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", TestBackend).public())
            .build()
            .expect("build server");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        *conn.dialect.write().await = Some(Dialect::Smb311);
        let (tx, mut rx) = mpsc::channel(8);
        conn.set_async_sender(tx).await;

        let session = Arc::new(RwLock::new(Session::new(
            1,
            crate::proto::auth::ntlm::Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        let share = state.find_share("share").await.expect("share");
        let tree = Arc::new(RwLock::new(TreeConnect::new(1, share, Access::ReadWrite)));
        session
            .read()
            .await
            .trees
            .write()
            .await
            .insert(1, tree.clone());
        conn.sessions.write().await.insert(1, session);

        let data = Arc::new(Mutex::new(b"hello".to_vec()));
        let path = "hello.txt".parse::<SmbPath>().expect("path");
        let lease_key = *b"0123456789abcdef";
        let leased_id = FileId::new(1, 1);
        let writer_id = FileId::new(2, 2);
        let mut leased = Open::new(
            leased_id,
            Box::new(TestHandle {
                data: Arc::clone(&data),
            }),
            Access::ReadWrite,
            FILE_WRITE_DATA | FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            path.clone(),
            false,
            false,
            None,
        );
        leased.lease_key = lease_key;
        leased.lease_state = LEASE_READ_CACHING | LEASE_WRITE_CACHING;
        leased.lease_epoch = 1;
        leased.lease_version = 2;
        let leased = Arc::new(RwLock::new(leased));
        let writer = Arc::new(RwLock::new(Open::new(
            writer_id,
            Box::new(TestHandle {
                data: Arc::clone(&data),
            }),
            Access::ReadWrite,
            FILE_WRITE_DATA | FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            path.clone(),
            false,
            false,
            None,
        )));
        tree.write()
            .await
            .opens
            .write()
            .await
            .insert(leased_id, Arc::clone(&leased));
        tree.write()
            .await
            .opens
            .write()
            .await
            .insert(writer_id, Arc::clone(&writer));
        state.register_open("share", &path, None, &leased, &conn);
        state.register_open("share", &path, None, &writer, &conn);

        let req = WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: 3,
            offset: 0,
            file_id: writer_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: b"bye".to_vec(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write request");
        let hdr = Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: Command::Write,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id: 10,
            tail: HeaderTail::sync(1),
            session_id: 1,
            signature: [0; 16],
        };
        let mut frame = Vec::new();
        hdr.write(&mut frame).expect("write header");
        frame.extend_from_slice(&body);

        let pending = dispatch::dispatch_frame(&state, &conn, &frame)
            .await
            .expect("pending response");
        let (pending_hdr, _) = Smb2Header::parse(&pending).expect("pending header");
        assert_eq!(pending_hdr.command, Command::Write);
        assert_eq!(
            pending_hdr.channel_sequence_status,
            ntstatus::STATUS_PENDING
        );
        let async_id = pending_hdr.async_id().expect("async id");

        let notification = rx.recv().await.expect("lease notification");
        let (notification_hdr, _) = Smb2Header::parse(&notification).expect("notification header");
        assert_eq!(notification_hdr.command, Command::OplockBreak);
        assert_eq!(
            notification_hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR,
            SMB2_FLAGS_SERVER_TO_REDIR
        );
        assert_eq!(&*data.lock().unwrap(), b"hello");

        assert_eq!(
            state
                .acknowledge_lease_break(lease_key, TEST_LEASE_NONE)
                .await,
            ntstatus::STATUS_SUCCESS
        );
        let final_frame = rx.recv().await.expect("final write response");
        let (final_hdr, final_body) = Smb2Header::parse(&final_frame).expect("final header");
        assert_eq!(final_hdr.command, Command::Write);
        assert_eq!(final_hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(final_hdr.async_id(), Some(async_id));
        assert_eq!(
            WriteResponse::parse(final_body)
                .expect("write response")
                .count,
            3
        );
        assert_eq!(&*data.lock().unwrap(), b"byelo");
        let leased = leased.read().await;
        assert_eq!(leased.lease_state, TEST_LEASE_NONE);
        assert!(!leased.lease_breaking);
    }
}
