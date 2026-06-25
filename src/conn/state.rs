//! Connection / session / tree / open state held during a single TCP
//! connection's lifetime.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::ntstatus;
use crate::proto::auth::ntlm::{Identity, NtlmServer};
use crate::proto::crypto::{PreauthIntegrity, SigningAlgo};
use crate::proto::header::{SMB2_FLAGS_RELATED_OPERATIONS, Smb2Header};
use crate::proto::messages::{Dialect, FileId};
use tokio::sync::{Mutex as AsyncMutex, RwLock, mpsc};
use uuid::Uuid;

use crate::backend::Handle;
use crate::builder::Access;
use crate::info_class::PosixMetadata;
use crate::path::SmbPath;
use crate::server::ShareBindings;

/// In-flight NTLM acceptor plus enough SPNEGO state to finish the exchange in
/// the same form the client opened with.
pub struct PendingAuthState {
    pub acceptor: NtlmServer,
    pub raw_ntlmssp: bool,
    pub mech_list: Vec<u8>,
}

pub type PendingAuth = Arc<Mutex<PendingAuthState>>;

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// One connection's negotiated state and its session/tree/open tables.
pub struct Connection {
    pub server_guid: Uuid,
    pub client_guid: tokio::sync::RwLock<Uuid>,
    pub negotiated_net_name: tokio::sync::RwLock<Option<String>>,
    pub dialect: tokio::sync::RwLock<Option<Dialect>>,
    pub client_requires_signing: tokio::sync::RwLock<bool>,
    pub signing_algo: tokio::sync::RwLock<SigningAlgo>,
    pub signing_context_present: tokio::sync::RwLock<bool>,
    pub compression_algorithms: tokio::sync::RwLock<Vec<u16>>,
    pub compression_chained: tokio::sync::RwLock<bool>,
    pub compression_algorithm: tokio::sync::RwLock<u16>,
    pub rdma_transform_ids: tokio::sync::RwLock<Vec<u16>>,
    pub posix_extensions: tokio::sync::RwLock<bool>,
    pub encryption_ciphers: tokio::sync::RwLock<Vec<u16>>,
    pub encryption_cipher: tokio::sync::RwLock<u16>,
    /// True when the underlying transport already provides confidentiality
    /// and integrity, e.g. SMB over QUIC. Direct TCP leaves this false.
    pub secure_transport: bool,
    /// SMB 3.1.1 transport capabilities accepted use of the secure transport
    /// instead of SMB transform encryption.
    pub transport_security: tokio::sync::RwLock<bool>,
    /// Connection.PreauthIntegrityHashValue after NEGOTIATE. SMB 3.1.1
    /// SESSION_SETUP exchanges fork this into `session_preauth`.
    pub preauth: Mutex<PreauthIntegrity>,
    /// Granted at NEGOTIATE: large MTU support flag etc.
    pub max_read_size: tokio::sync::RwLock<u32>,
    pub max_write_size: tokio::sync::RwLock<u32>,
    max_credits: u32,
    credit_balance: Mutex<u32>,

    /// Sessions keyed by SessionId.
    pub sessions: RwLock<HashMap<u64, Arc<RwLock<Session>>>>,
    /// Per-connection SMB signing keys for bound channels. The shared
    /// `Session` owns tree/open state, while each authenticated channel can
    /// have distinct signing/encryption material.
    pub session_signing_keys: RwLock<HashMap<u64, [u8; 16]>>,
    pub session_decrypt_keys: RwLock<HashMap<u64, Vec<u8>>>,
    pub session_encrypt_keys: RwLock<HashMap<u64, Vec<u8>>>,

    /// In-flight NTLM acceptors keyed by SessionId. We keep them out of
    /// `Session` because a session is created only after a successful first
    /// SESSION_SETUP round — between rounds the entry lives here. The
    /// `bool` records whether the client sent raw NTLMSSP (true) or
    /// SPNEGO-wrapped (false) so the second-round response matches form.
    pub pending_auths: RwLock<HashMap<u64, PendingAuth>>,

    /// In-flight SMB 3.1.1 preauth state keyed by SessionId during
    /// multi-leg SESSION_SETUP.
    pub session_preauth: RwLock<HashMap<u64, PreauthIntegrity>>,

    /// PreviousSessionId supplied on the first SESSION_SETUP leg, keyed by
    /// the newly allocated in-flight SessionId.
    pub pending_previous_session_ids: RwLock<HashMap<u64, u64>>,

    /// Sender for asynchronous SMB responses generated after the request
    /// handler has returned, e.g. CHANGE_NOTIFY completions.
    pub async_tx: RwLock<Option<mpsc::Sender<Vec<u8>>>>,
    /// Dispatch ordering gate. Simple independent READ/WRITE requests take a
    /// shared guard so they can run concurrently; compound/session/tree/control
    /// requests take an exclusive guard so connection state transitions do not
    /// race with independent workers.
    pub dispatch_gate: RwLock<()>,

    /// Monotonic SessionId allocator.
    next_session_id: AtomicU64,
    next_async_id: AtomicU64,
    pending_async_slots: AtomicUsize,
    force_unacked_timeout: AtomicBool,
    disconnect_requested: AtomicBool,
}

impl Connection {
    pub fn new(
        server_guid: Uuid,
        max_read_size: u32,
        max_write_size: u32,
        max_credits: u16,
    ) -> Self {
        Self::new_with_transport_security(
            server_guid,
            max_read_size,
            max_write_size,
            max_credits,
            false,
        )
    }

    pub fn new_with_transport_security(
        server_guid: Uuid,
        max_read_size: u32,
        max_write_size: u32,
        max_credits: u16,
        secure_transport: bool,
    ) -> Self {
        Self {
            server_guid,
            client_guid: tokio::sync::RwLock::new(Uuid::nil()),
            negotiated_net_name: tokio::sync::RwLock::new(None),
            dialect: tokio::sync::RwLock::new(None),
            client_requires_signing: tokio::sync::RwLock::new(false),
            signing_algo: tokio::sync::RwLock::new(SigningAlgo::HmacSha256),
            signing_context_present: tokio::sync::RwLock::new(false),
            compression_algorithms: tokio::sync::RwLock::new(Vec::new()),
            compression_chained: tokio::sync::RwLock::new(false),
            compression_algorithm: tokio::sync::RwLock::new(0),
            rdma_transform_ids: tokio::sync::RwLock::new(Vec::new()),
            posix_extensions: tokio::sync::RwLock::new(false),
            encryption_ciphers: tokio::sync::RwLock::new(Vec::new()),
            encryption_cipher: tokio::sync::RwLock::new(0),
            secure_transport,
            transport_security: tokio::sync::RwLock::new(false),
            preauth: Mutex::new(PreauthIntegrity::new()),
            max_read_size: tokio::sync::RwLock::new(max_read_size),
            max_write_size: tokio::sync::RwLock::new(max_write_size),
            max_credits: u32::from(max_credits.max(1)),
            credit_balance: Mutex::new(1),
            sessions: RwLock::new(HashMap::new()),
            session_signing_keys: RwLock::new(HashMap::new()),
            session_decrypt_keys: RwLock::new(HashMap::new()),
            session_encrypt_keys: RwLock::new(HashMap::new()),
            pending_auths: RwLock::new(HashMap::new()),
            session_preauth: RwLock::new(HashMap::new()),
            pending_previous_session_ids: RwLock::new(HashMap::new()),
            async_tx: RwLock::new(None),
            dispatch_gate: RwLock::new(()),
            next_session_id: AtomicU64::new(1),
            next_async_id: AtomicU64::new(1),
            pending_async_slots: AtomicUsize::new(0),
            force_unacked_timeout: AtomicBool::new(false),
            disconnect_requested: AtomicBool::new(false),
        }
    }

    pub fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn alloc_async_id(&self) -> u64 {
        self.next_async_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn try_reserve_pending_async(&self, limit: usize) -> bool {
        let mut current = self.pending_async_slots.load(Ordering::Acquire);
        loop {
            if current >= limit {
                return false;
            }
            match self.pending_async_slots.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn release_pending_async(&self) {
        let mut current = self.pending_async_slots.load(Ordering::Acquire);
        loop {
            if current == 0 {
                debug_assert!(false, "pending async slot underflow");
                return;
            }
            match self.pending_async_slots.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn enable_force_unacked_timeout(&self) {
        self.force_unacked_timeout.store(true, Ordering::Relaxed);
    }

    pub fn force_unacked_timeout(&self) -> bool {
        self.force_unacked_timeout.load(Ordering::Relaxed)
    }

    pub fn take_force_unacked_timeout(&self) -> bool {
        self.force_unacked_timeout.swap(false, Ordering::Relaxed)
    }

    pub fn request_disconnect(&self) {
        self.disconnect_requested.store(true, Ordering::Release);
    }

    pub fn disconnect_requested(&self) -> bool {
        self.disconnect_requested.load(Ordering::Acquire)
    }

    pub async fn set_async_sender(&self, tx: mpsc::Sender<Vec<u8>>) {
        *self.async_tx.write().await = Some(tx);
    }

    pub async fn clear_async_sender(&self) {
        *self.async_tx.write().await = None;
    }

    pub async fn async_sender(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.async_tx.read().await.clone()
    }

    pub fn debit_credits(&self, hdr: &Smb2Header) -> Result<(), u32> {
        if hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0 {
            return Ok(());
        }
        let charge = self.request_credit_charge(hdr);
        let mut balance = self
            .credit_balance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *balance < charge {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        *balance -= charge;
        Ok(())
    }

    pub fn grant_credits(&self, hdr: &Smb2Header) -> u16 {
        if hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0 {
            return 0;
        }
        let requested = u32::from(hdr.credit_request_response.max(1));
        let mut balance = self
            .credit_balance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let room = self.max_credits.saturating_sub(*balance);
        let grant = requested.min(room).min(u32::from(u16::MAX));
        *balance += grant;
        grant as u16
    }

    pub fn credit_balance(&self) -> u32 {
        *self
            .credit_balance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn request_credit_charge(&self, hdr: &Smb2Header) -> u32 {
        if hdr.credit_charge == 0 {
            1
        } else {
            u32::from(hdr.credit_charge)
        }
    }

    pub async fn close_session(&self, session_id: u64) -> bool {
        let removed = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&session_id)
        };
        if let Some(sess_arc) = removed {
            close_session_state(&sess_arc).await;
            true
        } else {
            false
        }
    }

    pub async fn close_tree(&self, session_id: u64, tree_id: u32) -> bool {
        let sess_arc = {
            let sessions = self.sessions.read().await;
            sessions.get(&session_id).cloned()
        };
        let Some(sess_arc) = sess_arc else {
            return false;
        };
        remove_tree_from_session(&sess_arc, tree_id).await
    }

    pub async fn close_sessions_for_user(&self, user: &str) -> usize {
        let to_remove = {
            let sessions = self.sessions.read().await;
            let mut ids = Vec::new();
            for (session_id, sess_arc) in sessions.iter() {
                let sess = sess_arc.read().await;
                if matches!(&sess.identity, Identity::User { user: session_user, .. } if session_user == user)
                {
                    ids.push(*session_id);
                }
            }
            ids
        };

        let mut removed = 0;
        for session_id in to_remove {
            if self.close_session(session_id).await {
                removed += 1;
            }
        }
        removed
    }

    pub async fn close_trees_for_share(&self, share_name: &str) -> usize {
        self.close_matching_trees(|_, tree| tree.share.name.eq_ignore_ascii_case(share_name))
            .await
    }

    pub async fn close_trees_for_user_share(&self, user: &str, share_name: &str) -> usize {
        self.close_matching_trees(|sess, tree| {
            matches!(&sess.identity, Identity::User { user: session_user, .. } if session_user == user)
                && tree.share.name.eq_ignore_ascii_case(share_name)
        })
        .await
    }

    async fn close_matching_trees(
        &self,
        matches_tree: impl Fn(&Session, &TreeConnect) -> bool,
    ) -> usize {
        let sessions: Vec<_> = {
            let sessions = self.sessions.read().await;
            sessions.values().cloned().collect()
        };

        let mut removed = 0;
        for sess_arc in sessions {
            let tree_ids = {
                let sess = sess_arc.read().await;
                let trees = sess.trees.read().await;
                let mut ids = Vec::new();
                for (tree_id, tree_arc) in trees.iter() {
                    let tree = tree_arc.read().await;
                    if matches_tree(&sess, &tree) {
                        ids.push(*tree_id);
                    }
                }
                ids
            };

            for tree_id in tree_ids {
                if remove_tree_from_session(&sess_arc, tree_id).await {
                    removed += 1;
                }
            }
        }
        removed
    }
}

pub(crate) async fn close_session_state(sess_arc: &Arc<RwLock<Session>>) {
    let sess = sess_arc.write().await;
    let trees: Vec<_> = sess.trees.write().await.drain().collect();
    for (_tree_id, tree_arc) in trees {
        close_tree_state(&tree_arc).await;
    }
}

async fn remove_tree_from_session(sess_arc: &Arc<RwLock<Session>>, tree_id: u32) -> bool {
    let removed = {
        let sess = sess_arc.read().await;
        let mut trees = sess.trees.write().await;
        trees.remove(&tree_id)
    };
    if let Some(tree_arc) = removed {
        close_tree_state(&tree_arc).await;
        true
    } else {
        false
    }
}

async fn close_tree_state(tree_arc: &Arc<RwLock<TreeConnect>>) {
    let tree = tree_arc.write().await;
    let opens: Vec<_> = tree.opens.write().await.drain().collect();
    for (_fid, open_arc) in opens {
        let mut open = open_arc.write().await;
        if let Some(handle) = open.handle.take() {
            let _ = handle.close().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub struct Session {
    pub id: u64,
    pub identity: Identity,
    pub session_base_key: [u8; 16],
    pub signing_key: [u8; 16],
    pub decrypt_key: Option<Vec<u8>>,
    pub encrypt_key: Option<Vec<u8>>,
    /// Whether SMB transform encryption keys may be derived for this session.
    pub encryption_allowed: bool,
    /// Whether signing is required for this session's traffic.
    pub signing_required: bool,
    /// True when successful SMB2 reauthentication most recently validated
    /// anonymous credentials. The channel keys stay unchanged, but selected
    /// authorization checks use the current reauth identity.
    pub reauth_anonymous: bool,
    pub trees: RwLock<HashMap<u32, Arc<RwLock<TreeConnect>>>>,
    /// 3.1.1: snapshot taken at SESSION_SETUP completion (after the request
    /// hash but before the response is hashed). Used as KDF context.
    pub preauth_snapshot: Option<[u8; 64]>,

    next_tree_id: AtomicU32,
}

impl Session {
    pub fn new(
        id: u64,
        identity: Identity,
        session_base_key: [u8; 16],
        signing_key: [u8; 16],
        signing_required: bool,
        preauth_snapshot: Option<[u8; 64]>,
    ) -> Self {
        Self {
            id,
            identity,
            session_base_key,
            signing_key,
            decrypt_key: None,
            encrypt_key: None,
            encryption_allowed: false,
            signing_required,
            reauth_anonymous: false,
            trees: RwLock::new(HashMap::new()),
            preauth_snapshot,
            next_tree_id: AtomicU32::new(1),
        }
    }

    pub fn alloc_tree_id(&self) -> u32 {
        self.next_tree_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self.identity, Identity::Anonymous)
    }
}

// ---------------------------------------------------------------------------
// TreeConnect
// ---------------------------------------------------------------------------

pub struct TreeConnect {
    pub id: u32,
    pub share: Arc<ShareBindings>,
    pub granted_access: Access,
    pub opens: RwLock<HashMap<FileId, Arc<RwLock<Open>>>>,
    next_volatile: AtomicU64,
}

impl TreeConnect {
    pub fn new(id: u32, share: Arc<ShareBindings>, granted_access: Access) -> Self {
        Self {
            id,
            share,
            granted_access,
            opens: RwLock::new(HashMap::new()),
            next_volatile: AtomicU64::new(1),
        }
    }

    pub fn alloc_file_id(&self) -> FileId {
        let v = self.next_volatile.fetch_add(1, Ordering::Relaxed);
        FileId::new(v, v)
    }
}

// ---------------------------------------------------------------------------
// Open / DirCursor
// ---------------------------------------------------------------------------

pub struct Open {
    pub file_id: FileId,
    pub handle: Option<Box<dyn Handle>>,
    pub mutation_gate: Arc<AsyncMutex<()>>,
    pub granted_access: Access,
    pub desired_access: u32,
    pub share_access: u32,
    pub last_path: SmbPath,
    pub stream_name: Option<String>,
    pub is_directory: bool,
    pub delete_on_close: bool,
    pub delete_on_close_unlinks_name: bool,
    pub posix_deleted: bool,
    pub posix_metadata: Option<PosixMetadata>,
    pub current_offset: u64,
    pub mode: u32,
    pub resilient: bool,
    pub durable: bool,
    pub durable_version: u8,
    pub durable_timeout_ms: u32,
    pub channel_sequence: u16,
    pub replay_eligible: bool,
    pub replay_consumed: bool,
    pub replay_used: bool,
    pub app_instance_id: [u8; 16],
    pub oplock_level: u8,
    pub oplock_breaking: bool,
    pub oplock_break_to: u8,
    pub create_guid: [u8; 16],
    pub create_action: u32,
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_flags: u32,
    pub lease_epoch: u16,
    pub lease_version: u8,
    pub lease_breaking: bool,
    pub lease_break_to: u32,
    pub lease_break_final_to: u32,
    pub lock_sequences: HashMap<u32, u8>,
    pub notify_started: bool,
    pub notify_enum_dir: bool,
    pub notify_recursive: bool,
    pub notify_completion_filter: u32,
    pub notify_buffer: Vec<NotifyEvent>,
    pub notify_buffer_suppressed: bool,
    pub search_state: Option<DirCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyEvent {
    pub action: u32,
    pub name: String,
    pub is_directory: bool,
}

impl Open {
    pub fn new(
        file_id: FileId,
        handle: Box<dyn Handle>,
        granted_access: Access,
        desired_access: u32,
        share_access: u32,
        last_path: SmbPath,
        is_directory: bool,
        delete_on_close: bool,
        posix_metadata: Option<PosixMetadata>,
    ) -> Self {
        Self {
            file_id,
            handle: Some(handle),
            mutation_gate: Arc::new(AsyncMutex::new(())),
            granted_access,
            desired_access,
            share_access,
            last_path,
            stream_name: None,
            is_directory,
            delete_on_close,
            delete_on_close_unlinks_name: delete_on_close,
            posix_deleted: false,
            posix_metadata,
            current_offset: 0,
            mode: 0,
            resilient: false,
            durable: false,
            durable_version: 0,
            durable_timeout_ms: 0,
            channel_sequence: 0,
            replay_eligible: false,
            replay_consumed: false,
            replay_used: false,
            app_instance_id: [0; 16],
            oplock_level: 0,
            oplock_breaking: false,
            oplock_break_to: 0,
            create_guid: [0; 16],
            create_action: 0,
            lease_key: [0; 16],
            lease_state: 0,
            lease_flags: 0,
            lease_epoch: 0,
            lease_version: 0,
            lease_breaking: false,
            lease_break_to: 0,
            lease_break_final_to: 0,
            lock_sequences: HashMap::new(),
            notify_started: false,
            notify_enum_dir: false,
            notify_recursive: false,
            notify_completion_filter: 0,
            notify_buffer: Vec::new(),
            notify_buffer_suppressed: false,
            search_state: None,
        }
    }

    pub fn replayed_lock_sequence(&mut self, dialect: Option<Dialect>, lock_sequence: u32) -> bool {
        let Some((index, number)) = self.lock_sequence_parts(dialect, lock_sequence) else {
            return false;
        };
        match self.lock_sequences.get(&index).copied() {
            Some(stored) if stored == number => true,
            Some(_) => {
                self.lock_sequences.remove(&index);
                false
            }
            None => false,
        }
    }

    pub fn record_lock_sequence(&mut self, dialect: Option<Dialect>, lock_sequence: u32) {
        let Some((index, number)) = self.lock_sequence_parts(dialect, lock_sequence) else {
            return;
        };
        self.lock_sequences.insert(index, number);
    }

    fn lock_sequence_parts(
        &self,
        dialect: Option<Dialect>,
        lock_sequence: u32,
    ) -> Option<(u32, u8)> {
        if dialect == Some(Dialect::Smb202) || !(self.resilient || self.durable) {
            return None;
        }
        let index = lock_sequence >> 4;
        if !(1..=64).contains(&index) {
            return None;
        }
        Some((index, (lock_sequence & 0x0f) as u8))
    }
}

/// Iterator state for a directory listing across multiple QUERY_DIRECTORY
/// calls. We snapshot the entries once and consume them in order; subsequent
/// calls advance `next` until exhaustion.
pub struct DirCursor {
    pub entries: Vec<crate::backend::DirEntry>,
    pub next: usize,
    /// The pattern fixed on the first scan; `RESTART_SCANS` resets `next`.
    pub pattern: Option<String>,
}
