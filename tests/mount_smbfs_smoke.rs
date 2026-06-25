//! Opt-in external `mount_smbfs` smoke tests.
//!
//! These mirror GoSMB's Darwin mount smoke coverage. They are skipped by
//! default because they require macOS, `mount_smbfs`, and local mount rights.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
#[path = "common/mod.rs"]
mod common;

#[cfg(target_os = "macos")]
mod macos {
    use std::io::{self, Write};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::process::Output;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use smb_server::wire::header::Command as SmbCommand;
    use smb_server::wire::messages::{CloseRequest, CreateRequest, CreateResponse};
    use smb_server::{LocalFsBackend, Share, ShutdownHandle, SmbServer};
    use tempfile::{TempDir, tempdir};
    use tokio::net::TcpStream;
    use tokio::process::Command;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    use super::common::{
        STATUS_SUCCESS, anonymous_session_setup, build_header, negotiate, parse_response_header,
        read_frame, tree_connect, utf16le, write_frame,
    };

    const SMOKE_CONTENT: &[u8] = b"hello from mount_smbfs smoke\n";
    const SYNCED_CONTENT: &[u8] = b"synced through mount_smbfs\n";
    const NOTIFY_CONTENT: &[u8] = b"notified through SMB\n";

    static TRACE_LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    static MOUNT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(Clone)]
    struct LogWriter {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for LogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner
                .lock()
                .expect("trace lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct LogMakeWriter {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for LogMakeWriter {
        type Writer = LogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogWriter {
                inner: self.inner.clone(),
            }
        }
    }

    fn trace_log() -> Arc<Mutex<Vec<u8>>> {
        let log = TRACE_LOG.get_or_init(|| {
            let log = Arc::new(Mutex::new(Vec::new()));
            let _ = tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .with_writer(LogMakeWriter { inner: log.clone() })
                .without_time()
                .try_init();
            log
        });
        log.lock().expect("trace lock").clear();
        log.clone()
    }

    fn trace_text(log: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8_lossy(&log.lock().expect("trace lock")).into_owned()
    }

    struct MountHarness {
        host: String,
        port: u16,
        home: TempDir,
        root: TempDir,
        shutdown: ShutdownHandle,
        serve: tokio::task::JoinHandle<io::Result<()>>,
        trace: Arc<Mutex<Vec<u8>>>,
    }

    impl MountHarness {
        async fn start(encrypt: bool) -> Option<Self> {
            if std::env::var("GOSMB_RUN_MOUNT_SMBFS").ok().as_deref() != Some("1") {
                return None;
            }
            if Command::new("mount_smbfs")
                .arg("-h")
                .output()
                .await
                .is_err()
            {
                return None;
            }

            let trace = trace_log();
            let root = tempdir().expect("tempdir");
            std::fs::write(root.path().join("hello.txt"), SMOKE_CONTENT).expect("seed file");
            let backend = LocalFsBackend::new(root.path()).expect("open root");
            let server = SmbServer::builder()
                .listen("127.0.0.1:0".parse().unwrap())
                .user("testuser", "testpass")
                .share(Share::new("VIRTUAL", backend).public())
                .netbios_name("TESTSERVER")
                .encrypt_data(encrypt)
                .build()
                .expect("build");

            server.bind().await.expect("bind");
            let addr = server.local_addr().await.expect("addr");
            let home = tempdir().expect("home tempdir");
            write_nsmb_conf(home.path().join("Library/Preferences/nsmb.conf"));
            let shutdown = server.shutdown_handle();
            let serve = tokio::spawn(server.serve());
            tokio::task::yield_now().await;

            Some(Self {
                host: addr.ip().to_string(),
                port: addr.port(),
                home,
                root,
                shutdown,
                serve,
                trace,
            })
        }

        async fn stop(self) {
            self.shutdown.shutdown();
            match tokio::time::timeout(Duration::from_secs(2), self.serve).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(err))) => panic!("SMB server failed during shutdown: {err}"),
                Ok(Err(err)) => panic!("SMB server task failed: {err}"),
                Err(_) => panic!("SMB server did not stop after shutdown"),
            }
        }

        async fn mount(&self) -> MountedShare {
            let parent = tempdir().expect("mount parent tempdir");
            let mount_point = parent.path().join("mnt");
            std::fs::create_dir(&mount_point).expect("create mount point");
            let url = format!(
                "//GOSMB;testuser:testpass@{}:{}/VIRTUAL",
                self.host, self.port
            );
            let output = run_command(
                &self.home,
                Duration::from_secs(15),
                "mount_smbfs",
                &[&url, mount_point.to_str().expect("mount path")],
            )
            .await
            .expect("run mount_smbfs");
            assert_success("mount_smbfs", &output);

            MountedShare {
                mount_point,
                _parent: parent,
            }
        }

        async fn create_file_over_smb(&self, name: &str, data: &[u8]) {
            let mut s = TcpStream::connect((self.host.as_str(), self.port))
                .await
                .expect("connect raw SMB trigger");
            let _ = negotiate(&mut s).await;
            let session_id = anonymous_session_setup(&mut s).await;
            let tree_id =
                tree_connect(&mut s, &format!(r"\\{}\VIRTUAL", self.host), session_id, 3).await;
            let file_id = create_file(&mut s, session_id, tree_id, 4, name, data).await;
            close_file(&mut s, session_id, tree_id, 5, file_id).await;
        }
    }

    struct MountedShare {
        mount_point: PathBuf,
        _parent: TempDir,
    }

    impl MountedShare {
        async fn unmount(self, home: &TempDir) {
            let mount = self.mount_point.to_string_lossy().into_owned();
            let output = run_command(home, Duration::from_secs(10), "umount", &[&mount])
                .await
                .expect("run umount");
            assert_success("umount", &output);
        }
    }

    fn write_nsmb_conf(path: PathBuf) {
        let parent = path.parent().expect("nsmb parent");
        std::fs::create_dir_all(parent).expect("create nsmb prefs dir");
        std::fs::write(
            path,
            "[default]\nprotocol_vers_map=4\nminauth=ntlmv2\nvalidate_neg_off=yes\nmc_on=no\n",
        )
        .expect("write nsmb.conf");
    }

    async fn run_command(
        home: &TempDir,
        timeout: Duration,
        program: &str,
        args: &[&str],
    ) -> Result<Output, String> {
        let mut cmd = Command::new(program);
        cmd.kill_on_drop(true).env("HOME", home.path()).args(args);
        match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(err)) => Err(format!("failed to run {program}: {err}")),
            Err(_) => Err(format!("{program} timed out")),
        }
    }

    fn output_text(output: &Output) -> String {
        let mut text = String::new();
        text.push_str(&String::from_utf8_lossy(&output.stdout));
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text
    }

    fn assert_success(program: &str, output: &Output) {
        assert!(
            output.status.success(),
            "{program} failed with status {:?}:\n{}",
            output.status.code(),
            output_text(output)
        );
    }

    async fn create_file(
        s: &mut TcpStream,
        session_id: u64,
        tree_id: u32,
        message_id: u64,
        name: &str,
        data: &[u8],
    ) -> smb_server::wire::messages::FileId {
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0012_0089 | 0x0012_0116,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 5,
            create_options: 0,
            name_offset: 0x78,
            name_length: utf16le(name).len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: utf16le(name),
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write create");
        let hdr = build_header(SmbCommand::Create, message_id, session_id, tree_id);
        write_frame(s, &hdr, &body).await;
        let resp = read_frame(s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, SmbCommand::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let file_id = CreateResponse::parse(rb).expect("parse create").file_id;

        let req = smb_server::wire::messages::WriteRequest {
            structure_size: 49,
            data_offset: smb_server::wire::messages::WriteRequest::STANDARD_DATA_OFFSET,
            length: data.len() as u32,
            offset: 0,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write write request");
        let hdr = build_header(SmbCommand::Write, message_id + 10, session_id, tree_id);
        write_frame(s, &hdr, &body).await;
        let resp = read_frame(s).await;
        let (rh, _) = parse_response_header(&resp);
        assert_eq!(rh.command, SmbCommand::Write);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        file_id
    }

    async fn close_file(
        s: &mut TcpStream,
        session_id: u64,
        tree_id: u32,
        message_id: u64,
        file_id: smb_server::wire::messages::FileId,
    ) {
        let req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write close");
        let hdr = build_header(SmbCommand::Close, message_id, session_id, tree_id);
        write_frame(s, &hdr, &body).await;
        let resp = read_frame(s).await;
        let (rh, _) = parse_response_header(&resp);
        assert_eq!(rh.command, SmbCommand::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    }

    fn wait_for_trace(log: &Arc<Mutex<Vec<u8>>>, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if trace_text(log).contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn wait_for_entry(dir: &Path, name: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if entry.file_name() == name {
                        return true;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn fsync_file(file: &std::fs::File) -> io::Result<()> {
        unsafe extern "C" {
            fn fsync(fd: i32) -> i32;
        }

        if unsafe { fsync(file.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    async fn mount_and_verify(encrypt: bool) {
        let Some(h) = MountHarness::start(encrypt).await else {
            return;
        };
        let mounted = h.mount().await;

        let listing = run_command(
            &h.home,
            Duration::from_secs(10),
            "ls",
            &["-la", mounted.mount_point.to_str().expect("mount path")],
        )
        .await
        .expect("run ls");
        assert_success("ls", &listing);
        assert!(
            output_text(&listing).contains("hello.txt"),
            "mounted listing did not include hello.txt:\n{}",
            output_text(&listing)
        );

        assert_eq!(
            std::fs::read(mounted.mount_point.join("hello.txt")).expect("read mounted hello.txt"),
            SMOKE_CONTENT
        );

        let synced_path = mounted.mount_point.join("synced.txt");
        std::fs::write(&synced_path, SYNCED_CONTENT).expect("write mounted synced.txt");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&synced_path)
            .expect("open mounted synced.txt");
        fsync_file(&file).expect("fsync mounted synced.txt");
        drop(file);
        assert_eq!(
            std::fs::read(h.root.path().join("synced.txt")).expect("read backend synced.txt"),
            SYNCED_CONTENT
        );
        assert!(
            wait_for_trace(&h.trace, "cmd=Flush", Duration::from_secs(5)),
            "mount_smbfs sync did not issue SMB FLUSH\ntrace:\n{}",
            trace_text(&h.trace)
        );

        mounted.unmount(&h.home).await;
        h.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mount_smbfs_smoke_unencrypted() {
        let _guard = MOUNT_TEST_LOCK.lock().await;
        mount_and_verify(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mount_smbfs_smoke_encrypted() {
        let _guard = MOUNT_TEST_LOCK.lock().await;
        mount_and_verify(true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mount_smbfs_change_notify_reveals_smb_created_file() {
        let _guard = MOUNT_TEST_LOCK.lock().await;
        let Some(h) = MountHarness::start(false).await else {
            return;
        };
        let mounted = h.mount().await;
        let _ = std::fs::read_dir(&mounted.mount_point).expect("read mounted directory");
        let saw_notify = wait_for_trace(&h.trace, "cmd=ChangeNotify", Duration::from_secs(5));

        const NOTIFIED_NAME: &str = "server-notify.txt";
        h.create_file_over_smb(NOTIFIED_NAME, NOTIFY_CONTENT).await;

        assert!(
            wait_for_entry(&mounted.mount_point, NOTIFIED_NAME, Duration::from_secs(5)),
            "mounted directory did not reveal notified file\ntrace:\n{}",
            trace_text(&h.trace)
        );
        assert!(
            saw_notify || trace_text(&h.trace).contains("cmd=ChangeNotify"),
            "mount_smbfs did not issue SMB CHANGE_NOTIFY\ntrace:\n{}",
            trace_text(&h.trace)
        );

        mounted.unmount(&h.home).await;
        h.stop().await;
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn mount_smbfs_smoke_is_macos_only() {}
