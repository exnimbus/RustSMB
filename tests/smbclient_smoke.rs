//! Opt-in external `smbclient` smoke tests.
//!
//! These mirror GoSMB's `smbclient_smoke_test.go` coverage and are skipped by
//! default because they require Samba's `smbclient` binary on the host.

use std::io;
use std::process::Output;
use std::time::Duration;

use smb_server::{Access, LocalFsBackend, Share, ShutdownHandle, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::process::Command;

const SMOKE_CONTENT: &[u8] = b"hello from smbclient smoke\n";

struct SmbClientHarness {
    host: String,
    port: String,
    shutdown: ShutdownHandle,
    serve: tokio::task::JoinHandle<io::Result<()>>,
    _root: TempDir,
}

impl SmbClientHarness {
    async fn start(encrypt: bool) -> Option<Self> {
        if std::env::var("GOSMB_RUN_SMBCLIENT").ok().as_deref() != Some("1") {
            return None;
        }
        if Command::new("smbclient")
            .arg("--version")
            .output()
            .await
            .is_err()
        {
            return None;
        }

        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("hello.txt"), SMOKE_CONTENT).expect("seed file");
        let backend = LocalFsBackend::new(root.path()).expect("open root");
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("testuser", "testpass")
            .share(Share::new("VIRTUAL", backend).user("testuser", Access::ReadWrite))
            .netbios_name("TESTSERVER")
            .encrypt_data(encrypt)
            .build()
            .expect("build");

        server.bind().await.expect("bind");
        let addr = server.local_addr().await.expect("addr");
        let shutdown = server.shutdown_handle();
        let serve = tokio::spawn(server.serve());
        tokio::task::yield_now().await;

        Some(Self {
            host: addr.ip().to_string(),
            port: addr.port().to_string(),
            shutdown,
            serve,
            _root: root,
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

    async fn run(&self, args: &[&str]) -> Result<Output, String> {
        self.run_with_user(r"GOSMB\testuser%testpass", args).await
    }

    async fn run_with_user(&self, user: &str, args: &[&str]) -> Result<Output, String> {
        let debug = std::env::var("GOSMB_SMBCLIENT_DEBUG").unwrap_or_else(|_| "1".to_string());
        let mut cmd = Command::new("smbclient");
        cmd.kill_on_drop(true)
            .arg("-d")
            .arg(debug)
            .arg("--debug-stdout")
            .arg("-p")
            .arg(&self.port)
            .arg("-m")
            .arg("SMB3_11")
            .arg("-U")
            .arg(user);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.arg(format!("//{}/VIRTUAL", self.host));

        match tokio::time::timeout(Duration::from_secs(15), cmd.output()).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(err)) => Err(format!("failed to run smbclient: {err}")),
            Err(_) => Err("smbclient timed out".to_string()),
        }
    }
}

fn output_text(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "smbclient failed with status {:?}:\n{}",
        output.status.code(),
        output_text(&output)
    );
}

async fn run_success(h: &SmbClientHarness, args: &[&str]) {
    let output = h.run(args).await.expect("run smbclient");
    assert_success(output);
}

#[tokio::test]
async fn smbclient_smoke_list_read_encrypt() {
    let Some(h) = SmbClientHarness::start(true).await else {
        return;
    };
    let dir = tempdir().expect("tempdir");
    let download = dir.path().join("hello.txt");
    let command = format!("ls; get hello.txt {}", download.display());

    run_success(&h, &["--client-protection=encrypt", "-c", &command]).await;
    assert_eq!(
        std::fs::read(&download).expect("read download"),
        SMOKE_CONTENT
    );

    h.stop().await;
}

#[tokio::test]
async fn smbclient_smoke_list_read_sign() {
    let Some(h) = SmbClientHarness::start(false).await else {
        return;
    };
    let dir = tempdir().expect("tempdir");
    let download = dir.path().join("hello.txt");
    let command = format!("ls; get hello.txt {}", download.display());

    run_success(&h, &["--client-protection=sign", "-c", &command]).await;
    assert_eq!(
        std::fs::read(&download).expect("read download"),
        SMOKE_CONTENT
    );

    h.stop().await;
}

#[tokio::test]
async fn smbclient_wrong_password_fails() {
    let Some(h) = SmbClientHarness::start(true).await else {
        return;
    };

    let output = h
        .run_with_user(
            r"GOSMB\testuser%wrongpass",
            &["--client-protection=encrypt", "-c", "ls"],
        )
        .await
        .expect("run smbclient");
    assert!(
        !output.status.success(),
        "wrong password succeeded unexpectedly:\n{}",
        output_text(&output)
    );

    h.stop().await;
}

#[tokio::test]
async fn smbclient_missing_file_fails() {
    let Some(h) = SmbClientHarness::start(true).await else {
        return;
    };
    let dir = tempdir().expect("tempdir");
    let download = dir.path().join("missing.txt");
    let command = format!("get missing.txt {}", download.display());

    let output = h
        .run(&["--client-protection=encrypt", "-c", &command])
        .await
        .expect("run smbclient");
    assert!(
        !output.status.success(),
        "missing file read succeeded unexpectedly:\n{}",
        output_text(&output)
    );
    assert!(
        !download.exists(),
        "missing file created local output unexpectedly"
    );

    h.stop().await;
}

#[tokio::test]
async fn smbclient_put_get_small_file() {
    let Some(h) = SmbClientHarness::start(true).await else {
        return;
    };
    let dir = tempdir().expect("tempdir");
    let local = dir.path().join("small.txt");
    let download = dir.path().join("download.txt");
    let want = b"small file written by smbclient\n";
    std::fs::write(&local, want).expect("write upload");
    let command = format!(
        "put {} uploaded-small.txt; get uploaded-small.txt {}",
        local.display(),
        download.display()
    );

    run_success(&h, &["--client-protection=encrypt", "-c", &command]).await;
    assert_eq!(std::fs::read(&download).expect("read download"), want);

    h.stop().await;
}

#[tokio::test]
async fn smbclient_put_get_large_file() {
    let Some(h) = SmbClientHarness::start(true).await else {
        return;
    };
    let dir = tempdir().expect("tempdir");
    let local = dir.path().join("large.bin");
    let download = dir.path().join("large-download.bin");
    let want = b"0123456789abcdef".repeat(8192);
    std::fs::write(&local, &want).expect("write upload");
    let command = format!(
        "put {} uploaded-large.bin; get uploaded-large.bin {}",
        local.display(),
        download.display()
    );

    run_success(&h, &["--client-protection=encrypt", "-c", &command]).await;
    assert_eq!(std::fs::read(&download).expect("read download"), want);

    h.stop().await;
}

#[tokio::test]
async fn smbclient_directory_rename_delete_flow() {
    let Some(h) = SmbClientHarness::start(true).await else {
        return;
    };
    let dir = tempdir().expect("tempdir");
    let local = dir.path().join("upload.txt");
    let download = dir.path().join("download.txt");
    let want = b"mutation flow through smbclient\n";
    std::fs::write(&local, want).expect("write upload");
    let command = format!(
        "mkdir made; put {} made/upload.txt; rename made/upload.txt made/renamed.txt; get made/renamed.txt {}; del made/renamed.txt; rmdir made",
        local.display(),
        download.display()
    );

    run_success(&h, &["--client-protection=encrypt", "-c", &command]).await;
    assert_eq!(std::fs::read(&download).expect("read download"), want);

    h.stop().await;
}
