//! Opt-in external `smbutil` smoke test.
//!
//! This mirrors GoSMB's `smbutil view` smoke coverage. It is skipped by
//! default because macOS `smbutil` requires port 445 for this flow. Set
//! `GOSMB_REQUIRE_SMBUTIL=1` with `GOSMB_RUN_SMBUTIL=1` to fail instead of
//! skipping when the real client path cannot run.

use std::io;
use std::path::PathBuf;
use std::process::Output;
use std::time::Duration;

use smb_server::{Access, LocalFsBackend, Share, ShutdownHandle, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::process::Command;

const SMOKE_CONTENT: &[u8] = b"hello from smbutil smoke\n";

struct SmbUtilHarness {
    home: TempDir,
    shutdown: ShutdownHandle,
    serve: tokio::task::JoinHandle<io::Result<()>>,
    _root: TempDir,
}

impl SmbUtilHarness {
    async fn start() -> Result<Option<Self>, String> {
        let run = std::env::var("GOSMB_RUN_SMBUTIL").ok().as_deref() == Some("1");
        let require = std::env::var("GOSMB_REQUIRE_SMBUTIL").ok().as_deref() == Some("1");
        if !run {
            return if require {
                Err("GOSMB_REQUIRE_SMBUTIL=1 requires GOSMB_RUN_SMBUTIL=1".to_string())
            } else {
                Ok(None)
            };
        }
        if Command::new("smbutil").arg("help").output().await.is_err() {
            return if require {
                Err("smbutil not found".to_string())
            } else {
                Ok(None)
            };
        }

        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("hello.txt"), SMOKE_CONTENT).expect("seed file");
        let backend = LocalFsBackend::new(root.path()).expect("open root");
        let server = SmbServer::builder()
            .listen("127.0.0.1:445".parse().unwrap())
            .user("testuser", "testpass")
            .share(Share::new("VIRTUAL", backend).user("testuser", Access::ReadWrite))
            .netbios_name("TESTSERVER")
            .build()
            .expect("build");

        if let Err(err) = server.bind().await {
            eprintln!("skipping smbutil smoke: could not bind 127.0.0.1:445: {err}");
            return if require {
                Err(format!(
                    "could not bind 127.0.0.1:445 for real smbutil smoke: {err}"
                ))
            } else {
                Ok(None)
            };
        }

        let home = tempdir().expect("home tempdir");
        write_nsmb_conf(home.path().join("Library/Preferences/nsmb.conf"));

        let shutdown = server.shutdown_handle();
        let serve = tokio::spawn(server.serve());
        tokio::task::yield_now().await;

        Ok(Some(Self {
            home,
            shutdown,
            serve,
            _root: root,
        }))
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
        let mut cmd = Command::new("smbutil");
        cmd.kill_on_drop(true).env("HOME", self.home.path());
        for arg in args {
            cmd.arg(arg);
        }

        match tokio::time::timeout(Duration::from_secs(15), cmd.output()).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(err)) => Err(format!("failed to run smbutil: {err}")),
            Err(_) => Err("smbutil timed out".to_string()),
        }
    }
}

fn write_nsmb_conf(path: PathBuf) {
    let parent = path.parent().expect("nsmb parent");
    std::fs::create_dir_all(parent).expect("create nsmb prefs dir");
    std::fs::write(
        path,
        "[default]\nport445=no_netbios\nprotocol_vers_map=4\nminauth=ntlmv2\nvalidate_neg_off=yes\nmc_on=no\n",
    )
    .expect("write nsmb.conf");
}

fn output_text(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

#[tokio::test]
async fn smbutil_view_lists_virtual_share() {
    let h = match SmbUtilHarness::start().await {
        Ok(Some(h)) => h,
        Ok(None) => return,
        Err(err) => panic!("{err}"),
    };

    let output = h
        .run(&["view", "-f", "//GOSMB;testuser:testpass@127.0.0.1"])
        .await
        .expect("run smbutil");
    assert!(
        output.status.success(),
        "smbutil view failed with status {:?}:\n{}",
        output.status.code(),
        output_text(&output)
    );
    let text = output_text(&output);
    assert!(
        text.contains("VIRTUAL"),
        "smbutil view did not list VIRTUAL share:\n{text}"
    );

    h.stop().await;
}
