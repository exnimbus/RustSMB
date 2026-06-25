//! Opt-in external CloudSoda/go-smb2 client smoke test.
//!
//! This mirrors GoSMB's `client_integration_test.go` and CloudSoda QUIC smoke
//! coverage. It is skipped by default because it requires the Go toolchain and
//! downloads the CloudSoda client module into the normal Go module cache.

use std::io;
use std::process::Output;
use std::time::Duration;

use smb_server::{Access, LocalFsBackend, Share, ShutdownHandle, SmbServer};
#[cfg(feature = "quic")]
use smb_server::{SmbQuicConfig, smb_quic_endpoint};
use tempfile::{TempDir, tempdir};
use tokio::process::Command;

#[cfg(feature = "quic")]
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const CLOUDSODA_CLIENT: &str = r#"
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	cloudsmb2 "github.com/cloudsoda/go-smb2"
)

func main() {
	if len(os.Args) != 2 {
		fatalf("usage: cloudsoda-smoke host:port")
	}
	conn, err := net.DialTimeout("tcp", os.Args[1], 2*time.Second)
	if err != nil {
		fatalf("dial tcp: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := &cloudsmb2.Dialer{
		Initiator: &cloudsmb2.NTLMInitiator{
			Domain:   "GOSMB",
			User:     "testuser",
			Password: "testpass",
		},
	}
	session, err := d.DialContext(ctx, conn)
	if err != nil {
		fatalf("dial CloudSoda client: %v", err)
	}
	defer session.Logoff()

	shares, err := session.ListSharenames()
	if err != nil {
		fatalf("list share names: %v", err)
	}
	foundShare := false
	for _, name := range shares {
		if name == "VIRTUAL" {
			foundShare = true
		}
	}
	if !foundShare {
		fatalf("VIRTUAL not found in share list: %#v", shares)
	}

	share, err := session.Mount("VIRTUAL")
	if err != nil {
		fatalf("mount virtual share: %v", err)
	}
	defer share.Umount()

	f, err := share.Open("hello.txt")
	if err != nil {
		fatalf("open hello.txt: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		_ = f.Close()
		fatalf("read hello.txt: %v", err)
	}
	if string(got) != "hello from cloudsoda smoke\n" {
		_ = f.Close()
		fatalf("read content mismatch: got %q", string(got))
	}

	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		fatalf("stat hello.txt: %v", err)
	}
	if stat.Size() != int64(len("hello from cloudsoda smoke\n")) {
		_ = f.Close()
		fatalf("stat size mismatch: got %d", stat.Size())
	}
	if stat.IsDir() {
		_ = f.Close()
		fatalf("hello.txt stat reported directory")
	}
	end, err := f.Seek(0, io.SeekEnd)
	_ = f.Close()
	if err != nil {
		fatalf("seek end: %v", err)
	}
	if end != int64(len("hello from cloudsoda smoke\n")) {
		fatalf("seek end mismatch: got %d", end)
	}

	infos, err := share.ReadDir(".")
	if err != nil {
		fatalf("read directory: %v", err)
	}
	foundFile := false
	for _, info := range infos {
		if info.Name() == "hello.txt" {
			foundFile = true
			if info.IsDir() {
				fatalf("hello.txt was returned as a directory")
			}
		}
	}
	if !foundFile {
		fatalf("hello.txt not found in directory listing: %#v", infos)
	}

	wf, err := share.Create("written.txt")
	if err != nil {
		fatalf("create written.txt: %v", err)
	}
	if _, err := wf.Write([]byte("written through cloudsoda\n")); err != nil {
		_ = wf.Close()
		fatalf("write written.txt: %v", err)
	}
	if err := wf.Close(); err != nil {
		fatalf("close written.txt after write: %v", err)
	}

	rf, err := share.Open("written.txt")
	if err != nil {
		fatalf("reopen written.txt: %v", err)
	}
	written, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		fatalf("read written.txt: %v", err)
	}
	if string(written) != "written through cloudsoda\n" {
		fatalf("written content mismatch: got %q", string(written))
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
"#;

#[cfg(feature = "quic")]
const CLOUDSODA_QUIC_CLIENT: &str = r#"
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	cloudsmb2 "github.com/cloudsoda/go-smb2"
	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) != 2 {
		fatalf("usage: cloudsoda-quic-smoke host:port")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, os.Args[1], &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"smb"},
	}, nil)
	if err != nil {
		fatalf("dial quic: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fatalf("open quic stream: %v", err)
	}
	defer stream.Close()

	d := &cloudsmb2.Dialer{
		Initiator: &cloudsmb2.NTLMInitiator{
			Domain:   "GOSMB",
			User:     "testuser",
			Password: "testpass",
		},
	}
	session, err := d.DialContext(ctx, quicStreamNetConn{
		Stream:     stream,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	})
	if err != nil {
		fatalf("dial CloudSoda over QUIC: %v", err)
	}
	defer session.Logoff()

	share, err := session.Mount("VIRTUAL")
	if err != nil {
		fatalf("mount virtual share over QUIC: %v", err)
	}
	defer share.Umount()

	f, err := share.Open("hello.txt")
	if err != nil {
		fatalf("open hello.txt over QUIC: %v", err)
	}
	got, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		fatalf("read hello.txt over QUIC: %v", err)
	}
	if string(got) != "hello from cloudsoda over quic\n" {
		fatalf("read content mismatch: got %q", string(got))
	}

	wf, err := share.Create("written.txt")
	if err != nil {
		fatalf("create written.txt over QUIC: %v", err)
	}
	if _, err := wf.Write([]byte("written through cloudsoda over quic\n")); err != nil {
		_ = wf.Close()
		fatalf("write written.txt over QUIC: %v", err)
	}
	if err := wf.Close(); err != nil {
		fatalf("close written.txt after write over QUIC: %v", err)
	}

	rf, err := share.Open("written.txt")
	if err != nil {
		fatalf("reopen written.txt over QUIC: %v", err)
	}
	written, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		fatalf("read written.txt over QUIC: %v", err)
	}
	if string(written) != "written through cloudsoda over quic\n" {
		fatalf("written content mismatch: got %q", string(written))
	}
}

type quicStreamNetConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c quicStreamNetConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c quicStreamNetConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
"#;

struct CloudSodaHarness {
    addr: String,
    shutdown: ShutdownHandle,
    serve: tokio::task::JoinHandle<io::Result<()>>,
    _root: TempDir,
}

impl CloudSodaHarness {
    async fn start() -> Option<Self> {
        if std::env::var("GOSMB_RUN_CLOUDSODA").ok().as_deref() != Some("1") {
            return None;
        }
        if Command::new("go").arg("version").output().await.is_err() {
            eprintln!("skipping CloudSoda smoke: go binary not found");
            return None;
        }

        let root = tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("hello.txt"),
            b"hello from cloudsoda smoke\n",
        )
        .expect("seed file");
        let backend = LocalFsBackend::new(root.path()).expect("open root");
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("testuser", "testpass")
            .share(Share::new("VIRTUAL", backend).user("testuser", Access::ReadWrite))
            .netbios_name("TESTSERVER")
            .encrypt_data(true)
            .build()
            .expect("build");

        server.bind().await.expect("bind");
        let addr = server.local_addr().await.expect("addr").to_string();
        let shutdown = server.shutdown_handle();
        let serve = tokio::spawn(server.serve());
        tokio::task::yield_now().await;

        Some(Self {
            addr,
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
}

#[cfg(feature = "quic")]
struct CloudSodaQuicHarness {
    addr: String,
    shutdown: ShutdownHandle,
    serve: tokio::task::JoinHandle<io::Result<()>>,
    _root: TempDir,
}

#[cfg(feature = "quic")]
impl CloudSodaQuicHarness {
    async fn start() -> Option<Self> {
        if std::env::var("GOSMB_RUN_CLOUDSODA").ok().as_deref() != Some("1") {
            return None;
        }
        if Command::new("go").arg("version").output().await.is_err() {
            eprintln!("skipping CloudSoda QUIC smoke: go binary not found");
            return None;
        }

        let root = tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("hello.txt"),
            b"hello from cloudsoda over quic\n",
        )
        .expect("seed file");
        let backend = LocalFsBackend::new(root.path()).expect("open root");
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("testuser", "testpass")
            .share(Share::new("VIRTUAL", backend).user("testuser", Access::ReadWrite))
            .netbios_name("TESTSERVER")
            .encrypt_data(true)
            .build()
            .expect("build");
        let shutdown = server.shutdown_handle();
        let endpoint = smb_quic_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            cloudsoda_quic_tls_config(),
            SmbQuicConfig::default(),
        )
        .expect("quic endpoint");
        let addr = endpoint.local_addr().expect("local addr").to_string();
        let serve = tokio::spawn(server.serve_quic(endpoint));
        tokio::task::yield_now().await;

        Some(Self {
            addr,
            shutdown,
            serve,
            _root: root,
        })
    }

    async fn stop(self) {
        self.shutdown.shutdown();
        match tokio::time::timeout(Duration::from_secs(2), self.serve).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => panic!("SMB QUIC server failed during shutdown: {err}"),
            Ok(Err(err)) => panic!("SMB QUIC server task failed: {err}"),
            Err(_) => panic!("SMB QUIC server did not stop after shutdown"),
        }
    }
}

#[tokio::test]
async fn cloudsoda_tcp_client_can_mount_read_write_virtual_share() {
    let Some(h) = CloudSodaHarness::start().await else {
        return;
    };
    let module = tempdir().expect("cloudsoda module tempdir");
    std::fs::write(
        module.path().join("go.mod"),
        "module cloudsoda-smoke\n\ngo 1.22\n\nrequire github.com/cloudsoda/go-smb2 v0.0.0-20231007014108-7d20866bfe38\n",
    )
    .expect("write go.mod");
    std::fs::write(module.path().join("main.go"), CLOUDSODA_CLIENT).expect("write main.go");

    let output = run_cloudsoda_client(&module, &h.addr).await;
    h.stop().await;
    assert_success(output);
}

#[cfg(feature = "quic")]
#[tokio::test]
async fn cloudsoda_quic_client_can_mount_read_write_virtual_share() {
    let Some(h) = CloudSodaQuicHarness::start().await else {
        return;
    };
    let module = tempdir().expect("cloudsoda quic module tempdir");
    std::fs::write(
        module.path().join("go.mod"),
        "module cloudsoda-quic-smoke\n\ngo 1.25\n\nrequire (\n\tgithub.com/cloudsoda/go-smb2 v0.0.0-20231007014108-7d20866bfe38\n\tgithub.com/quic-go/quic-go v0.60.0\n)\n",
    )
    .expect("write go.mod");
    std::fs::write(module.path().join("main.go"), CLOUDSODA_QUIC_CLIENT).expect("write main.go");

    let output = run_cloudsoda_client(&module, &h.addr).await;
    h.stop().await;
    assert_success(output);
}

async fn run_cloudsoda_client(module: &TempDir, addr: &str) -> Output {
    let mut cmd = Command::new("go");
    cmd.kill_on_drop(true)
        .arg("run")
        .arg("-mod=mod")
        .arg(".")
        .arg(addr)
        .current_dir(module.path());
    match tokio::time::timeout(Duration::from_secs(60), cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => panic!("failed to run CloudSoda client: {err}"),
        Err(_) => panic!("CloudSoda client timed out"),
    }
}

#[cfg(feature = "quic")]
fn cloudsoda_quic_tls_config() -> quinn::rustls::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert_der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], PrivateKeyDer::from(key))
        .expect("server tls")
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "CloudSoda client failed with status {:?}:\n{}",
        output.status.code(),
        output_text(&output)
    );
}

fn output_text(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}
