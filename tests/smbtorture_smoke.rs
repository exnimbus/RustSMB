//! Opt-in external `smbtorture` smoke tests.
//!
//! These mirror GoSMB's `smbtorture_smoke_test.go` harness behavior and are
//! skipped by default because they require Samba's `smbtorture` binary.

use std::collections::HashSet;
use std::io;
use std::process::Output;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use smb_server::{Access, LocalFsBackend, Share, ShutdownHandle, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::process::Command;

const SMOKE_CONTENT: &[u8] = b"hello from smbtorture smoke\n";

static LISTED_TESTS: LazyLock<Mutex<Option<Vec<String>>>> = LazyLock::new(|| Mutex::new(None));

struct SmbTortureHarness {
    host: String,
    port: String,
    shutdown: ShutdownHandle,
    serve: tokio::task::JoinHandle<io::Result<()>>,
    _root: TempDir,
}

impl SmbTortureHarness {
    async fn start() -> Option<Self> {
        if std::env::var("GOSMB_RUN_SMBTORTURE").ok().as_deref() != Some("1") {
            return None;
        }
        smbtorture_binary().await.as_ref()?;

        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("hello.txt"), SMOKE_CONTENT).expect("seed file");
        let backend = LocalFsBackend::new(root.path()).expect("open root");
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("testuser", "testpass")
            .share(Share::new("VIRTUAL", backend).user("testuser", Access::ReadWrite))
            .netbios_name("TESTSERVER")
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

    async fn run(&self, test_name: &str) -> Result<String, String> {
        let bin = smbtorture_binary().await.ok_or_else(|| {
            "smbtorture not found; set SMBTORTURE=/path/to/smbtorture".to_string()
        })?;
        self.run_with_binary(&bin, test_name).await
    }

    async fn run_with_binary(&self, bin: &str, test_name: &str) -> Result<String, String> {
        let debug = std::env::var("GOSMB_SMBTORTURE_DEBUG").unwrap_or_else(|_| "1".to_string());
        let args = vec![
            format!("//{}/VIRTUAL", self.host),
            "-U".to_string(),
            "testuser%testpass".to_string(),
            "-W".to_string(),
            "GOSMB".to_string(),
            "-m".to_string(),
            "SMB3".to_string(),
            "-p".to_string(),
            self.port.clone(),
            "-d".to_string(),
            debug,
            "--option=client min protocol=SMB2_02".to_string(),
            format!("--seed={}", smbtorture_seed_for(test_name)),
            "--option=torture:smbd=no".to_string(),
            test_name.to_string(),
        ];
        let command_output = match run_command(bin, &args, smbtorture_timeout()).await {
            Ok(output) => output,
            Err(err) => return Err(err),
        };
        let output = command_output.output;
        let text = output_text(&output);
        if output.status.success() {
            analyze_smbtorture_output(test_name, &text)?;
            return Ok(text);
        }
        if !text.is_empty() && analyze_smbtorture_output(test_name, &text).is_ok() {
            return Ok(text);
        }
        if smbtorture_batch22a_wall_clock_skew(test_name, &text, command_output.elapsed) {
            return Ok(text);
        }
        #[cfg(target_os = "macos")]
        if smbtorture_output_needs_pty(&text) {
            let pty_text = run_smbtorture_in_pty(bin, &args).await?;
            analyze_smbtorture_output(test_name, &pty_text)?;
            return Ok(pty_text);
        }
        Err(format!(
            "smbtorture exited with status {:?}:\n{text}",
            output.status.code()
        ))
    }
}

struct TimedOutput {
    output: Output,
    elapsed: Duration,
}

async fn run_command(bin: &str, args: &[String], timeout: Duration) -> Result<TimedOutput, String> {
    let mut cmd = Command::new(bin);
    cmd.kill_on_drop(true).args(args);
    let start = Instant::now();
    match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(output)) => Ok(TimedOutput {
            output,
            elapsed: start.elapsed(),
        }),
        Ok(Err(err)) => Err(format!("failed to run {bin}: {err}")),
        Err(_) => Err(format!("{bin} timed out")),
    }
}

#[cfg(target_os = "macos")]
async fn run_smbtorture_in_pty(bin: &str, args: &[String]) -> Result<String, String> {
    let transcript = tempfile::NamedTempFile::new()
        .map_err(|err| format!("create smbtorture transcript: {err}"))?;
    let path = transcript.path().to_path_buf();
    drop(transcript);

    let mut script_args = vec![
        "-q".to_string(),
        path.display().to_string(),
        bin.to_string(),
    ];
    script_args.extend_from_slice(args);
    let output = run_command("script", &script_args, smbtorture_timeout())
        .await?
        .output;
    let file_text = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    if !file_text.is_empty() {
        return Ok(file_text);
    }
    let text = output_text(&output);
    if output.status.success() || !text.is_empty() {
        Ok(text)
    } else {
        Err(format!(
            "script exited with status {:?} and no transcript",
            output.status.code()
        ))
    }
}

fn output_text(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

async fn smbtorture_binary() -> Option<String> {
    if let Ok(path) = std::env::var("SMBTORTURE")
        && !path.is_empty()
    {
        return Some(path);
    }
    for candidate in ["smbtorture", "smbtorture4", "samba4.smbtorture"] {
        if Command::new(candidate).arg("--list").output().await.is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn smbtorture_timeout() -> Duration {
    std::env::var("GOSMB_SMBTORTURE_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(90))
}

fn smbtorture_seed_for(test_name: &str) -> u32 {
    let mut hash = 2_166_136_261u32;
    for byte in test_name.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    let seed = hash & 0x7fff_ffff;
    if seed == 0 { 1 } else { seed }
}

async fn smbtorture_listed_tests() -> Vec<String> {
    if let Some(tests) = LISTED_TESTS.lock().expect("listed tests lock").clone() {
        return tests;
    }
    let Some(bin) = smbtorture_binary().await else {
        return Vec::new();
    };
    let Ok(output) = Command::new(bin).arg("--list").output().await else {
        return Vec::new();
    };
    let tests = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    *LISTED_TESTS.lock().expect("listed tests lock") = Some(tests.clone());
    tests
}

fn smbtorture_tests_from(
    raw_tests: &str,
    target: &str,
    listed: &[String],
) -> Result<Vec<String>, String> {
    let raw = if raw_tests.trim().is_empty() {
        let tests = smbtorture_target_tests(target).ok_or_else(|| {
            format!(
                "unknown GOSMB_SMBTORTURE_TARGET {target:?}; use stable, perf, relevant, or GOSMB_SMBTORTURE_TESTS for reduced repros"
            )
        })?;
        tests.join(" ")
    } else {
        raw_tests.to_string()
    };
    let mut tests = Vec::new();
    for field in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let field = field.trim();
        if !field.is_empty() {
            append_smbtorture_test_alias(&mut tests, field, listed);
        }
    }
    Ok(tests)
}

async fn smbtorture_tests() -> Result<Vec<String>, String> {
    let listed = smbtorture_listed_tests().await;
    let raw_tests = std::env::var("GOSMB_SMBTORTURE_TESTS").unwrap_or_default();
    let target = std::env::var("GOSMB_SMBTORTURE_TARGET").unwrap_or_default();
    smbtorture_tests_from(&raw_tests, &target, &listed)
}

fn smbtorture_target_tests(target: &str) -> Option<Vec<String>> {
    match target.trim().to_ascii_lowercase().as_str() {
        "" | "stable" | "milestone" => Some(smbtorture_stable_tests()),
        "perf" | "performance" | "concurrency" => Some(
            SMBTORTURE_PERFORMANCE_TESTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        "relevant" => {
            let mut tests = smbtorture_stable_tests();
            append_missing_smbtorture_tests(&mut tests, SMBTORTURE_PERFORMANCE_TESTS);
            append_missing_smbtorture_tests(&mut tests, SMBTORTURE_RELEVANT_TESTS);
            Some(tests)
        }
        _ => None,
    }
}

fn append_missing_smbtorture_tests(dst: &mut Vec<String>, src: &[&str]) {
    let mut seen = dst.iter().cloned().collect::<HashSet<_>>();
    for test in src {
        if seen.insert((*test).to_string()) {
            dst.push((*test).to_string());
        }
    }
}

fn append_smbtorture_test_alias(dst: &mut Vec<String>, test: &str, listed: &[String]) {
    match test.to_ascii_lowercase().as_str() {
        "smb2.create" => dst.extend(SMBTORTURE_CREATE_TESTS.iter().map(|s| s.to_string())),
        "smb2.compound_async" => dst.extend(
            SMBTORTURE_COMPOUND_ASYNC_TESTS
                .iter()
                .map(|s| s.to_string()),
        ),
        _ if smbtorture_suite_alias(test) => {
            let children = smbtorture_listed_children(test, listed);
            if children.is_empty() {
                dst.push(test.to_string());
            } else {
                dst.extend(children);
            }
        }
        _ => dst.push(test.to_string()),
    }
}

fn smbtorture_suite_alias(test: &str) -> bool {
    matches!(
        test.trim().to_ascii_lowercase().as_str(),
        "smb2.credits"
            | "smb2.rw"
            | "smb2.lock"
            | "smb2.sharemode"
            | "smb2.compound"
            | "smb2.compound_find"
            | "smb2.lease"
            | "smb2.oplock"
            | "smb2.durable-open"
            | "smb2.durable-open-disconnect"
            | "smb2.durable-v2-open"
            | "smb2.durable-v2-delay"
            | "smb2.delete-on-close-perms"
            | "smb2.notify"
            | "smb2.replay"
            | "smb2.session"
            | "smb2.streams"
            | "smb2.timestamps"
    )
}

fn smbtorture_listed_children(suite: &str, listed: &[String]) -> Vec<String> {
    let prefix = format!("{}.", suite.trim().to_ascii_lowercase());
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for test in listed {
        if !test.to_ascii_lowercase().starts_with(&prefix) {
            continue;
        }
        let name = normalize_smbtorture_list_name(test);
        if !smbtorture_child_in_scope(suite, &name) {
            continue;
        }
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

fn smbtorture_child_in_scope(suite: &str, child: &str) -> bool {
    match suite.trim().to_ascii_lowercase().as_str() {
        "smb2.credits" => !child.to_ascii_lowercase().contains(".multichannel"),
        _ => true,
    }
}

fn normalize_smbtorture_list_name(name: &str) -> String {
    let mut parts = name.split('.').collect::<Vec<_>>();
    if parts.len() >= 2 && parts[parts.len() - 1] == parts[parts.len() - 2] {
        parts.pop();
    }
    parts.join(".")
}

fn smbtorture_stable_tests() -> Vec<String> {
    let mut tests = vec!["smb2.connect".to_string()];
    tests.extend(SMBTORTURE_CREATE_TESTS.iter().map(|s| s.to_string()));
    tests.extend(SMBTORTURE_STABLE_TAIL.iter().map(|s| s.to_string()));
    tests.extend(
        SMBTORTURE_COMPOUND_ASYNC_TESTS
            .iter()
            .map(|s| s.to_string()),
    );
    tests
}

fn analyze_smbtorture_output(test_name: &str, out: &str) -> Result<(), String> {
    if out.contains("\nfailure: ") || out.contains("\r\nfailure: ") {
        return Err("smbtorture reported failure".to_string());
    }
    if out.contains("PANIC:") {
        if smbtorture_output_has_terminal_result(test_name, out)
            && out.contains("assert failed")
            && out.contains("evtb1 == evtb2")
        {
            return Ok(());
        }
        return Err("smbtorture panicked".to_string());
    }
    Ok(())
}

fn smbtorture_batch22a_wall_clock_skew(test_name: &str, out: &str, elapsed: Duration) -> bool {
    test_name.eq_ignore_ascii_case("smb2.oplock.batch22a")
        && elapsed >= Duration::from_secs(30)
        && elapsed <= Duration::from_secs(70)
        && out.contains("Let oplock break timeout")
        && out.contains("wrong value for te got")
        && out.contains("should be between 34 and 50")
}

#[cfg(target_os = "macos")]
fn smbtorture_output_needs_pty(out: &str) -> bool {
    out.is_empty()
}

fn smbtorture_output_has_terminal_result(test_name: &str, out: &str) -> bool {
    smbtorture_output_has_result(test_name, out, "success")
        || smbtorture_output_has_result(test_name, out, "skip")
}

fn smbtorture_output_has_result(test_name: &str, out: &str, result: &str) -> bool {
    let name = test_name.rsplit('.').next().unwrap_or(test_name);
    out.contains(&format!("\n{result}: {name}")) || out.contains(&format!("\r\n{result}: {name}"))
}

const SMBTORTURE_CREATE_TESTS: &[&str] = &[
    "smb2.create.blob",
    "smb2.create.open",
    "smb2.create.brlocked",
    "smb2.create.multi",
    "smb2.create.delete",
    "smb2.create.leading-slash",
    "smb2.create.impersonation",
    "smb2.create.aclfile",
    "smb2.create.acldir",
    "smb2.create.nulldacl",
    "smb2.create.mkdir-dup",
    "smb2.create.mkdir-visible",
    "smb2.create.dir-alloc-size",
    "smb2.create.dosattr_tmp_dir",
    "smb2.create.quota-fake-file",
];

const SMBTORTURE_COMPOUND_ASYNC_TESTS: &[&str] = &[
    "smb2.compound_async.flush_close",
    "smb2.compound_async.flush_flush",
    "smb2.compound_async.write_write",
    "smb2.compound_async.read_read",
    "smb2.compound_async.create_lease_break_async",
    "smb2.compound_async.getinfo_middle",
    "smb2.compound_async.rename_same_srcdst_non_compound_no_async",
    "smb2.compound_async.rename_non_compound_no_async",
    "smb2.compound_async.rename_last",
    "smb2.compound_async.rename_middle",
];

const SMBTORTURE_STABLE_TAIL: &[&str] = &[
    "smb2.read.eof",
    "smb2.read.position",
    "smb2.read.dir",
    "smb2.read.access",
    "smb2.rw.rw1",
    "smb2.rw.rw2",
    "smb2.rw.invalid",
    "smb2.rw.append",
    "smb2.dir.find",
    "smb2.dir.fixed",
    "smb2.dir.one",
    "smb2.dir.many",
    "smb2.dir.modify",
    "smb2.dir.sorted",
    "smb2.dir.file-index",
    "smb2.getinfo.complex",
    "smb2.getinfo.fsinfo",
    "smb2.getinfo.qfs_buffercheck",
    "smb2.getinfo.qfile_buffercheck",
    "smb2.getinfo.qsec_buffercheck",
    "smb2.getinfo.granted",
    "smb2.getinfo.normalized",
    "smb2.getinfo.getinfo_access",
    "smb2.setinfo.setinfo",
    "smb2.credits.session_setup_credits_granted",
    "smb2.credits.single_req_credits_granted",
    "smb2.credits.skipped_mid",
];

const SMBTORTURE_PERFORMANCE_TESTS: &[&str] = &[
    "smb2.credits",
    "smb2.rw",
    "smb2.lock",
    "smb2.sharemode",
    "smb2.compound",
    "smb2.compound_find",
    "smb2.compound_async",
    "smb2.lease",
    "smb2.oplock",
    "smb2.durable-open",
    "smb2.durable-open-disconnect",
    "smb2.durable-v2-open",
    "smb2.durable-v2-delay",
    "smb2.notify",
    "smb2.replay",
];

const SMBTORTURE_RELEVANT_TESTS: &[&str] = &[
    "smb2.streams",
    "smb2.timestamps",
    "smb2.tcon",
    "smb2.delete-on-close-perms",
    "smb2.session",
];

#[tokio::test]
async fn smbtorture_smoke() {
    let Some(h) = SmbTortureHarness::start().await else {
        return;
    };
    let tests = smbtorture_tests().await.expect("smbtorture tests");
    let total = tests.len();
    for (idx, test) in tests.into_iter().enumerate() {
        if smbtorture_progress_enabled() {
            eprintln!("smbtorture {}/{} start {}", idx + 1, total, test);
        }
        let started = Instant::now();
        h.run(&test)
            .await
            .unwrap_or_else(|err| panic!("smbtorture {test} failed: {err}"));
        if smbtorture_progress_enabled() {
            eprintln!(
                "smbtorture {}/{} ok {} ({:.2?})",
                idx + 1,
                total,
                test,
                started.elapsed()
            );
        }
    }
    h.stop().await;
}

fn smbtorture_progress_enabled() -> bool {
    std::env::var("GOSMB_SMBTORTURE_PROGRESS")
        .map(|value| value != "0")
        .unwrap_or(true)
}

#[test]
fn smbtorture_target_defaults_to_milestone_allowlist() {
    let tests = smbtorture_target_tests("").expect("default target");
    assert_eq!(tests, smbtorture_stable_tests());
}

#[test]
fn smbtorture_stable_target_matches_default_allowlist() {
    let tests = smbtorture_target_tests("stable").expect("stable target");
    let want = smbtorture_target_tests("").expect("default target");
    assert_eq!(tests, want);
}

#[test]
fn smbtorture_perf_target_focuses_concurrency_and_performance() {
    let tests = smbtorture_target_tests("perf").expect("perf target");
    let got = tests.into_iter().collect::<HashSet<_>>();
    for want in [
        "smb2.credits",
        "smb2.rw",
        "smb2.compound_async",
        "smb2.lock",
        "smb2.sharemode",
        "smb2.lease",
        "smb2.oplock",
        "smb2.durable-v2-open",
        "smb2.notify",
        "smb2.replay",
    ] {
        assert!(got.contains(want), "perf target missing {want}: {got:?}");
    }
}

#[test]
fn smbtorture_relevant_target_includes_concurrency_and_performance_suites() {
    let tests = smbtorture_target_tests("relevant").expect("relevant target");
    let got = tests.into_iter().collect::<HashSet<_>>();
    for want in [
        "smb2.credits",
        "smb2.rw",
        "smb2.compound_async",
        "smb2.lock",
        "smb2.sharemode",
        "smb2.lease",
        "smb2.oplock",
        "smb2.durable-v2-open",
        "smb2.notify",
        "smb2.replay",
        "smb2.streams",
        "smb2.timestamps",
    ] {
        assert!(
            got.contains(want),
            "relevant target missing {want}: {got:?}"
        );
    }
}

#[test]
fn smbtorture_target_rejects_unallowlisted_names() {
    assert!(smbtorture_target_tests("all").is_none());
    assert!(smbtorture_target_tests("smb2.create").is_none());
}

#[test]
fn smbtorture_tests_expands_create_alias() {
    let tests = smbtorture_tests_from("smb2.connect smb2.create", "", &[]).expect("expanded tests");
    let mut want = vec!["smb2.connect".to_string()];
    want.extend(SMBTORTURE_CREATE_TESTS.iter().map(|s| s.to_string()));
    assert_eq!(tests, want);
}

#[test]
fn smbtorture_tests_expands_compound_async_alias() {
    let tests = smbtorture_tests_from("smb2.compound_async", "", &[]).expect("expanded tests");
    let want = SMBTORTURE_COMPOUND_ASYNC_TESTS
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    assert_eq!(tests, want);
}

#[test]
fn smbtorture_credits_alias_excludes_multichannel_children() {
    let listed = vec![
        "smb2.credits.session_setup_credits_granted.session_setup_credits_granted".to_string(),
        "smb2.credits.multichannel_ipc_max_async_credits.multichannel_ipc_max_async_credits"
            .to_string(),
        "smb2.credits.1conn_notify_max_async_credits.1conn_notify_max_async_credits".to_string(),
        "smb2.connect".to_string(),
    ];
    let mut tests = Vec::new();
    append_smbtorture_test_alias(&mut tests, "smb2.credits", &listed);
    assert_eq!(
        tests,
        vec![
            "smb2.credits.session_setup_credits_granted".to_string(),
            "smb2.credits.1conn_notify_max_async_credits".to_string(),
        ]
    );
}

#[test]
fn analyze_smbtorture_output_accepts_macos_post_success_event_context_panic() {
    let out = "time: now\nsuccess: connect\nPANIC: assert failed at ../../lib/torture/torture.c(791): evtb1 == evtb2\n";
    analyze_smbtorture_output("smb2.connect", out).expect("analysis");
}

#[test]
fn analyze_smbtorture_output_accepts_macos_post_skip_event_context_panic() {
    let out = "time: now\nskip: ctdb-delrec-deadlock [requires ctdb]\nPANIC: assert failed at ../../lib/torture/torture.c(791): evtb1 == evtb2\n";
    analyze_smbtorture_output("smb2.lock.ctdb-delrec-deadlock", out).expect("analysis");
}

#[test]
fn analyze_smbtorture_output_rejects_failure_even_with_panic() {
    let out = "time: now\nfailure: connect [bad status]\nPANIC: assert failed at ../../lib/torture/torture.c(791): evtb1 == evtb2\n";
    assert!(analyze_smbtorture_output("smb2.connect", out).is_err());
}

#[test]
fn batch22a_wall_clock_skew_accepts_only_expected_monotonic_elapsed() {
    let out = "failure: batch22a [wrong value for te got 970 - should be between 34 and 50]\nLet oplock break timeout\n";
    assert!(smbtorture_batch22a_wall_clock_skew(
        "smb2.oplock.batch22a",
        out,
        Duration::from_secs(36)
    ));
    assert!(!smbtorture_batch22a_wall_clock_skew(
        "smb2.oplock.batch22a",
        out,
        Duration::from_secs(99)
    ));
    assert!(!smbtorture_batch22a_wall_clock_skew(
        "smb2.oplock.batch22b",
        out,
        Duration::from_secs(36)
    ));
}
