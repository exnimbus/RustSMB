//! Raw SMB negotiate smoke/perf tool for TCP and SMB over QUIC.

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binrw::BinWrite;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use quinn::rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use quinn::{Endpoint, VarInt};
use smb_server::wire::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use smb_server::wire::messages::{
    CloseRequest, CloseResponse, CreateRequest, CreateResponse, FileId, NegotiateContext,
    NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities, ReadRequest, ReadResponse,
    SessionSetupRequest, SessionSetupResponse, TreeConnectRequest, TreeConnectResponse,
    WriteRequest, WriteResponse,
};
use smb_server::{
    DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW, DEFAULT_QUIC_STREAM_RECEIVE_WINDOW, SMB_QUIC_ALPN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const STATUS_SUCCESS: u32 = 0;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const CREDIT_UNIT_BYTES: u64 = 64 * 1024;
const DEFAULT_TRANSFER_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_BLOCK_BYTES: usize = 8 * 1024 * 1024;
const PERF_REQUESTED_CREDITS: u16 = 8192;
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";
const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::parse()?;
    match config.op {
        Operation::Negotiate => run_negotiate(&config).await?,
        Operation::Read | Operation::Write | Operation::WriteRead => run_transfer(&config).await?,
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Config {
    op: Operation,
    transport: Transport,
    addr: String,
    tls_server_name: Option<String>,
    tls_insecure: bool,
    tls_ca_der: Option<PathBuf>,
    quic_stream_window: u64,
    quic_conn_window: u64,
    count: u64,
    output: OutputFormat,
    bytes: usize,
    block_bytes: usize,
    depth: usize,
    depths: Vec<usize>,
    share: String,
    path: String,
    bandwidth_mbps: Option<f64>,
    rtt_ms: Option<f64>,
}

impl Config {
    fn parse() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut config = Self {
            op: Operation::Negotiate,
            transport: Transport::Tcp,
            addr: "127.0.0.1:445".into(),
            tls_server_name: None,
            tls_insecure: false,
            tls_ca_der: None,
            quic_stream_window: DEFAULT_QUIC_STREAM_RECEIVE_WINDOW,
            quic_conn_window: DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW,
            count: 1,
            output: OutputFormat::Text,
            bytes: DEFAULT_TRANSFER_BYTES,
            block_bytes: DEFAULT_BLOCK_BYTES,
            depth: 1,
            depths: vec![1],
            share: "share".into(),
            path: "smbperf.bin".into(),
            bandwidth_mbps: None,
            rtt_ms: None,
        };

        let mut depths_arg = String::new();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--op" => config.op = parse_operation(&next_arg(&mut args, &arg)?)?,
                "--transport" => config.transport = parse_transport(&next_arg(&mut args, &arg)?)?,
                "--addr" => config.addr = next_arg(&mut args, &arg)?,
                "--share" => config.share = next_arg(&mut args, &arg)?,
                "--path" => config.path = next_arg(&mut args, &arg)?,
                "--bytes" => config.bytes = next_arg(&mut args, &arg)?.parse()?,
                "--block-bytes" => config.block_bytes = next_arg(&mut args, &arg)?.parse()?,
                "--depth" => config.depth = next_arg(&mut args, &arg)?.parse()?,
                "--depths" => depths_arg = next_arg(&mut args, &arg)?,
                "--output" => config.output = parse_output_format(&next_arg(&mut args, &arg)?)?,
                "--tls-server-name" => config.tls_server_name = Some(next_arg(&mut args, &arg)?),
                "--tls-insecure" => config.tls_insecure = true,
                "--tls-ca-der" => config.tls_ca_der = Some(next_arg(&mut args, &arg)?.into()),
                "--quic-stream-window" => {
                    config.quic_stream_window = next_arg(&mut args, &arg)?.parse()?
                }
                "--quic-conn-window" => {
                    config.quic_conn_window = next_arg(&mut args, &arg)?.parse()?
                }
                "--count" => config.count = next_arg(&mut args, &arg)?.parse()?,
                "--bandwidth-mbps" => {
                    config.bandwidth_mbps = Some(next_arg(&mut args, &arg)?.parse()?)
                }
                "--rtt-ms" => config.rtt_ms = Some(next_arg(&mut args, &arg)?.parse()?),
                other => return Err(format!("unknown argument {other:?}; use --help").into()),
            }
        }

        if config.count == 0 {
            return Err("--count must be positive".into());
        }
        if config.quic_stream_window == 0 || config.quic_conn_window == 0 {
            return Err("QUIC receive windows must be positive".into());
        }
        if config.bytes == 0 {
            return Err("--bytes must be positive".into());
        }
        if config.block_bytes == 0 {
            return Err("--block-bytes must be positive".into());
        }
        if config.block_bytes > u32::MAX as usize {
            return Err("--block-bytes must fit in an SMB READ/WRITE length field".into());
        }
        credit_charge_for_len(config.block_bytes)?;
        if config.depth == 0 {
            return Err("--depth must be positive".into());
        }
        config.depths = parse_depths(&depths_arg, config.depth)?;
        if config.share.is_empty() {
            return Err("--share must not be empty".into());
        }
        if config.path.is_empty() {
            return Err("--path must not be empty".into());
        }
        if config.bandwidth_mbps.is_some() != config.rtt_ms.is_some() {
            return Err("--bandwidth-mbps and --rtt-ms must be supplied together".into());
        }
        Ok(config)
    }

    fn transfer_plan(&self) -> Result<TransferPlan, Box<dyn Error + Send + Sync>> {
        build_transfer_plan(
            self.bytes as u64,
            self.block_bytes as u64,
            self.depth,
            self.bandwidth_mbps,
            self.rtt_ms,
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct TransferPlan {
    total_bytes: u64,
    block_bytes: u64,
    depth: usize,
    payload_window_bytes: u64,
    credit_window_bytes: u64,
    credits_per_request: u64,
    bdp_bytes: u64,
    required_credits: u64,
    required_depth: u64,
}

#[derive(Debug, Clone, Copy)]
struct RunResult {
    bytes: u64,
    duration: Duration,
}

#[derive(Debug, Clone)]
struct Measurement {
    mode: String,
    depth: usize,
    total_bytes: u64,
    block_bytes: u64,
    payload_window_bytes: u64,
    credit_window_bytes: u64,
    credits_per_request: u64,
    bdp_bytes: u64,
    required_depth: u64,
    required_credits: u64,
    bytes: u64,
    duration_seconds: f64,
    mib_per_second: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Csv,
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => f.write_str("text"),
            Self::Csv => f.write_str("csv"),
            Self::Json => f.write_str("json"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Negotiate,
    Read,
    Write,
    WriteRead,
}

impl Operation {
    const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::WriteRead)
    }

    const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::WriteRead)
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negotiate => f.write_str("negotiate"),
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::WriteRead => f.write_str("write-read"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Quic,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Quic => f.write_str("quic"),
        }
    }
}

fn parse_operation(value: &str) -> Result<Operation, Box<dyn Error + Send + Sync>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "negotiate" => Ok(Operation::Negotiate),
        "read" => Ok(Operation::Read),
        "write" => Ok(Operation::Write),
        "write-read" => Ok(Operation::WriteRead),
        _ => Err("--op must be negotiate, read, write, or write-read".into()),
    }
}

fn parse_transport(value: &str) -> Result<Transport, Box<dyn Error + Send + Sync>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok(Transport::Tcp),
        "quic" => Ok(Transport::Quic),
        _ => Err("--transport must be tcp or quic".into()),
    }
}

fn parse_output_format(value: &str) -> Result<OutputFormat, Box<dyn Error + Send + Sync>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "text" => Ok(OutputFormat::Text),
        "csv" => Ok(OutputFormat::Csv),
        "json" => Ok(OutputFormat::Json),
        _ => Err("--output must be text, csv, or json".into()),
    }
}

fn parse_depths(
    value: &str,
    default_depth: usize,
) -> Result<Vec<usize>, Box<dyn Error + Send + Sync>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(vec![default_depth]);
    }
    let mut depths = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("empty depth".into());
        }
        let depth = part.parse::<usize>()?;
        if depth == 0 {
            return Err("depth must be positive".into());
        }
        if !depths.contains(&depth) {
            depths.push(depth);
        }
    }
    Ok(depths)
}

fn next_arg(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn print_usage() {
    println!(
        "\
usage: smbperf [options]

Options:
  --op negotiate|read|write|write-read
                                     operation, default negotiate
  --transport tcp|quic             SMB transport, default tcp
  --addr HOST:PORT                 target address, default 127.0.0.1:445
  --count N                        connect+negotiate iterations, default 1
  --share NAME                     share name for transfer ops, default share
  --path NAME                      file path for transfer ops, default smbperf.bin
  --bytes N                        total bytes per transfer iteration, default 8388608
  --block-bytes N                  read/write request size, default 8388608
  --depth N                        max pipelined READ/WRITE requests, default 1
  --depths N,N                     comma-separated depth sweep; overrides --depth
  --output text|csv|json           measurement output format, default text
  --bandwidth-mbps N               target WAN bandwidth for BDP planning
  --rtt-ms N                       target WAN RTT for BDP planning
  --tls-server-name NAME           QUIC TLS server name, default host from --addr
  --tls-insecure                   disable QUIC certificate verification for local testing
  --tls-ca-der PATH                trust one DER certificate for QUIC
  --quic-stream-window BYTES       QUIC stream receive window
  --quic-conn-window BYTES         QUIC connection receive window
"
    );
}

async fn run_negotiate(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut total = Duration::ZERO;
    let mut dialect = 0;
    let mut transport_security = false;
    for _ in 0..config.count {
        let started = Instant::now();
        let mut stream = SmbStream::connect(config).await?;
        let smoke = negotiate(&mut stream, matches!(config.transport, Transport::Quic)).await?;
        stream.close().await;

        dialect = smoke.dialect;
        transport_security = smoke.transport_security;
        total += started.elapsed();
    }

    let avg = total.div_f64(config.count as f64);
    println!(
        "smoke: op={} transport={} addr={} count={} dialect=0x{dialect:04x} transport-security={} total={} avg={}",
        config.op,
        config.transport,
        config.addr,
        config.count,
        transport_security,
        format_duration(total),
        format_duration(avg),
    );
    Ok(())
}

async fn run_transfer(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut measurements = Vec::new();

    for &depth in &config.depths {
        let mut config = config.clone();
        config.depth = depth;
        let plan = config.transfer_plan()?;
        if config.output == OutputFormat::Text {
            print_plan(&plan, &config);
        }

        let mut total = Duration::ZERO;
        let mut dialect = 0;
        let mut transport_security = false;
        let mut total_written = 0u64;
        let mut total_read = 0u64;
        let mut write_duration = Duration::ZERO;
        let mut read_duration = Duration::ZERO;

        for i in 0..config.count {
            let started = Instant::now();
            let mut stream = SmbStream::connect(&config).await?;
            let smoke = negotiate(&mut stream, matches!(config.transport, Transport::Quic)).await?;
            dialect = smoke.dialect;
            transport_security = smoke.transport_security;

            let session_id = anonymous_session_setup(&mut stream).await?;
            let tree_id = tree_connect(&mut stream, session_id, 3, &config).await?;
            let path = iteration_path(&config.path, i);
            let create_disposition = if config.op.writes() { 5 } else { 1 };
            let file_id = create_file(
                &mut stream,
                session_id,
                tree_id,
                4,
                &path,
                create_disposition,
            )
            .await?;
            let mut message_id = 5;

            if config.op.writes() {
                let started = Instant::now();
                total_written += write_blocks(
                    &mut stream,
                    session_id,
                    tree_id,
                    file_id,
                    &mut message_id,
                    &config,
                )
                .await?;
                write_duration += started.elapsed();
            }
            if config.op.reads() {
                let started = Instant::now();
                total_read += read_blocks(
                    &mut stream,
                    session_id,
                    tree_id,
                    file_id,
                    &mut message_id,
                    &config,
                )
                .await?;
                read_duration += started.elapsed();
            }
            close_file(&mut stream, session_id, tree_id, message_id, file_id).await?;
            stream.close().await;

            total += started.elapsed();
        }

        let avg = total.div_f64(config.count as f64);
        if config.output == OutputFormat::Text {
            println!(
                "perf: op={} transport={} addr={} share={} path={} count={} bytes-per-iter={} block-bytes={} depth={} dialect=0x{dialect:04x} transport-security={} total={} avg={} write-throughput={} read-throughput={}",
                config.op,
                config.transport,
                config.addr,
                config.share,
                config.path,
                config.count,
                config.bytes,
                config.block_bytes,
                config.depth,
                transport_security,
                format_duration(total),
                format_duration(avg),
                format_rate(total_written, write_duration),
                format_rate(total_read, read_duration),
            );
        }
        if config.op.writes() {
            measurements.push(build_measurement(
                "write",
                &plan,
                RunResult {
                    bytes: total_written,
                    duration: write_duration,
                },
            ));
        }
        if config.op.reads() {
            measurements.push(build_measurement(
                "read",
                &plan,
                RunResult {
                    bytes: total_read,
                    duration: read_duration,
                },
            ));
        }
    }

    let mut stdout = io::stdout().lock();
    match config.output {
        OutputFormat::Text => {}
        OutputFormat::Csv => write_measurements_csv(&mut stdout, &measurements)?,
        OutputFormat::Json => write_measurements_json(&mut stdout, &measurements)?,
    }
    Ok(())
}

fn build_transfer_plan(
    total_bytes: u64,
    block_bytes: u64,
    depth: usize,
    bandwidth_mbps: Option<f64>,
    rtt_ms: Option<f64>,
) -> Result<TransferPlan, Box<dyn Error + Send + Sync>> {
    let credits_per_request = ceil_div(block_bytes, CREDIT_UNIT_BYTES).max(1);
    let mut plan = TransferPlan {
        total_bytes,
        block_bytes,
        depth,
        payload_window_bytes: block_bytes * depth as u64,
        credit_window_bytes: credits_per_request * depth as u64 * CREDIT_UNIT_BYTES,
        credits_per_request,
        bdp_bytes: 0,
        required_credits: 0,
        required_depth: 0,
    };

    if let Some(bandwidth_mbps) = bandwidth_mbps {
        let Some(rtt_ms) = rtt_ms else {
            return Err("--bandwidth-mbps and --rtt-ms must be supplied together".into());
        };
        if bandwidth_mbps <= 0.0 || rtt_ms <= 0.0 {
            return Err("--bandwidth-mbps and --rtt-ms must be positive".into());
        }
        plan.bdp_bytes = (bandwidth_mbps * 1_000_000.0 / 8.0 * (rtt_ms / 1000.0)).ceil() as u64;
        plan.required_depth = ceil_div(plan.bdp_bytes, block_bytes);
        plan.required_credits = ceil_div(plan.bdp_bytes, CREDIT_UNIT_BYTES);
    } else if rtt_ms.is_some() {
        return Err("--bandwidth-mbps and --rtt-ms must be supplied together".into());
    }

    Ok(plan)
}

fn print_plan(plan: &TransferPlan, config: &Config) {
    println!(
        "plan: total={} block={} depth={} payload-window={} credit-window={} credits/request={}",
        format_bytes(plan.total_bytes),
        format_bytes(plan.block_bytes),
        plan.depth,
        format_bytes(plan.payload_window_bytes),
        format_bytes(plan.credit_window_bytes),
        plan.credits_per_request,
    );
    if plan.bdp_bytes > 0 {
        println!(
            "bdp: target={} required-depth={} required-credits={} payload-covered={} credits-covered={} quic-stream-window={} quic-conn-window={} stream-covered={} conn-covered={}",
            format_bytes(plan.bdp_bytes),
            plan.required_depth,
            plan.required_credits,
            plan.payload_window_bytes >= plan.bdp_bytes,
            plan.credit_window_bytes >= plan.bdp_bytes,
            format_bytes(config.quic_stream_window),
            format_bytes(config.quic_conn_window),
            config.quic_stream_window >= plan.bdp_bytes,
            config.quic_conn_window >= plan.bdp_bytes,
        );
    }
}

fn build_measurement(mode: &str, plan: &TransferPlan, result: RunResult) -> Measurement {
    let duration_seconds = if result.duration.is_zero() {
        1e-9
    } else {
        result.duration.as_secs_f64()
    };
    let mib = result.bytes as f64 / (1 << 20) as f64;
    Measurement {
        mode: mode.to_string(),
        depth: plan.depth,
        total_bytes: plan.total_bytes,
        block_bytes: plan.block_bytes,
        payload_window_bytes: plan.payload_window_bytes,
        credit_window_bytes: plan.credit_window_bytes,
        credits_per_request: plan.credits_per_request,
        bdp_bytes: plan.bdp_bytes,
        required_depth: plan.required_depth,
        required_credits: plan.required_credits,
        bytes: result.bytes,
        duration_seconds,
        mib_per_second: mib / duration_seconds,
    }
}

fn write_measurements_csv(
    w: &mut impl io::Write,
    rows: &[Measurement],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    writeln!(
        w,
        "mode,depth,total_bytes,block_bytes,payload_window_bytes,credit_window_bytes,credits_per_request,bdp_bytes,required_depth,required_credits,bytes,duration_seconds,mib_per_second"
    )?;
    for row in rows {
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6}",
            csv_field(&row.mode),
            row.depth,
            row.total_bytes,
            row.block_bytes,
            row.payload_window_bytes,
            row.credit_window_bytes,
            row.credits_per_request,
            row.bdp_bytes,
            row.required_depth,
            row.required_credits,
            row.bytes,
            row.duration_seconds,
            row.mib_per_second,
        )?;
    }
    Ok(())
}

fn write_measurements_json(
    w: &mut impl io::Write,
    rows: &[Measurement],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    writeln!(w, "[")?;
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            writeln!(w, ",")?;
        }
        write!(
            w,
            "  {{\n    \"mode\": \"{}\",\n    \"depth\": {},\n    \"total_bytes\": {},\n    \"block_bytes\": {},\n    \"payload_window_bytes\": {},\n    \"credit_window_bytes\": {},\n    \"credits_per_request\": {},",
            json_escape(&row.mode),
            row.depth,
            row.total_bytes,
            row.block_bytes,
            row.payload_window_bytes,
            row.credit_window_bytes,
            row.credits_per_request,
        )?;
        if row.bdp_bytes != 0 {
            write!(
                w,
                "\n    \"bdp_bytes\": {},\n    \"required_depth\": {},\n    \"required_credits\": {},",
                row.bdp_bytes, row.required_depth, row.required_credits,
            )?;
        }
        write!(
            w,
            "\n    \"bytes\": {},\n    \"duration_seconds\": {},\n    \"mib_per_second\": {}\n  }}",
            row.bytes, row.duration_seconds, row.mib_per_second,
        )?;
    }
    writeln!(w, "\n]")?;
    Ok(())
}

fn csv_field(value: &str) -> String {
    if value
        .chars()
        .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct TransferBlock {
    offset: u64,
    len: usize,
}

enum SmbStream {
    Tcp(TcpStream),
    Quic {
        endpoint: Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
}

impl SmbStream {
    async fn connect(config: &Config) -> Result<Self, Box<dyn Error + Send + Sync>> {
        match config.transport {
            Transport::Tcp => Ok(Self::Tcp(TcpStream::connect(&config.addr).await?)),
            Transport::Quic => connect_quic(config).await,
        }
    }

    async fn write_frame(&mut self, payload: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut framed = Vec::with_capacity(payload.len() + 4);
        encode_frame(payload, &mut framed);
        match self {
            Self::Tcp(stream) => stream.write_all(&framed).await?,
            Self::Quic { send, .. } => send.write_all(&framed).await?,
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut header = [0u8; 4];
        match self {
            Self::Tcp(stream) => {
                stream.read_exact(&mut header).await?;
            }
            Self::Quic { recv, .. } => {
                recv.read_exact(&mut header).await?;
            }
        };
        if header[0] != 0 {
            return Err(format!("unsupported SMB direct frame marker 0x{:02x}", header[0]).into());
        }
        let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
        let mut frame = vec![0u8; len];
        match self {
            Self::Tcp(stream) => {
                stream.read_exact(&mut frame).await?;
            }
            Self::Quic { recv, .. } => {
                recv.read_exact(&mut frame).await?;
            }
        };
        Ok(frame)
    }

    async fn request(
        &mut self,
        command: Command,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: &[u8],
    ) -> Result<(Smb2Header, Vec<u8>), Box<dyn Error + Send + Sync>> {
        self.send_request(command, message_id, session_id, tree_id, 1, body)
            .await?;
        self.read_response().await
    }

    async fn send_request(
        &mut self,
        command: Command,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credit_charge: u16,
        body: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut payload = Vec::new();
        build_header_with_credit(command, message_id, session_id, tree_id, credit_charge)
            .write(&mut payload)?;
        payload.extend_from_slice(body);
        self.write_frame(&payload).await?;
        Ok(())
    }

    async fn read_response(
        &mut self,
    ) -> Result<(Smb2Header, Vec<u8>), Box<dyn Error + Send + Sync>> {
        let frame = self.read_frame().await?;
        let (header, body) = parse_response(&frame)?;
        Ok((header, body.to_vec()))
    }

    async fn close(self) {
        match self {
            Self::Tcp(_) => {}
            Self::Quic { endpoint, conn, .. } => {
                conn.close(0u32.into(), b"");
                endpoint.close(0u32.into(), b"");
                endpoint.wait_idle().await;
            }
        }
    }
}

async fn connect_quic(config: &Config) -> Result<SmbStream, Box<dyn Error + Send + Sync>> {
    let addr = resolve_addr(&config.addr)?;
    let server_name = config
        .tls_server_name
        .clone()
        .unwrap_or_else(|| host_part(&config.addr).unwrap_or_else(|| "localhost".into()));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(quic_client_config(config)?);
    let conn = endpoint.connect(addr, &server_name)?.await?;
    let (send, recv) = conn.open_bi().await?;
    Ok(SmbStream::Quic {
        endpoint,
        conn,
        send,
        recv,
    })
}

fn quic_client_config(
    config: &Config,
) -> Result<quinn::ClientConfig, Box<dyn Error + Send + Sync>> {
    let mut tls = if config.tls_insecure {
        quinn::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        if let Some(path) = &config.tls_ca_der {
            roots.add(CertificateDer::from(std::fs::read(path)?))?;
        }
        quinn::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![SMB_QUIC_ALPN.to_vec()];

    let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(VarInt::try_from(config.quic_stream_window)?);
    transport.receive_window(VarInt::try_from(config.quic_conn_window)?);
    client.transport_config(Arc::new(transport));
    Ok(client)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<quinn::rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(
            quinn::rustls::crypto::ring::default_provider(),
        )))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, quinn::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        quinn::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        quinn::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn negotiate(
    stream: &mut SmbStream,
    accept_transport_security: bool,
) -> Result<NegotiateSmoke, Box<dyn Error + Send + Sync>> {
    let payload = negotiate_payload(accept_transport_security)?;
    stream.write_frame(&payload).await?;
    let response = stream.read_frame().await?;
    validate_negotiate_response(&response)
}

async fn anonymous_session_setup(
    stream: &mut SmbStream,
) -> Result<u64, Box<dyn Error + Send + Sync>> {
    let init = build_spnego_init(&anonymous_ntlm_negotiate_token());
    let req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: init.len() as u16,
        previous_session_id: 0,
        security_buffer: init,
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    let (header, body) = stream
        .request(Command::SessionSetup, 1, 0, 0, &body)
        .await?;
    expect_status(
        &header,
        Command::SessionSetup,
        STATUS_MORE_PROCESSING_REQUIRED,
    )?;
    let session_id = header.session_id;
    if session_id == 0 {
        return Err("SESSION_SETUP challenge returned session id 0".into());
    }
    let response = SessionSetupResponse::parse(&body)?;
    if response.security_buffer.is_empty() {
        return Err("SESSION_SETUP challenge returned empty security blob".into());
    }

    let auth = build_spnego_resp(&anonymous_ntlm_authenticate_token());
    let req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: auth.len() as u16,
        previous_session_id: 0,
        security_buffer: auth,
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    let (header, body) = stream
        .request(Command::SessionSetup, 2, session_id, 0, &body)
        .await?;
    expect_status(&header, Command::SessionSetup, STATUS_SUCCESS)?;
    if header.session_id != session_id {
        return Err(format!(
            "SESSION_SETUP changed session id from {session_id} to {}",
            header.session_id
        )
        .into());
    }
    let response = SessionSetupResponse::parse(&body)?;
    if response.session_flags & SessionSetupResponse::FLAG_IS_GUEST == 0 {
        return Err("SESSION_SETUP did not authenticate as guest".into());
    }
    Ok(session_id)
}

async fn tree_connect(
    stream: &mut SmbStream,
    session_id: u64,
    message_id: u64,
    config: &Config,
) -> Result<u32, Box<dyn Error + Send + Sync>> {
    let unc = format!(
        r"\\{}\{}",
        host_part(&config.addr).unwrap_or_else(|| "127.0.0.1".into()),
        config.share
    );
    let path = utf16le(&unc);
    let req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path.len() as u16,
        path,
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    let (header, body) = stream
        .request(Command::TreeConnect, message_id, session_id, 0, &body)
        .await?;
    expect_status(&header, Command::TreeConnect, STATUS_SUCCESS)?;
    let tree_id = header
        .tree_id()
        .ok_or("TREE_CONNECT response missing tree id")?;
    let tree = TreeConnectResponse::parse(&body)?;
    if tree.share_type != TreeConnectResponse::SHARE_TYPE_DISK {
        return Err(format!(
            "TREE_CONNECT returned non-disk share type {}",
            tree.share_type
        )
        .into());
    }
    Ok(tree_id)
}

async fn create_file(
    stream: &mut SmbStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    create_disposition: u32,
) -> Result<FileId, Box<dyn Error + Send + Sync>> {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_019f,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    let (header, body) = stream
        .request(Command::Create, message_id, session_id, tree_id, &body)
        .await?;
    expect_status(&header, Command::Create, STATUS_SUCCESS)?;
    Ok(CreateResponse::parse(&body)?.file_id)
}

async fn write_blocks(
    stream: &mut SmbStream,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    next_message_id: &mut u64,
    config: &Config,
) -> Result<u64, Box<dyn Error + Send + Sync>> {
    let mut pending = transfer_blocks(config);
    let mut in_flight = HashMap::new();
    let mut written = 0u64;

    while !pending.is_empty() || !in_flight.is_empty() {
        while in_flight.len() < config.depth {
            let Some(block) = pending.pop_front() else {
                break;
            };
            let message_id = *next_message_id;
            *next_message_id += 1;
            let data = perf_block(block.offset, block.len);
            let body = write_request_body(file_id, block.offset, &data)?;
            stream
                .send_request(
                    Command::Write,
                    message_id,
                    session_id,
                    tree_id,
                    credit_charge_for_len(block.len)?,
                    &body,
                )
                .await?;
            in_flight.insert(message_id, block);
        }

        let (header, body) = stream.read_response().await?;
        expect_status(&header, Command::Write, STATUS_SUCCESS)?;
        let block = in_flight
            .remove(&header.message_id)
            .ok_or_else(|| format!("unexpected WRITE response message id {}", header.message_id))?;
        let response = WriteResponse::parse(&body)?;
        if response.count as usize != block.len {
            return Err(format!(
                "WRITE count {} did not match requested {} at offset {}",
                response.count, block.len, block.offset
            )
            .into());
        }
        written += u64::try_from(block.len)?;
    }

    Ok(written)
}

fn write_request_body(
    file_id: FileId,
    offset: u64,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: data.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    Ok(body)
}

async fn read_blocks(
    stream: &mut SmbStream,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    next_message_id: &mut u64,
    config: &Config,
) -> Result<u64, Box<dyn Error + Send + Sync>> {
    let mut pending = transfer_blocks(config);
    let mut in_flight = HashMap::new();
    let mut read = 0u64;

    while !pending.is_empty() || !in_flight.is_empty() {
        while in_flight.len() < config.depth {
            let Some(block) = pending.pop_front() else {
                break;
            };
            let message_id = *next_message_id;
            *next_message_id += 1;
            let body = read_request_body(file_id, block.offset, block.len as u32)?;
            stream
                .send_request(
                    Command::Read,
                    message_id,
                    session_id,
                    tree_id,
                    credit_charge_for_len(block.len)?,
                    &body,
                )
                .await?;
            in_flight.insert(message_id, block);
        }

        let (header, body) = stream.read_response().await?;
        expect_status(&header, Command::Read, STATUS_SUCCESS)?;
        let block = in_flight
            .remove(&header.message_id)
            .ok_or_else(|| format!("unexpected READ response message id {}", header.message_id))?;
        let response = ReadResponse::parse(&body)?;
        let expected = perf_block(block.offset, block.len);
        if response.data != expected {
            return Err(format!(
                "read-back mismatch at offset {}: got {} bytes, expected {} bytes",
                block.offset,
                response.data.len(),
                expected.len()
            )
            .into());
        }
        read += u64::try_from(block.len)?;
    }

    Ok(read)
}

fn read_request_body(
    file_id: FileId,
    offset: u64,
    length: u32,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length,
        offset,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    Ok(body)
}

async fn close_file(
    stream: &mut SmbStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: FileId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body)?;
    let (header, body) = stream
        .request(Command::Close, message_id, session_id, tree_id, &body)
        .await?;
    expect_status(&header, Command::Close, STATUS_SUCCESS)?;
    let _ = CloseResponse::parse(&body)?;
    Ok(())
}

fn negotiate_payload(
    accept_transport_security: bool,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let preauth = PreauthIntegrityCapabilities {
        hash_algorithm_count: 1,
        salt_length: 0,
        hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
        salt: vec![],
    };
    let mut preauth_cursor = std::io::Cursor::new(Vec::new());
    BinWrite::write(&preauth, &mut preauth_cursor)?;

    let mut contexts = vec![NegotiateContext {
        context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
        data_length: preauth_cursor.get_ref().len() as u16,
        reserved: 0,
        data: preauth_cursor.into_inner(),
    }];
    if accept_transport_security {
        let data = NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
            .to_le_bytes()
            .to_vec();
        contexts.push(NegotiateContext {
            context_type: NegotiateContext::TYPE_TRANSPORT_CAPS,
            data_length: data.len() as u16,
            reserved: 0,
            data,
        });
    }

    let mut contexts_bytes = Vec::new();
    NegotiateContext::encode_list(&contexts, &mut contexts_bytes)?;
    let contexts_offset = align_8(64 + 36 + 2) as u32;
    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 1,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0x53; 16],
        negotiate_context_offset_or_client_start_time: (contexts_offset as u64)
            | ((contexts.len() as u64) << 32),
        dialects: vec![0x0311],
    };

    let mut body = Vec::new();
    req.write_to(&mut body)?;
    body.resize(contexts_offset as usize - 64, 0);
    body.extend_from_slice(&contexts_bytes);

    let mut payload = Vec::new();
    build_header(Command::Negotiate, 0, 0, 0).write(&mut payload)?;
    payload.extend_from_slice(&body);
    Ok(payload)
}

fn build_header(command: Command, message_id: u64, session_id: u64, tree_id: u32) -> Smb2Header {
    build_header_with_credit(command, message_id, session_id, tree_id, 1)
}

fn build_header_with_credit(
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    credit_charge: u16,
) -> Smb2Header {
    Smb2Header {
        credit_charge,
        channel_sequence_status: 0,
        command,
        credit_request_response: PERF_REQUESTED_CREDITS,
        flags: 0,
        next_command: 0,
        message_id,
        tail: HeaderTail::sync(tree_id),
        session_id,
        signature: [0u8; 16],
    }
}

#[derive(Debug)]
struct NegotiateSmoke {
    dialect: u16,
    transport_security: bool,
}

fn validate_negotiate_response(
    frame: &[u8],
) -> Result<NegotiateSmoke, Box<dyn Error + Send + Sync>> {
    let (header, body) = parse_response(frame)?;
    if header.command != Command::Negotiate {
        return Err(format!("expected NEGOTIATE response, got {:?}", header.command).into());
    }
    if header.channel_sequence_status != STATUS_SUCCESS {
        return Err(format!(
            "NEGOTIATE failed with status 0x{:08x}",
            header.channel_sequence_status
        )
        .into());
    }
    let response = NegotiateResponse::parse(body)?;
    if response.dialect_revision != 0x0311 {
        return Err(format!(
            "expected SMB 3.1.1 dialect, got 0x{:04x}",
            response.dialect_revision
        )
        .into());
    }
    Ok(NegotiateSmoke {
        dialect: response.dialect_revision,
        transport_security: response_transport_security_accepted(body)?,
    })
}

fn response_transport_security_accepted(buf: &[u8]) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let response = NegotiateResponse::parse(buf)?;
    if response.negotiate_context_count_or_reserved == 0 {
        return Ok(false);
    }
    let offset = response.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts =
        NegotiateContext::parse_list(&buf[offset..], response.negotiate_context_count_or_reserved)?;
    Ok(contexts.iter().any(|ctx| {
        ctx.context_type == NegotiateContext::TYPE_TRANSPORT_CAPS
            && ctx.data.len() >= 4
            && u32::from_le_bytes(ctx.data[0..4].try_into().expect("slice length"))
                & NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
                != 0
    }))
}

fn parse_response(frame: &[u8]) -> Result<(Smb2Header, &[u8]), Box<dyn Error + Send + Sync>> {
    let (header, body) = Smb2Header::parse(frame)?;
    if header.flags & SMB2_FLAGS_SERVER_TO_REDIR == 0 {
        return Err("response SMB2 header is missing SERVER_TO_REDIR".into());
    }
    Ok((header, body))
}

fn expect_status(
    header: &Smb2Header,
    command: Command,
    status: u32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if header.command != command {
        return Err(format!("expected {command:?} response, got {:?}", header.command).into());
    }
    if header.channel_sequence_status != status {
        return Err(format!(
            "{command:?} returned status 0x{:08x}, expected 0x{status:08x}",
            header.channel_sequence_status
        )
        .into());
    }
    Ok(())
}

fn encode_frame(payload: &[u8], out: &mut Vec<u8>) {
    assert!(payload.len() <= 0x00ff_ffff);
    out.push(0);
    out.push(((payload.len() >> 16) & 0xff) as u8);
    out.push(((payload.len() >> 8) & 0xff) as u8);
    out.push((payload.len() & 0xff) as u8);
    out.extend_from_slice(payload);
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn write_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let mut tmp = Vec::new();
        let mut n = content.len();
        while n > 0 {
            tmp.push((n & 0xff) as u8);
            n >>= 8;
        }
        out.push(0x80 | tmp.len() as u8);
        for b in tmp.into_iter().rev() {
            out.push(b);
        }
    }
    out.extend_from_slice(content);
}

fn build_spnego_init(ntlm: &[u8]) -> Vec<u8> {
    let mut mts = Vec::new();
    write_tlv(0x06, OID_NTLMSSP, &mut mts);
    let mut mts_seq = Vec::new();
    write_tlv(0x30, &mts, &mut mts_seq);
    let mut mts_ctx0 = Vec::new();
    write_tlv(0xa0, &mts_seq, &mut mts_ctx0);

    let mut tok_oct = Vec::new();
    write_tlv(0x04, ntlm, &mut tok_oct);
    let mut tok_ctx2 = Vec::new();
    write_tlv(0xa2, &tok_oct, &mut tok_ctx2);

    let mut seq = Vec::new();
    seq.extend_from_slice(&mts_ctx0);
    seq.extend_from_slice(&tok_ctx2);
    let mut neg_token_init = Vec::new();
    write_tlv(0x30, &seq, &mut neg_token_init);

    let mut choice = Vec::new();
    write_tlv(0xa0, &neg_token_init, &mut choice);

    let mut gss_inner = Vec::new();
    write_tlv(0x06, OID_SPNEGO, &mut gss_inner);
    gss_inner.extend_from_slice(&choice);

    let mut blob = Vec::new();
    write_tlv(0x60, &gss_inner, &mut blob);
    blob
}

fn build_spnego_resp(ntlm: &[u8]) -> Vec<u8> {
    let mut enum_state = Vec::new();
    write_tlv(0x0a, &[1], &mut enum_state);
    let mut state_ctx0 = Vec::new();
    write_tlv(0xa0, &enum_state, &mut state_ctx0);

    let mut mech_oid = Vec::new();
    write_tlv(0x06, OID_NTLMSSP, &mut mech_oid);
    let mut mech_ctx1 = Vec::new();
    write_tlv(0xa1, &mech_oid, &mut mech_ctx1);

    let mut tok_oct = Vec::new();
    write_tlv(0x04, ntlm, &mut tok_oct);
    let mut tok_ctx2 = Vec::new();
    write_tlv(0xa2, &tok_oct, &mut tok_ctx2);

    let mut seq = Vec::new();
    seq.extend_from_slice(&state_ctx0);
    seq.extend_from_slice(&mech_ctx1);
    seq.extend_from_slice(&tok_ctx2);

    let mut seq_outer = Vec::new();
    write_tlv(0x30, &seq, &mut seq_outer);
    let mut out = Vec::new();
    write_tlv(0xa1, &seq_outer, &mut out);
    out
}

fn anonymous_ntlm_negotiate_token() -> Vec<u8> {
    let mut ntlm_negotiate = Vec::new();
    ntlm_negotiate.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&0x6209_8215u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&[0u8; 16]);
    ntlm_negotiate.extend_from_slice(&[0u8; 8]);
    ntlm_negotiate
}

fn anonymous_ntlm_authenticate_token() -> Vec<u8> {
    let mut ntlm_auth = Vec::new();
    ntlm_auth.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_auth.extend_from_slice(&3u32.to_le_bytes());
    let header_len: u32 = 72;
    for _ in 0..6 {
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&header_len.to_le_bytes());
    }
    ntlm_auth.extend_from_slice(&0x0000_0800u32.to_le_bytes());
    ntlm_auth.extend_from_slice(&[0u8; 8]);
    ntlm_auth
}

fn iteration_path(base: &str, index: u64) -> String {
    if index == 0 {
        return base.to_string();
    }
    match base.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}-{index}.{ext}"),
        _ => format!("{base}-{index}"),
    }
}

fn transfer_blocks(config: &Config) -> VecDeque<TransferBlock> {
    let mut blocks = VecDeque::new();
    let mut remaining = config.bytes;
    let mut offset = 0u64;
    while remaining > 0 {
        let len = remaining.min(config.block_bytes);
        blocks.push_back(TransferBlock { offset, len });
        offset += len as u64;
        remaining -= len;
    }
    blocks
}

fn perf_block(offset: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((offset + i as u64) as u8).wrapping_mul(31))
        .collect()
}

fn credit_charge_for_len(len: usize) -> Result<u16, Box<dyn Error + Send + Sync>> {
    let charge = ceil_div(len as u64, CREDIT_UNIT_BYTES).max(1);
    u16::try_from(charge).map_err(|_| {
        format!(
            "request length {len} needs {charge} credits, above SMB2 CreditCharge limit {}",
            u16::MAX
        )
        .into()
    })
}

fn resolve_addr(addr: &str) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("could not resolve {addr:?}").into())
}

fn host_part(addr: &str) -> Option<String> {
    addr.rsplit_once(':').map(|(host, _)| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    })
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}

const fn ceil_div(n: u64, d: u64) -> u64 {
    if n == 0 { 0 } else { (n - 1) / d + 1 }
}

fn format_bytes(bytes: u64) -> String {
    if bytes.is_multiple_of(1 << 20) {
        format!("{} MiB", bytes >> 20)
    } else {
        format!("{:.2} MiB", bytes as f64 / (1 << 20) as f64)
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{:.3}s", duration.as_secs_f64())
    } else {
        format!("{:.3}ms", duration.as_secs_f64() * 1000.0)
    }
}

fn format_rate(bytes: u64, duration: Duration) -> String {
    if bytes == 0 {
        return "0.00 MiB/s".into();
    }
    if duration.is_zero() {
        return "inf MiB/s".into();
    }
    format!(
        "{:.2} MiB/s",
        bytes as f64 / (1 << 20) as f64 / duration.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config {
            op: Operation::Negotiate,
            transport: Transport::Tcp,
            addr: "127.0.0.1:445".into(),
            tls_server_name: None,
            tls_insecure: false,
            tls_ca_der: None,
            quic_stream_window: DEFAULT_QUIC_STREAM_RECEIVE_WINDOW,
            quic_conn_window: DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW,
            count: 1,
            output: OutputFormat::Text,
            bytes: DEFAULT_TRANSFER_BYTES,
            block_bytes: DEFAULT_BLOCK_BYTES,
            depth: 1,
            depths: vec![1],
            share: "share".into(),
            path: "smbperf.bin".into(),
            bandwidth_mbps: None,
            rtt_ms: None,
        }
    }

    #[test]
    fn transfer_plan_without_bdp_matches_gosmb_math() {
        let mut config = default_config();
        config.bytes = 1024 << 20;
        config.block_bytes = 8 << 20;
        config.depth = 32;

        let plan = config.transfer_plan().expect("transfer plan");
        assert_eq!(plan.payload_window_bytes, 256 << 20);
        assert_eq!(plan.credits_per_request, 128);
        assert_eq!(plan.credit_window_bytes, 256 << 20);
        assert_eq!(plan.bdp_bytes, 0);
        assert_eq!(plan.required_depth, 0);
        assert_eq!(plan.required_credits, 0);
    }

    #[test]
    fn bdp_plan_matches_gosmb_wan_math() {
        let mut config = default_config();
        config.bandwidth_mbps = Some(10_000.0);
        config.rtt_ms = Some(200.0);
        config.depth = 32;

        let plan = config.transfer_plan().expect("transfer plan");
        assert_eq!(plan.bdp_bytes, 250_000_000);
        assert_eq!(plan.required_credits, 3815);
        assert_eq!(plan.credit_window_bytes, 256 * 1024 * 1024);
        assert_eq!(plan.required_depth, 30);
        assert_eq!(plan.payload_window_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn bdp_plan_matches_quic_one_gbps_forty_ms_profile() {
        let mut config = default_config();
        config.transport = Transport::Quic;
        config.bandwidth_mbps = Some(1_000.0);
        config.rtt_ms = Some(40.0);

        let plan = config.transfer_plan().expect("transfer plan");
        assert_eq!(plan.bdp_bytes, 5_000_000);
        assert_eq!(plan.required_credits, 77);
        assert_eq!(plan.required_depth, 1);
        assert!(plan.payload_window_bytes >= plan.bdp_bytes);
        assert!(config.quic_stream_window >= plan.bdp_bytes);
        assert!(config.quic_conn_window >= plan.bdp_bytes);
    }

    #[test]
    fn bdp_plan_rejects_non_positive_wan_profile() {
        for (bandwidth_mbps, rtt_ms) in [(0.0, 40.0), (1_000.0, 0.0), (-1.0, 40.0)] {
            let mut config = default_config();
            config.bandwidth_mbps = Some(bandwidth_mbps);
            config.rtt_ms = Some(rtt_ms);
            assert!(
                config.transfer_plan().is_err(),
                "bandwidth={bandwidth_mbps} rtt={rtt_ms}"
            );
        }
    }

    #[test]
    fn parse_operation_accepts_supported_modes() {
        assert_eq!(
            parse_operation(" negotiate ").expect("negotiate op"),
            Operation::Negotiate
        );
        assert_eq!(
            parse_operation("write-read").expect("write-read op"),
            Operation::WriteRead
        );
        assert_eq!(parse_operation("read").expect("read op"), Operation::Read);
        assert_eq!(
            parse_operation("write").expect("write op"),
            Operation::Write
        );
        assert!(parse_operation("rdma").is_err());
    }

    #[test]
    fn parse_transport_accepts_tcp_and_quic_only() {
        assert_eq!(parse_transport("tcp").expect("tcp"), Transport::Tcp);
        assert_eq!(parse_transport(" QUIC ").expect("quic"), Transport::Quic);
        assert!(parse_transport("rdma").is_err());
    }

    #[test]
    fn parse_output_format_accepts_text_csv_and_json() {
        assert_eq!(
            parse_output_format("text").expect("text"),
            OutputFormat::Text
        );
        assert_eq!(
            parse_output_format(" CSV ").expect("csv"),
            OutputFormat::Csv
        );
        assert_eq!(
            parse_output_format("json").expect("json"),
            OutputFormat::Json
        );
        assert!(parse_output_format("yaml").is_err());
    }

    #[test]
    fn parse_depths_dedupes_and_rejects_invalid_values() {
        assert_eq!(parse_depths("", 16).expect("default"), vec![16]);
        assert_eq!(parse_depths("1,2,4,8", 16).expect("list"), vec![1, 2, 4, 8]);
        assert_eq!(parse_depths(" 4, 8, 4 ", 16).expect("dedupe"), vec![4, 8]);
        assert!(parse_depths("0", 16).is_err());
        assert!(parse_depths("1,,2", 16).is_err());
        assert!(parse_depths("fast", 16).is_err());
    }

    #[test]
    fn build_measurement_matches_gosmb_fields() {
        let mut config = default_config();
        config.bytes = 1024 << 20;
        config.block_bytes = 8 << 20;
        config.depth = 32;
        config.bandwidth_mbps = Some(10_000.0);
        config.rtt_ms = Some(200.0);

        let plan = config.transfer_plan().expect("transfer plan");
        let row = build_measurement(
            "read",
            &plan,
            RunResult {
                bytes: 512 << 20,
                duration: Duration::from_secs(2),
            },
        );
        assert_eq!(row.mode, "read");
        assert_eq!(row.depth, 32);
        assert_eq!(row.payload_window_bytes, 256 << 20);
        assert_eq!(row.required_credits, 3815);
        assert_eq!(row.mib_per_second, 256.0);
    }

    #[test]
    fn write_measurements_csv_matches_gosmb_shape() {
        let plan = build_transfer_plan(128 << 20, 8 << 20, 16, Some(10_000.0), Some(200.0))
            .expect("transfer plan");
        let row = build_measurement(
            "write",
            &plan,
            RunResult {
                bytes: 128 << 20,
                duration: Duration::from_secs(1),
            },
        );
        let mut out = Vec::new();
        write_measurements_csv(&mut out, &[row]).expect("csv");
        let csv = String::from_utf8(out).expect("utf8");
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("mode,depth,total_bytes"));
        assert!(lines[1].starts_with("write,16,134217728,8388608"));
    }

    #[test]
    fn write_measurements_json_matches_gosmb_shape() {
        let plan = build_transfer_plan(128 << 20, 8 << 20, 16, None, None).expect("transfer plan");
        let row = build_measurement(
            "read",
            &plan,
            RunResult {
                bytes: 128 << 20,
                duration: Duration::from_secs(1),
            },
        );
        let mut out = Vec::new();
        write_measurements_json(&mut out, &[row]).expect("json");
        let json = String::from_utf8(out).expect("utf8");
        assert!(json.contains("\"mode\": \"read\""));
        assert!(json.contains("\"mib_per_second\": 128"));
        assert!(!json.contains("\"bdp_bytes\""));
    }

    #[test]
    fn iteration_path_preserves_extension_for_repeated_runs() {
        assert_eq!(iteration_path("file.bin", 0), "file.bin");
        assert_eq!(iteration_path("file.bin", 2), "file-2.bin");
        assert_eq!(iteration_path("file", 2), "file-2");
    }

    #[test]
    fn transfer_blocks_split_tail_and_preserve_offsets() {
        let mut config = default_config();
        config.bytes = 10;
        config.block_bytes = 4;

        let blocks: Vec<_> = transfer_blocks(&config).into_iter().collect();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].offset, 0);
        assert_eq!(blocks[0].len, 4);
        assert_eq!(blocks[1].offset, 4);
        assert_eq!(blocks[1].len, 4);
        assert_eq!(blocks[2].offset, 8);
        assert_eq!(blocks[2].len, 2);
    }

    #[test]
    fn perf_block_is_deterministic_by_absolute_offset() {
        assert_eq!(perf_block(0, 0), Vec::<u8>::new());
        assert_eq!(perf_block(0, 4), vec![0, 31, 62, 93]);
        assert_eq!(perf_block(4, 4), vec![124, 155, 186, 217]);
    }

    #[test]
    fn credit_charge_matches_smb3_multicredit_boundaries() {
        assert_eq!(credit_charge_for_len(0).expect("zero"), 1);
        assert_eq!(credit_charge_for_len(64 * 1024).expect("one"), 1);
        assert_eq!(credit_charge_for_len(64 * 1024 + 1).expect("two"), 2);
        assert_eq!(
            credit_charge_for_len(DEFAULT_BLOCK_BYTES).expect("8mib"),
            128
        );
    }

    #[test]
    fn host_part_handles_ipv4_hostnames_and_bracketed_ipv6() {
        assert_eq!(host_part("127.0.0.1:445").as_deref(), Some("127.0.0.1"));
        assert_eq!(
            host_part("server.example:445").as_deref(),
            Some("server.example")
        );
        assert_eq!(host_part("[::1]:445").as_deref(), Some("::1"));
        assert_eq!(host_part("missing-port"), None);
    }

    #[test]
    fn ceil_div_matches_gosmb_boundaries() {
        assert_eq!(ceil_div(0, 64), 0);
        assert_eq!(ceil_div(64, 64), 1);
        assert_eq!(ceil_div(65, 64), 2);
    }
}
