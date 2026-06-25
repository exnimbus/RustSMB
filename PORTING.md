# GoSMB Feature Port Matrix

This file tracks parity with `/Users/bill/Desktop/gosmb/GoSMB` as the source
implementation. The goal is feature parity without a line-for-line port: Rust
code should keep the existing async architecture, typed codecs, backend traits,
and idiomatic error handling.

Status meanings:

- `done`: implemented with Rust tests.
- `partial`: some behavior exists, but GoSMB parity or test coverage is missing.
- `missing`: not implemented yet.
- `not planned`: outside GoSMB's own current scope.

Audit helpers:

- `tools/porting-test-audit.sh summary` compares normalized GoSMB `Test...`
  names from every GoSMB `*_test.go` file with normalized Rust test function
  names and reports exact matches, reviewed renamed/grouped matches from
  `tools/porting-test-reviewed.tsv`, and remaining unreviewed candidates.
  `tools/porting-test-audit.sh unreviewed-source` adds GoSMB
  file/line/test-name provenance for the remaining queue. The unreviewed list is
  not proof of missing behavior: Rust tests often use different names or group
  several Go cases into one integration test. Use it as the deterministic queue
  for requirement-by-requirement audit passes, and add manually verified mappings
  to `tools/porting-test-reviewed.tsv`.
- `tools/porting-matrix-audit.sh` checks that every feature-matrix row is either
  `done` or a GoSMB-scoped `not planned` exclusion, that there are no `partial`
  or `missing` feature rows, and that every `done` row cites concrete backtick
  evidence.

Current normalized-test audit as of 2026-06-22:

- GoSMB normalized tests: 475
- Rust normalized tests: 1112
- Exact normalized matches: 121
- Reviewed renamed/grouped candidates: 354
- Unreviewed candidates: 0
- Matrix feature rows: 61
- Done rows: 57
- Not-planned rows: 4
- Partial rows: 0
- Missing rows: 0

## Protocol And Transport

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| SMB direct TCP framing | done | `proto::framing`, including the exact GoSMB direct-TCP `\xfeSMBpayload` fixture, `conn::reader`, integration tests, and GoSMB-compatible NetBIOS session-request prelude handling before direct TCP NEGOTIATE |
| SMB2/3 header encode/decode | done | `proto::header` unit tests, including exact GoSMB sync and async header round-trip fixture values |
| SMB1 multi-protocol negotiate bridge | done | `dispatch::handle_smb1_multi_protocol` accepts GoSMB-style SMB1 NEGOTIATE dialect lists, prefers `SMB 2.???` over `SMB 2.002`, and returns an SMB2 NEGOTIATE response with message id `0`, tree id `0xFFFF`, and the selected wildcard dialect |
| Dialect negotiation for SMB 3.1.1, 3.0.2, 3.0, 2.1 | done | `handlers::negotiate`, `Dialect`, and direct GoSMB-style coverage that the server selects the highest supported client dialect regardless of offer order; NEGOTIATE request/response codecs validate fixed `StructureSize`, dialect vector truncation, header-relative security-buffer/context ranges, and negotiate-context chain bounds |
| SMB over QUIC listener, TLS ALPN `smb` | done | Optional `quic` feature adds Quinn server endpoint construction, TLS ALPN `smb`, TLS 1.3-compatible server configuration, one client-opened bidirectional SMB stream per QUIC connection with concurrent bidi and uni streams blocked, transport-agnostic dispatcher wiring, QUIC negotiate smoke coverage, guest SESSION_SETUP/TREE_CONNECT/CREATE/READ/CLOSE file-read coverage, guest CREATE/WRITE/READ/CLOSE write-path coverage, authenticated NTLMv2 CREATE/WRITE/READ/CLOSE coverage on a user-restricted share, and opt-in CloudSoda/go-smb2 over QUIC read/write/reopen external-client coverage mirroring GoSMB |
| QUIC transport-security negotiate context | done | `src/conn/state.rs`, `src/handlers/negotiate.rs`, `src/dispatch.rs`, `src/handlers/tree_connect.rs`, `tests/integration_negotiate.rs`, and `tests/integration_quic.rs` cover secure-transport state, SMB 3.1.1 transport-security negotiate context acceptance only on QUIC, TCP rejection, SMB transform-encryption skip when accepted, isolated-transport TREE_CONNECT flags, and QUIC negotiate/session/tree/file read-write loopback coverage |
| QUIC flow-control / WAN perf harness | done | `SmbQuicConfig` exposes stream and connection receive-window settings with GoSMB-style defaults, applies SMB QUIC single-bidi-stream and disabled-uni-stream transport limits with loopback coverage, preserves explicit idle-timeout/keepalive/window overrides, and documents that quic-go's separate handshake idle timeout maps to Quinn's max-idle-timeout-driven handshake idle handling because Quinn 0.11 has no separate server handshake-idle knob. `examples/smbperf` can run TCP/QUIC SMB 3.1.1 negotiate smoke probes plus anonymous TREE_CONNECT/CREATE/READ/CLOSE, pipelined block-depth READ/WRITE/READ validation, SMB3 multi-credit request charging for large blocks, configurable payload size, block size, depth, depth sweeps, text/CSV/JSON measurements, QUIC receive-window, and BDP-planning knobs. The `smbperf` example has GoSMB-derived unit coverage for WAN BDP credit/depth math including 10 Gbps / 200 ms and QUIC 1 Gbps / 40 ms profiles, operation/transport/output parsing, depth-list parsing, measurement construction, CSV/JSON output shape, repeated-run paths, host parsing, payload determinism, block splitting, multi-credit boundaries, and ceil-div boundaries. `tools/wanem.sh` mirrors GoSMB's macOS pf/dnctl and Linux tc helper, including UDP/QUIC bandwidth shaping and the `sudo env HOST=...` macOS workflow. QUIC integration coverage now includes a rootless userspace UDP WAN profile with 20 ms one-way delay, 1 Gbps serialization, 1 MiB multi-credit WRITE/READ validation, and opt-in CloudSoda/go-smb2 external QUIC mount/read/write/reopen validation |
| External client smoke tests | done | Opt-in `tests/cloudsoda_smoke.rs` mirrors GoSMB's CloudSoda/go-smb2 TCP client integration for authenticated encrypted share enumeration, mount, read/stat/seek/readdir, write, close, and reopen/read flows, plus GoSMB's CloudSoda/go-smb2 QUIC mount/read/write/reopen flow. Opt-in `tests/smbclient_smoke.rs` mirrors GoSMB's Samba `smbclient` coverage for encrypted list/read, signed list/read, wrong-password failure, missing-file failure, small and large put/get, and directory rename/delete flows; the real `GOSMB_RUN_SMBCLIENT=1` gate passes locally. Opt-in `tests/smbutil_smoke.rs` mirrors GoSMB's `smbutil view` coverage for authenticated share enumeration on port 445 and supports `GOSMB_REQUIRE_SMBUTIL=1` to fail instead of skip when privileged bind rights are unavailable. Opt-in macOS `tests/mount_smbfs_smoke.rs` mirrors GoSMB's `mount_smbfs` mount/read/write/sync coverage plus mounted-directory change-notify visibility. Opt-in `tests/smbtorture_smoke.rs` mirrors GoSMB's Samba `smbtorture` target allowlists, suite aliases, macOS output analysis, and authenticated temporary-share runner; the real stable target passes locally, including `smb2.dir.many` index-resume enumeration |
| Multi-channel / QUIC multipath | not planned | Also not implemented in GoSMB. The GoSMB smbtorture harness explicitly excludes multichannel children from its credits alias, and the Rust harness mirrors that exclusion while still covering single-connection credit-window, async-credit, and WAN-BDP behavior |

## Examples And Tools

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| Minimal local filesystem daemon example | done | `examples/minimal` exposes public read/write, public read-only, and user-restricted shares using `LocalFsBackend` and the public `SmbServer` builder |
| Hacker News read-only virtual filesystem example | done | `examples/hnfs` mirrors GoSMB's HNFS layout with a read-only API-backed `ShareBackend`, cached Hacker News Firebase API reads, root/list/item/user directories, story `.txt`/`.url`/`.json` files, stable story-ID path handling, and deterministic tests for story prefixes, story ID extraction, slug cleanup, and stable file IDs |
| `smbperf` WAN/performance tool | done | `examples/smbperf/src/main.rs` implements the TCP/QUIC perf harness; unit tests in that crate cover GoSMB-derived transfer planning, WAN BDP math, QUIC parsing, depth sweeps, multi-credit boundaries, and text/CSV/JSON output shape. See the QUIC flow-control / WAN perf harness row above |
| `gosmbd` daemon CLI helpers | not planned | `rust-smb-server` remains a library-first crate with examples rather than a GoSMB daemon clone. GoSMB's CLI-only listener validation, log-level parsing, and development-certificate warning helpers are audited separately from SMB protocol parity; Rust QUIC endpoint construction, TLS ALPN behavior, receive-window defaults, and WAN helper behavior are covered by the QUIC rows above |

## Negotiation Contexts

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| SHA-512 preauth integrity context | done | `PreauthIntegrityCapabilities`, preauth tests |
| Validate required preauth and duplicate singleton contexts | done | `src/handlers/negotiate.rs`, `tests/integration_negotiate.rs`, and `src/dispatch.rs` cover SMB 3.1.1 rejection of missing/malformed preauth, no SHA-512 overlap, duplicate singleton contexts, malformed supported signing/POSIX contexts, SMB 3.1.1 success with only SHA-512 preauth when encryption is optional, the single selected preauth response context, leasing capability advertisement for SMB 2.1 and SMB 3.1.1, and GoSMB's terminal first-leg SESSION_SETUP preauth rule that hashes the request but not the error response |
| Encryption capabilities AES-128/256 CCM/GCM | done | Parses and records SMB 3.1.1 encryption cipher offers with direct handler coverage, keeps malformed unsupported encryption contexts non-fatal unless encryption is enabled, exposes `encrypt_data`, falls back from SMB 3.1.1 to SMB 3.0.2 when required encryption lacks a 3.1.1 cipher context, advertises `GLOBAL_CAP_ENCRYPTION`, returns the selected 3.1.1 cipher context with GoSMB-style AES-256-GCM preference, AES-128-GCM fallback, and AES-256-GCM-only compatibility coverage, derives per-session SMB 3.0/3.1.1 encryption keys, skips SMB transform encryption when transport security is accepted, sets encrypted/compressed/isolated TREE_CONNECT share flags, has authenticated SMB 3.1.1 encrypted ECHO coverage for AES-128/256 CCM/GCM using real NTLMv2 session keys, has authenticated SMB 3.1.1 AES-128-GCM plus SMB 3.0.2 AES-128-CCM TCP loopback coverage for encrypted TREE_CONNECT/CREATE/WRITE/READ/CLOSE, and opt-in encrypted external-client smoke coverage mirrors GoSMB |
| Compression capabilities XPRESS/LZ77/PATTERN_V1 negotiation | done | `src/handlers/negotiate.rs` and `tests/integration_negotiate.rs` parse/validate SMB 3.1.1 compression capabilities, record offered algorithms/chained flag including unsupported offers, select LZ77 then chained Pattern_V1 like GoSMB, advertise only the selected algorithm, and expose a server-side disable knob that clears recorded compression state and avoids advertising compression |
| Compression transform frames | done | Handles `0xFC 'SMB'` transform frames, XPRESS LZ77 and Pattern_V1 decompress/compress, chained NONE/LZ77/Pattern payloads with GoSMB-style algorithm and payload-length byte offsets, GoSMB-style compressed request decompression through `dispatch_frame`, non-session response compression, and GoSMB-derived crypto/dispatch tests |
| NETNAME negotiate context parsing | done | `src/handlers/negotiate.rs` and `tests/integration_negotiate.rs` parse request-only UTF-16LE NETNAME, store it on connection state, and verify the response does not echo it |
| RDMA transform capabilities parsing without advertising RDMA | done | `src/proto/messages/negotiate.rs`, `src/handlers/negotiate.rs`, and `tests/integration_negotiate.rs` parse/validate SMB 3.1.1 RDMA transform capabilities, record requested IDs with direct handler coverage, and verify the TCP/QUIC server does not advertise RDMA transforms |
| Signing capabilities AES-CMAC / AES-GMAC selection | done | `src/handlers/negotiate.rs`, `tests/integration_negotiate.rs`, and `src/proto/crypto/sign.rs` cover SMB 3.1.1 parsing of client signing capabilities, AES-GMAC preference over AES-CMAC, selected signing-context responses, and negotiated signing verification |
| POSIX extensions negotiate context | done | `src/proto/messages/negotiate.rs`, `src/handlers/negotiate.rs`, `src/handlers/create.rs`, and `tests/integration_localfs.rs` parse exact POSIX GUID requests, reject malformed and duplicate singleton POSIX contexts, record negotiated POSIX support on SMB 3.1.1 connections, echo the POSIX support context, and feed the POSIX create/query paths. Broader POSIX metadata and share/cache-break semantics are tracked separately under POSIX mode/identity metadata |

## Authentication, Signing, Encryption

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| Anonymous guest session setup | done | NTLM anonymous path with a real SPNEGO-wrapped NTLMSSP challenge, SPNEGO init without NTLM completing as a null session when anonymous access is allowed, GoSMB-style SESSION_SETUP fixed request/response `StructureSize`, flags/security-mode/capabilities/channel/previous-session-id decoding, header-relative security-buffer range validation, and integration tests |
| NTLMv2 session setup via user store | done | `proto::auth::ntlm`, `handlers::session_setup` |
| Raw NTLMSSP and SPNEGO-wrapped NTLM | done | `handlers::session_setup`, auth tests, and direct SPNEGO wire coverage for NTLM-only `NegTokenInit` hints plus explicit `[1] NegTokenResp` wrappers carrying NTLM challenge tokens without a mechListMIC |
| SMB signing for authenticated SMB 3.x sessions | done | HMAC-SHA256, AES-CMAC, and AES-GMAC signing primitives exist, with negotiate-selected GMAC/CMAC algorithm support and GoSMB-compatible AES-GMAC nonce derivation including CANCEL command direction bits. Required-signing sessions sign responses including access-denied errors to unsigned requests with the negotiated CMAC or GMAC algorithm, SESSION_SETUP records the client signing-required bit while keeping guest/null sessions unsigned, authenticated SMB 3.0.2 TCP loopback coverage verifies unsigned post-session ECHO is rejected with a signed `STATUS_ACCESS_DENIED` response and a signed ECHO succeeds using the real NTLMv2-derived signing key, authenticated SMB 3.1.1 TCP loopback coverage verifies negotiated AES-GMAC and AES-CMAC sessions reject unsigned ECHO with signed access-denied responses and accept signed ECHO using the real NTLMv2/preauth-derived signing key, accepted transport-security sessions still accept signed required requests while returning signed cleartext SMB responses without SMB transform encryption, and opt-in `smbclient --client-protection=sign` smoke coverage mirrors GoSMB |
| Server/client-required signing enforcement | done | `require_signing` server config advertises NEGOTIATE signing-required, FSCTL_VALIDATE_NEGOTIATE_INFO mirrors it, NEGOTIATE and SESSION_SETUP client signing-required bits are recorded with direct handler coverage, authenticated sessions enforce signed post-setup traffic, and dispatch tests verify required-signing error responses are signed |
| SMB 3.x AES-CCM/GCM transform encryption | done | Wire-level `0xFD SMB` transform header codec, AES-128/256-GCM, AES-128/256-CCM, tamper detection, session-id/original-size fields, SMB 3.0/3.1.1 encryption key derivation helpers, encrypted negotiate configuration, capability advertisement, SMB 3.1.1 cipher response selection, SMB 3.0.2 fallback, per-session key storage, encrypted request decrypt, encrypted response wrapping, cleartext rejection, accepted transport-security skip behavior, TREE_CONNECT encryption/compression/isolated flags, authenticated NTLMv2 encrypted ECHO coverage for all SMB 3.1.1 AES-128/256 CCM/GCM ciphers, authenticated NTLMv2 encrypted TCP write/read loopbacks for SMB 3.1.1 AES-128-GCM and SMB 3.0.2 AES-128-CCM, and opt-in encrypted external-client smoke coverage mirror GoSMB |
| Reject cleartext post-auth traffic when encryption required | done | `src/dispatch.rs` and `tests/integration_negotiate.rs` reject cleartext authenticated requests once SMB encryption keys exist, return encrypted access-denied errors, and allow cleartext only when SMB 3.1.1 transport security has been accepted |
| Kerberos / fuller SPNEGO | not planned | Also not implemented in GoSMB. GoSMB only treats a non-NTLM/Kerberos-only SPNEGO init as guest/null-session completion when guest access is allowed, and Rust mirrors guest/null-session behavior without adding Kerberos authentication |

## File Server Operations

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| Share lookup / virtual backend registry | done | `ShareBackend`, `ShareBindings`, dynamic config tests, GoSMB-style TREE_CONNECT fixed `StructureSize`, header-relative UTF-16 path range, UNC path, and response `StructureSize` validation, ECHO/LOGOFF/TREE_DISCONNECT request/response codec fixed `StructureSize` validation, disk/IPC TREE_CONNECT response type and caching-flag coverage, active-session enforcement for TREE_CONNECT and tree-bound commands, TREE_DISCONNECT invalidation of trees/handles, and LOGOFF invalidation of session trees/handles while still allowing non-tree ECHO requests. The Rust test `MemFsBackend` mirrors GoSMB `vfs/mem_test.go` behavior for case-insensitive existing-path resolution, canonical parent casing on create/list, create-existing failure, case-collision rejection, case-only rename, directory subtree rename rekeying, open handles surviving unlink, live `put_file` updates preserving file identity, allocation growth to 4096-byte boundaries after writes extend past the current allocation, non-empty directory unlink rejection, and backend-originated watch events for direct child changes, recursive filtering, old/new rename records, and open-handle writes |
| CREATE / READ / WRITE / CLOSE | done | Core handlers plus localfs integration tests cover GoSMB behavior. CREATE records share access, enforces read/write/delete share conflicts for same-path live opens across connections, covers GoSMB access/share matrix rows, validates fixed request/response `StructureSize`, UTF-16 names, header-relative name/create-context ranges, GoSMB-style requested/granted oplock byte fixtures, create-context `Next`/alignment/name/data bounds, create options, impersonation level, leading names, desired access, requested oplock level, requested DOS attributes, directory creation via `FILE_DIRECTORY_FILE`, `QFid`, `TWrp`, malformed lease/durable/app-instance contexts, mixed durable generations, durable v1/v2 create/reconnect/replay, lease/oplock-dependent CREATE behavior, missing parent paths, readonly reopen/clear-readonly behavior, `FILE_DELETE_ON_CLOSE` access checks, GoSMB-compatible `$Extend\$Quota:$Q:$INDEX_ALLOCATION` probes, requested DOS attributes on mutating creates, CREATE delete-on-close namespace removal while preserving surviving open handles, and SET_INFO disposition delete-pending visibility until the last open closes. CLOSE validates fixed request/response `StructureSize` and cleanup semantics. READ/WRITE enforce per-open data access, allow execute-backed reads, reject directory reads, validate unsupported channel info and invalid offsets, reject payloads above negotiated max sizes, validate fixed `StructureSize`, decode GoSMB-style channel/remaining/channel-info request fields, accept GoSMB-style fixed READ bodies without trailing padding, validate header-relative buffers, honor byte-range locks, handle zero-length I/O, EOF/minimum-count status mapping, max SMB file-size `STATUS_DISK_FULL`, and update current offsets for FileAllInformation |
| CREATE maximal-access (`MxAc`) context | done | `src/handlers/create.rs` and `tests/integration_locks.rs` return success plus broad file access and cover response context emission alongside durable/lease CREATE cases |
| CREATE allocation-size (`AlSi`) context | done | `src/handlers/create.rs`, `src/info_class.rs`, `src/backend.rs`, and `tests/integration_localfs.rs` persist explicit base-file allocation metadata on mutating CREATEs, reflect it in CREATE responses, QUERY_INFO, QUERY_DIRECTORY, and close post-query attributes, and use GoSMB-style 4096-byte rounded default nonzero base-file allocations when no explicit allocation exists. Named-stream allocation fidelity is tracked under alternate data streams |
| Apple `AAPL` CREATE context | done | `src/handlers/create.rs` and `tests/integration_localfs.rs` decode GoSMB-style server query requests, return filtered server/volume/model response data including model-only reply-bitmap layout, emit AAPL responses before other response contexts, ignore malformed AAPL requests, and cover the TCP loopback response ordering |
| FLUSH | done | `handlers::flush`, GoSMB-style fixed request and response `StructureSize` validation, wire tests, backend-handle flush invocation coverage, standalone loopback coverage for file/directory/pipe handles and closed-handle `STATUS_FILE_CLOSED` |
| QUERY_DIRECTORY | done | `handlers::query_directory`, localfs integration tests, GoSMB-style invalid info-class status, fixed `StructureSize`, UTF-16 pattern alignment, and header-relative file-name buffer range validation, extended FileId directory classes with GoSMB-style fixed offsets for FileIndex, EOF, allocation, attributes, EA/reparse fields, 64-bit and 128-bit FileId slots, short names, and names, metadata/file-id consistency across common and extended directory classes, `FileBothDirectoryInformation` short-name encoding, `FileIdBothDirectoryInformation` short-name plus FileId field encoding, POSIX directory information fixed offsets for FileIndex, allocation, EOF, attributes, inode, mode, and name, POSIX directory mode/identity records, case-insensitive SMB wildcard matching including `*.LOG` and `*.*`, restart/reopen/index cursor handling including resume-key indexing across directory classes, tiny output-buffer continuation, SMB dot/dotdot entries including empty directories, current-mask filtering over the directory snapshot, initial no-match vs later no-match status mapping, restart/reopen refresh after localfs mutations and renames, restart-scan refresh against mutable virtual backend listings, large-directory continuation without duplicates, and continuation behavior that skips deleted unconsumed snapshot entries without shifting already-consumed entries |
| QUERY_INFO basic metadata | done | Includes basic/standard/all/name/alternate-name/normalized-name/network-open/stream/compression/attribute-tag/remote-protocol/file-id encoders, `FileNameInformation` and `FileAllInformation` handle-path names, `FileAlternateNameInformation` basename-derived short names, `FileRemoteProtocolInformation` SMB 3.1.1 dialect fields, normalized-name SMB 3.1.1 gating, empty root-name encoding, canonical backend casing, and canonical named-stream casing, stable backend/share identities for `FileInternalInformation`, `FileAllInformation`, `FileIdInformation`, and POSIX info, exact GoSMB-style `FileAccessInformation`, `FileNetworkOpenInformation`, `FileAttributeTagInformation`, and multi-record `FileStreamInformation` wire contents including `NextEntryOffset`, stream sizes, and UTF-16 names, filesystem volume/control/size/device/attribute/quota/full-size/object-id/sector-size encoders, direct GoSMB-style filesystem encoder-size checks for size/full-size/control/attribute information, GoSMB-style invalid file/filesystem class statuses, GoSMB additional file-class minimum-size coverage for EA/full-EA/name/position/mode/alignment/alternate-name/stream/compression/remote-protocol/file-id/POSIX info, `FileEaInformation` exact full-EA blob size reporting, file and filesystem fixed-size buffer handling, `STATUS_INFO_LENGTH_MISMATCH`, and `STATUS_BUFFER_OVERFLOW` truncation, GoSMB-style fixed `StructureSize` and input-buffer range validation, GoSMB-style default archive attributes plus path-scoped DOS attribute overlays, GoSMB SMB2_GETINFO class-specific access matrix coverage for synchronize/read-attributes/read-EA groups including `FileFullEaInformation` requiring `FileReadEA`, handle-specific `FileAccessInformation` / `FileAllInformation` access masks including write-only handles, and loopback/unit tests |
| SET_INFO timestamps, EOF, allocation, rename, delete-on-close | done | Direct GoSMB `server/set_info_test.go` behavior is covered: access gates for write-attributes, write-data/append, delete, write-EA, and security descriptor writes; rename denial on insufficient open access; per-open `FilePositionInformation` and `FileModeInformation` round-trip through QUERY_INFO and FileAllInformation, including invalid mode rejection and clearing mode back to `0`; `FileBasicInformation` persists DOS attributes and all four FILETIME fields, treats zero attributes/timestamps as no-op, keeps `NORMAL` exclusive, can clear READONLY on existing files, rejects invalid directory/temporary transitions, and preserves metadata after rejected updates; `FileEndOfFileInformation` grows and shrinks files with FileAllInformation verification; live-handle rename followed by EOF and basic-info updates stays bound to the renamed path; `FileAllocationInformation` truncates when shrinking and persists explicit base-file allocation for later metadata queries/listings; `FileFullEaInformation` persists, merges, deletes zero-length EAs, and requires `FILE_WRITE_EA`; `FileDispositionInformation` and `FileDispositionInformationEx` set, clear, and defer delete-on-close with delete-pending reflected in `FileStandardInformation` / `FileAllInformation`; `FileDispositionInformationEx` flag parsing rejects short and unknown-flag buffers; common delete-on-close/replace paths are covered; parent-directory DELETE opens block renames including the Batch-oplock resume case; `FileDispositionInformationEx` POSIX delete unlinks immediately while preserving readable open handles and reporting `nlink=0`; `FileRenameInformationEx` parser coverage includes POSIX+replace flags, unsupported POSIX-without-replace, unknown flags, and odd-length UTF-16 names; `FileRenameInformationEx` POSIX replacement preserves old open handles while new target opens see source data; base-file rename, EOF truncation, allocation shrink, and delete-on-close marking send conflicting lease-break notifications, return async `STATUS_PENDING`, wait for ACK before mutating namespace/data/delete-pending state, and complete final SET_INFO responses after ACK |
| IOCTL FSCTL decode and basic responses | done | `handlers::ioctl` handles GoSMB's IOCTL/FSCTL surface with typed request/response codecs, fixed `StructureSize` and header-relative input/output buffer validation, FSCTL flag enforcement, `FSCTL_VALIDATE_NEGOTIATE_INFO`, DFS referral failure status, unsupported pipe peek/wait and network-interface FSCTL status, non-FSCTL `PIPE_TRANSCEIVE` rejection, end-to-end `FSCTL_CREATE_OR_GET_OBJECT_ID` object-buffer coverage including the `GoSMBObj` prefix and short-output rejection, `FSCTL_LMR_REQUEST_RESILIENCY` enabling lock-sequence replay with duplicate lock/unlock coverage, `FSCTL_PIPE_TRANSCEIVE` for supported IPC pipes with bounded-output truncation, and the smbtorture private force-unacked-timeout FSCTL used by GoSMB's oplock timeout tests |
| IPC$ tree connect and named pipe open | done | Synthetic IPC$ TREE_CONNECT returns pipe share metadata with no-caching flags, CREATE opens supported `srvsvc` / `lsarpc` named pipes with GoSMB-style name normalization and rejects unsupported pipe names, FLUSH succeeds for pipe handles, DCE/RPC bind ACKs preserve call IDs and advertise the selected pipe name for `srvsvc` / `lsarpc`, `srvsvc` NetShareEnumAll returns configured shares, unsupported `srvsvc` opnums fault with GoSMB-compatible DCE/RPC status, `FSCTL_PIPE_TRANSCEIVE` honors max-output truncation, and pipe READ returns bounded async `STATUS_PENDING` that completes with `STATUS_CANCELLED` on SMB CANCEL or `STATUS_NOTIFY_CLEANUP` on pipe CLOSE/TREE_DISCONNECT |
| Change notify | done | Parses requests and validates GoSMB-style fixed `StructureSize`, front-door cases: invalid flags, oversized output buffers, closed handles, non-directory handles, and missing `FILE_LIST_DIRECTORY` access. Response decoding validates fixed `StructureSize` and header-relative output-buffer ranges. Otherwise-valid directory watches return async `STATUS_PENDING`, enforce a per-connection pending limit with `STATUS_INSUFFICIENT_RESOURCES`, treat completion filter `0` as matching any event, distinguish file-name from directory-name filters, distinguish size/last-write from attribute metadata filters, ignore watched-directory metadata events while still reporting child metadata changes, complete with `FILE_ACTION_ADDED` for simple child CREATE events, complete size/metadata-filter watches with `FILE_ACTION_MODIFIED` after matching WRITE or `FileBasicInformation` attribute updates, complete security-filter watches with `FILE_ACTION_MODIFIED` after `SET_INFO Security` descriptor updates, complete parent-directory watches with `FILE_ACTION_REMOVED` after successful delete-on-close unlink, return recursive watch names relative to the watched root, encode multi-record `FILE_NOTIFY_INFORMATION` chains with GoSMB-style `NextEntryOffset`/action/name fields, return `STATUS_NOTIFY_ENUM_DIR` when output does not fit with GoSMB-style first-overflow stickiness per handle, emit old/new-name records for same-directory base-file renames, apply GoSMB-style notify event coalescing for create/write bursts and remove/add/modify replacement sequences in the multi-record encoder, honor same-session async CANCEL with a final `STATUS_CANCELLED` while ignoring wrong-session CANCEL, complete pending watches with `STATUS_NOTIFY_CLEANUP` on CLOSE/TREE_DISCONNECT/LOGOFF, and complete watches rooted at a delete-pending directory with `STATUS_DELETE_PENDING`. `ShareBackend::watch` now provides optional backend-originated notify events, LocalFs translates native create/remove/modify/rename/security events into SMB notify records while a request is pending, and loopback plus smbtorture `smb2.notify` coverage verifies direct on-disk creates and security updates complete pending SMB CHANGE_NOTIFY requests |
| Byte-range locks | done | Wire plus GoSMB-style fixed `StructureSize`, nonzero count, lock-element range, and response `StructureSize` validation, immediate lock/unlock enforcement, READ/WRITE conflict checks, unknown FileId validation, invalid range/flag handling, exact-owned-range unlock enforcement, unlock-with-fail-immediately rejection without releasing the lock, close cleanup, async wait completion after unlock, SMB CANCEL completion with `STATUS_CANCELLED`, close cleanup with `STATUS_RANGE_NOT_LOCKED`, shared-lock read/write semantics, stacked same-handle locks, zero-length range edge cases, same-handle exclusive conflicts, multi-lock fail-immediately validation, GoSMB-style partial mixed-unlock behavior, atomic failure for invalid mixed lock requests, resilient-handle lock-sequence replay after `FSCTL_LMR_REQUEST_RESILIENCY`, durable-v1 lock-sequence duplicate LOCK/UNLOCK replay for batch-oplock durable creates, exclusive LOCK breaks the same handle's Level II oplock to none when another handle is open, and the direct GoSMB `server/lock_test.go` matrix is covered by TCP loopback tests including pending lock async completion, cancel, close cleanup, shared/exclusive lock conflicts, exact unlock ownership, zero-length lock points, invalid mixed requests, durable/resilient lock sequence replay, and LOCK-triggered Level II oplock breaks after Batch-to-LevelII downgrade |
| Extended attributes | done | `ExtA` create context validation/storage with loopback `FileFullEaInformation` and `FileEaInformation` verification, `SET_INFO FileFullEaInformation` merge/delete semantics including zero-length delete and zero-length unknown-name no-op, denied `SET_INFO FileFullEaInformation` without `FILE_WRITE_EA`, `QUERY_INFO FileEaInformation` and `FileFullEaInformation` including empty full-EA blob and `FileReadEA` access enforcement, rename/delete cleanup, `FileReadEA`/`FileWriteEA` enforcement, GoSMB-compatible zero EA-size slot in `FileAllInformation`, and loopback/unit tests |
| Alternate data streams | done | GoSMB-derived loopback coverage now maps the stream test matrix: named stream CREATE/READ/WRITE, `FileStreamInformation` default+named stream listing from base and named-stream handles including write-only stream handles, write-updated and zero-byte stream listings, case-insensitive reopen/read variants, duplicate lower-case `FILE_CREATE` collision, canonical stream-name casing in listings and normalized names, stream overwrite action/listing with retained named-stream entry, stream-relative named-stream rename with overwrite, rename-to-default-stream, full-base stream rename returning sharing violation, default stream aliases including `::$DATA` base-file reads, wildcard stream names, directory-base named streams and default-stream statuses/listing, missing-base create rules including `FILE_CREATE`, `FILE_OPEN_IF`, and `FILE_OVERWRITE_IF` base creation, fresh create cleanup for stale stream/delete-pending metadata, base overwrite cleanup, base rename rekeying with post-rename stream listing and reopen/read verification, base rename with an already-open named stream, base rename denial while a named stream is open when required by local share-mode coverage, named stream delete-on-close cleanup, GoSMB-derived same-stream share-mode blocking with independent streams on one base file, base delete/share-delete matrix rows, stream-name validation matrix rows including the control-character sweep, stream/base shared basic-info creation-time, timestamp, and attribute propagation, named-stream EOF size isolation, `FileNameInformation` stripping of stream data-type suffixes, and full external `smb2.streams` smbtorture alias coverage |
| Security descriptors | done | GoSMB-derived loopback and unit coverage now maps the security descriptor matrix: default QUERY_SECURITY returns a self-relative descriptor with DACL-present control bits and valid owner/DACL offsets, READ_CONTROL gating, `AdditionalInformation` owner/group/DACL filtering, security-query `STATUS_BUFFER_TOO_SMALL`, create-time `SecD` storage/reopen/rename query support with persistence and missing-DACL defaulting, SET_INFO security descriptor persistence, full DACL replacement, SET_INFO no-DACL to nil-DACL normalization, CREATE-time DACL enforcement for empty DACLs, allow-only DACLs, deny ACEs, parent-directory child-create denial, and inheritable ACE propagation to newly created `FILE_CREATE` / `FILE_OPEN_IF` / overwrite-if children |
| POSIX mode/identity metadata | done | Direct GoSMB POSIX behavior is covered: POSIX create-context mode/identity storage, create response context encoding, QUERY_INFO `FilePOSIXInformation`, close/reopen persistence, rename rekey, delete/recreate cleanup back to default POSIX metadata, QUERY_DIRECTORY `FilePOSIXInformation`, malformed POSIX create-context rejection, immediate POSIX disposition unlink while preserving readable open handles with `nlink=0`/delete-pending metadata, and POSIX rename-over-open-target replacement preserving old open handles while new opens see source data |

## Performance And Concurrency

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| Multi-credit `CreditCharge` validation | done | `src/dispatch.rs`, `tests/integration_quic.rs`, `tests/integration_localfs.rs`, `tests/integration_ipc.rs`, and `examples/smbperf/src/main.rs` cover credit balance/window accounting, capped requested-credit grants, growth from a single-credit grant to the 8192-credit default window, 8192-credit default grant coverage for smbtorture/WAN windows, overdraw rejection, related-operation bypass, and payload-size charge validation for large READ/WRITE/QUERY_DIRECTORY/IOCTL |
| WAN-oriented 8 MiB read/write defaults | done | `src/builder.rs`, `src/handlers/negotiate.rs`, `src/dispatch.rs`, and `examples/smbperf/src/main.rs` set 8 MiB read/write builder defaults, advertise 8 MiB max transact/read/write sizes in NEGOTIATE, cover a 10 Gbps / 200 ms BDP profile with default credits, and expose builder APIs for max-size overrides |
| Concurrent pipelined READ/WRITE dispatch | done | `src/conn/reader.rs`, `src/dispatch.rs`, `src/server.rs`, and `tests/integration_localfs.rs` dispatch standalone non-compound READ/WRITE frames concurrently behind a connection dispatch gate, wait for workers before teardown, serialize same-open WRITE mutations while allowing independent-handle writes and reads to overlap, and disconnect malformed short payloads while releasing non-durable opens; loopback tests mirror GoSMB transport dispatch coverage |
| Compound request handling and related IDs | done | Direct GoSMB `server/compound_test.go` behavior is covered by TCP loopback tests: related CREATE/READ/CLOSE, CREATE/QUERY_INFO/CLOSE, failed-related status propagation, repeated related CLOSE, first-related invalid handling, unknown related command invalid-parameter responses preserving the raw opcode, related-file-id reset across unrelated gaps, related and unrelated QUERY_DIRECTORY cursor continuation, QUERY_DIRECTORY followed by CLOSE preserving the find response while closing the handle, related reuse of the prior request FileId for FLUSH/CLOSE, FLUSH/FLUSH, WRITE/WRITE, and READ/READ, async compound CREATE/related SET_INFO rename completion after a lease-break ACK, and async first-command CREATE final responses that include related QUERY_INFO/CLOSE tail commands after ACK. Dispatcher unit coverage also verifies GoSMB-style compound response stitching: `NextCommand` uses 8-byte aligned response lengths and the final response is padded when part of a compound chain |
| Async pending responses | done | Async response framing is used by change notify, named pipe READ cancellation/cleanup, byte-range lock waits, lease and oplock cache-break waits, WRITE and SET_INFO cache-break tasks, Batch-oplock share-conflict CREATE waits, durable replay pending-create checks, and compound cache-break final responses. Dispatcher unit coverage verifies GoSMB-style async pending/final framing with the async header flag, stable AsyncId, pending response credits, final-completion zero credits, and notify response body `StructureSize`; SMB2 CANCEL has typed wire coverage including fixed structure-size validation, and GoSMB-derived integration coverage verifies cancel, cleanup, ACK, timeout, and final-response behavior across the async paths |

## Caching And Durable Handles

| GoSMB feature | Rust status | Rust evidence / next work |
| --- | --- | --- |
| CREATE oplock/lease request parsing | done | Direct GoSMB lease/oplock CREATE behavior is covered: lease v1/v2 context parsing/validation, `RQLS` response encoding with v1/v2 key/state/flags/parent-key/epoch byte-layout checks, durable-v2 response timeout plus persistent-flag masking, lease metadata storage, read/write and metadata-only lease grants, read-caching grants for write-only opens, existing stat/read-control coexistence, no-read-caching downgrade to `LEASE_NONE`, directory no-grant behavior, ordinary Level II/Exclusive/Batch oplock grants, Level II grant alongside read leases, Exclusive-to-Level-II downgrade after ACK, same-key strict-superset upgrades with v1/v2 response shapes and epoch preservation, contended same-key compatibility checks, same-key different-file rejection, `LEASE_BREAK_IN_PROGRESS`, same-key rearming after break-to-none, new-key write-caching downgrade, write-capable open preservation of read leases, write/SET_INFO EOF read-lease breaks, overwrite lease breaks to none before truncation, handle-caching breaks before final share-conflict status, Batch/Exclusive oplock break notifications and waits, wrong-state ACK rejection, pending CREATE cleanup on cancel/tree/logoff, delete-pending no-break behavior, attribute-only OpenIf no-break behavior, attribute-only overwrite Batch-break Level II grant, and fixed `StructureSize` validation for lease/oplock break codecs |
| Lease/oplock grant and break state | done | Lease and ordinary oplock state is stored on opens and returned in CREATE/reconnect/replay responses. GoSMB-derived coverage verifies conflicting CREATE, WRITE, and SET_INFO cache-break state, direct lease/oplock ACK and notification byte-layout checks for key/FileId/state/epoch/flags fields, SMB3 v2 lease epoch handling, one break notification per lease key, `STATUS_PENDING`, same-key `LEASE_BREAK_IN_PROGRESS`, rearming after break-to-none, wrong-state ACK preservation of pending creates, final async completion after ACK, accepted ACK downgrade of same-key groups, timeout-forced final break targets, cancel/tree/logoff cleanup, SMB 2.1 zero-epoch read-lease break notifications, handle-caching share-conflict breaks, Batch/Exclusive oplock breaks to Level II/none, ACK file-id/level validation, resume after ACK or blocking Batch handle close, final share-conflict status after Batch breaks, attribute-only overwrite Batch break to Level II, smbtorture force-unacked Batch cleanup, Level II write breaks without ACK across connections with colliding FileIds, and delete-on-close silent Level II drops |
| Async block on cache break until ACK/timeout | done | Conflicting CREATE against existing write leases and Batch/Exclusive oplocks uses SMB2 async pending/final flow, resumes when the matching lease/oplock ACK arrives, resumes after timeout with the break forced to the final target, returns `STATUS_CANCELLED` on CANCEL, and returns cleanup on TREE_DISCONNECT/LOGOFF. WRITE pends before mutation and applies only after lease-break ACK/timeout, LOGOFF completes pending writes without mutation, SET_INFO rename/EOF/allocation/delete-on-close tasks pend before mutation and resume after ACK/timeout, compound CREATE/SET_INFO waits defer and stitch final compound responses after ACK, share-conflicting handle-caching lease and Batch-oplock CREATEs pend before final status, delete-on-close Batch waits resume after the blocking handle closes, and the smbtorture force-unacked path cleans an unacked Batch handle before resuming a waiting CREATE |
| Non-persistent durable handle v2 | done | Direct GoSMB durable-v2 behavior is covered: SMB 3.x `DH2Q` creates with handle-caching lease requests and Batch oplocks return non-persistent v2 durable responses, persistent requests are accepted as non-persistent, lease metadata, Batch oplock level, CreateGuid, AppInstanceID, AppInstanceVersion, and durable owner are preserved, TREE_DISCONNECT/LOGOFF/TCP disconnect and same-connection/cross-connection `PreviousSessionId` detach opens for reconnect, `DH2C` reconnect reattaches lease-backed and Batch-oplock opens, reconnect ignores CREATE access/share fields while rejecting wrong client, wrong owner, wrong CreateGuid, wrong volatile FileId, and v2-reconnect-to-v1 durable attempts without attaching, missing reconnect state fails without opening a fresh handle, CLOSE removes durable state and share conflicts, handle-caching lease breaks to none remove reconnectability, timeout scavenging removes detached opens, fresh opens invalidate detached reconnect state including restrictive-share detached opens, nonzero AppInstanceID takeover closes the prior durable open, completed durable creates replay without reopening/truncating the backend, and durable TCP-disconnect/reconnect wire coverage mirrors GoSMB by verifying the reconnected FileId remains usable for a post-reconnect byte-checked READ |
| Durable v1 non-persistent handles | done | Direct GoSMB durable-v1 behavior is covered: Batch-oplock and handle-caching-lease `DHnQ` CREATE requests return a durable response context, mark the open durable, detach on TREE_DISCONNECT/LOGOFF/TCP disconnect and same-connection/cross-connection `PreviousSessionId` session setup, reconnect through `DHnC`, preserve the original FileId and Batch oplock for post-reconnect READ even when reconnect CREATE fields are bogus, pass request lease contexts through v1 lease reconnect, require original names for lease-backed v1 reconnects while retaining batch reconnect field-ignore behavior, reject lease-backed reconnects from different client GUIDs and wrong durable owners, keep delete-on-close durable handles detached without unlinking until reconnect+CLOSE, scavenge expired detached handles, invalidate detached durable v1 reconnect state when a fresh open succeeds on the same path, unlink detached delete-on-close durable files when a fresh regular open scavenges them, close rather than detach no-write lease handles that hold byte-range locks, and enable durable lock-sequence replay |
| Persistent durable handles | not planned | Also not implemented in GoSMB. GoSMB accepts the persistent durable-v2 request flag but returns a non-persistent durable response and does not implement persistent-handle storage; Rust mirrors that non-persistent behavior and covers it in durable-v2 tests |
| CREATE replay via create GUID | done | Completed durable v2 creates with matching `DH2Q` CreateGuid, client GUID, durable owner, and `SMB2_FLAGS_REPLAY_OPERATION` return the existing FileId/create action and do not reapply overwrite/truncate side effects; duplicate CreateGuid requests without the replay flag return `STATUS_DUPLICATE_OBJECTID`; replay with a mismatched lease key returns `STATUS_ACCESS_DENIED`; live replays from another attached connection/session return `STATUS_DUPLICATE_OBJECTID`; replay while the original durable v2 create is still pending behind a cache break returns `STATUS_FILE_NOT_AVAILABLE`; completed async cache-break CREATEs are replayable from their cached final response even after the live durable open is closed; replay is scoped by durable owner; replay only intercepts GoSMB-eligible durable opens while missing/ineligible replay targets fall through to normal CREATE; consumed-and-used durable replays fall through to fresh creates while preserving duplicate checks for later handles; durable WRITE/IOCTL/SET_INFO channel-sequence validation returns `STATUS_FILE_NOT_AVAILABLE` for stale CSNs; and local plus smbtorture `smb2.replay` coverage mirrors GoSMB |
| Query-on-disk-id (`QFid`) CREATE response | done | `src/handlers/create.rs`, `src/fs/local.rs`, and `tests/integration_localfs.rs` return backend-stable disk file id plus stable share volume id, reject non-empty requests, and cover localfs loopback identity agreement |
| `FileInternalInformation` stable object IDs | done | `FileInfo.file_index_or` prefers backend identities with SMB handle fallback; localfs derives stable ids from metadata and loopback tests cover `QFid`, `FileInternalInformation`, and `FileIdInformation` agreement |

## Test Port Checklist

Port GoSMB tests by behavior, not by source translation:

1. `internal/smbproto/aapl_test.go`, `codec_test.go`, `smb1_test.go`, and
   `transport_test.go` -> Rust typed wire, AAPL, SMB1 negotiate bridge, and
   direct-TCP/NetBIOS prelude unit tests.
2. `internal/smbcrypto/compression_test.go`, `encryption_test.go`,
   `signing_test.go`, and `xpress_test.go` -> Rust crypto/compression/sign/encrypt tests.
3. `internal/spnego/spnego_test.go` -> Rust SPNEGO init/response codec tests.
4. `server/conn_test.go` and `server/access_test.go` -> negotiate, signing,
   encryption, credits, guest/auth, tree/session lifecycle, access gates,
   negotiated max I/O sizes, and share-mode tests.
5. `server/compound_test.go` -> compound and async compound integration tests.
6. `server/create_context_test.go` and `server/durable_wire_test.go` -> leases,
   oplocks, durable handles, durable reconnect wire behavior, replay, and create
   context validation.
7. `server/query_directory_test.go` and `server/query_info_test.go` -> metadata,
   named streams, query-info classes, and directory listing behavior.
8. `server/set_info_test.go` -> rename, EOF, timestamps, delete-on-close, security/EA classes.
9. `server/lock_test.go` -> byte-range lock conflicts and durable lock sequencing.
10. `server/change_notify_test.go` -> pending notify and cleanup.
11. `server/flush_test.go`, `server/ipc_pipe_test.go`, and
    `server/dcerpc_test.go` -> FLUSH, IPC pipe opens/reads, DCE/RPC bind, SRVSVC
    share enumeration, and pipe FSCTL behavior.
12. `server/transport_dispatch_test.go` -> pipelined READ/WRITE dispatch,
    write serialization, worker teardown, and malformed-frame cleanup.
13. `server/smbclient_smoke_test.go`, `server/smbtorture_smoke_test.go`,
    `server/smbutil_smoke_test.go`, `server/mount_smbfs_smoke_test.go`,
    `server/client_integration_test.go`, and CloudSoda coverage in
    `server/quic_test.go` -> opt-in external client/smbtorture tests;
    CloudSoda/go-smb2 TCP/QUIC, `smbclient`, `smbutil`, `mount_smbfs`, and
    `smbtorture` are ported.
14. `server/quic_test.go` -> Rust QUIC transport config, ALPN, single-stream,
    guest/authenticated read-write, transport-security, WAN-profile, and
    CloudSoda QUIC coverage.
15. `vfs/mem_test.go` -> Rust `MemFsBackend` unit coverage for case-insensitive names, canonical casing, rename, unlink, and open-node lifetime semantics.
16. `cmd/smbperf/main_test.go` -> `examples/smbperf` unit coverage for WAN BDP math, QUIC transport parsing, depth sweeps, and text/CSV/JSON measurements.
17. `examples/hnfs/hnfs_test.go` -> `examples/hnfs` unit coverage for stable story prefixes and ID extraction.
18. `cmd/gosmbd/main_test.go` -> audited as daemon CLI behavior rather than core SMB server parity; Rust QUIC server construction covers the transport settings that map to Quinn, while quic-go's separate handshake idle timeout and development-certificate warning helpers remain CLI-specific.

## Current Baseline

As of 2026-06-22:

```sh
cd /Users/bill/Desktop/gosmb/GoSMB && go test ./...
tools/porting-test-audit.sh summary
tools/porting-matrix-audit.sh
cargo test --features quic
cargo test --workspace --features quic
```

pass on macOS. The GoSMB source-of-truth tests are green, and the Rust workspace
run includes the QUIC loopback/WAN-profile tests, IPC, localfs,
lock/oplock/durable-handle, external-client smoke wrappers in their non-opt-in
mode, smbtorture harness tests, doctests, and workspace example/tool crates
(`examples/minimal`, `examples/hnfs`, and `examples/smbperf`). The latest
full-suite baseline includes the GoSMB-compatible
`FSCTL_QUERY_NETWORK_INTERFACE_INFO` status mapping, pending WRITE cache-break
cleanup on LOGOFF, tree-disconnect durable reconnect invalidation, delayed
scavenging for durable delete-on-close opens, cross-connection Level II oplock
break notifications without relying on colliding FileIds, and the `mount_smbfs`
harness hardening.

The opt-in Samba `smbclient` smoke gate also passes locally:

```sh
GOSMB_RUN_SMBCLIENT=1 cargo test --features quic --test smbclient_smoke -- --nocapture
```

It covers signed and encrypted list/read flows, wrong-password and missing-file
failures, small and large put/get flows, and directory rename/delete.

The opt-in CloudSoda/go-smb2 external client gate also passes locally:

```sh
GOSMB_RUN_CLOUDSODA=1 cargo test --features quic --test cloudsoda_smoke -- --nocapture
```

It covers authenticated TCP share enumeration, mount, read/stat/seek/readdir,
write/reopen/read flows, and the same mount/read/write/reopen flow over SMB over
QUIC.

The opt-in macOS `mount_smbfs` gate also passes locally:

```sh
GOSMB_RUN_MOUNT_SMBFS=1 cargo test --features quic --test mount_smbfs_smoke -- --nocapture
```

It covers unencrypted and encrypted macOS mounts, mounted-file read/write plus
SMB FLUSH visibility, and mounted-directory change-notify visibility for files
created through a separate SMB connection. The harness serializes the mount
tests, uses a multi-thread Tokio runtime, calls `fsync(2)` directly for the
FLUSH check, drops mounted file handles before unmount, and sets
`kill_on_drop(true)` for timed external commands.

The opt-in macOS `smbutil view` gate mirrors GoSMB's port-445 constraint. It
skips by default when the test process cannot bind `127.0.0.1:445`; use the
strict form below in a privileged shell to require the real client path:

```sh
GOSMB_RUN_SMBUTIL=1 GOSMB_REQUIRE_SMBUTIL=1 cargo test --features quic --test smbutil_smoke -- --nocapture
```

The focused localfs integration suite also passes:

```sh
cargo test --features quic --test integration_localfs -- --nocapture
```

The opt-in stable Samba interop target also passes:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TARGET=stable \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

The latest stable run covers 53 allowlisted child suites and includes
`smb2.dir.many`, which validates `QUERY_DIRECTORY` continuation across 700
files, five directory-info classes, and SINGLE/INDEX/RESTART/REOPEN modes. Rust
now returns wire `FileIndex` values as resume keys so clients using
`SMB2_CONTINUE_FLAG_INDEX` continue after the last returned entry instead of
looping on it.

Broader `GOSMB_SMBTORTURE_TARGET=relevant` coverage passes all 476 currently
selected cases as of the latest fresh run. The expanded sweep covers the stable
set plus full streams including missing-base `FILE_OPEN_IF` named-stream
creation, expanded timestamps, delete-on-close permissions, session
reauthentication/reconnect/bind-negative/signing/encryption cases including
anonymous encryption/signing, lease, oplock, durable, notify, replay, and related
performance/concurrency suites. This baseline includes the GoSMB-compatible
`FSCTL_QUERY_NETWORK_INTERFACE_INFO` status mapping to
`STATUS_FS_DRIVER_REQUIRED`:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TARGET=relevant \
GOSMB_SMBTORTURE_TIMEOUT_SECS=300 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

Focused reauth cleanup coverage still passes:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.session.reauth5' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

Additional focused session interop coverage now passes:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.session.reconnect1 smb2.session.reconnect2 smb2.session.bind_negative_smb3to3s smb2.session.bind_negative_smb3encGtoCs' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

The broader relevant sweep now moves past `smb2.compound.invalid2` after
related-operation context tracking was split from ordinary previous-header
presence:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.compound.invalid2' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

`smb2.notify.dir` now passes while `smb2.session.reauth5` remains green after
missing-file delete-on-close cleanup opens were limited to the reauth-anonymous
cleanup case and ordinary-session missing cleanup unlinks kept returning
`STATUS_OBJECT_NAME_NOT_FOUND`:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.notify.dir' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

`smb2.create.mkdir-visible` now passes after matching Samba's cleanup semantics:
children retry until the concurrently-created directory inherits the deny ACE
and returns `STATUS_ACCESS_DENIED`, directory delete-on-close can unlink an
empty directory name while another compatible handle remains open, and repeated
delete-on-close opens against an already-deleted name return not-found instead
of a synthetic success:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.create.mkdir-visible' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

The SMB 3.1.1 bind-negative signing/encryption transition matrix now passes,
including mixed CMAC/HMAC session binding, GMAC-specific negative statuses,
SMB 2.x/3.0 to SMB 3.1.1 GMAC transition negatives, and encryption-only
GCM/CCM mismatch negatives:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.session.bind_negative_smb3encGtoCs smb2.session.bind_negative_smb3encGtoCd smb2.session.bind_negative_smb3sneGtoCs smb2.session.bind_negative_smb3sneGtoCd smb2.session.bind_negative_smb3sneGtoHs smb2.session.bind_negative_smb3sneGtoHd smb2.session.bind_negative_smb3signCtoHs smb2.session.bind_negative_smb3signCtoHd smb2.session.bind_negative_smb3signCtoGs smb2.session.bind_negative_smb3signCtoGd smb2.session.bind_negative_smb3signHtoCs smb2.session.bind_negative_smb3signHtoCd smb2.session.bind_negative_smb3signHtoGs smb2.session.bind_negative_smb3signHtoGd smb2.session.bind_negative_smb3signGtoCs smb2.session.bind_negative_smb3signGtoCd smb2.session.bind_negative_smb3signGtoHs smb2.session.bind_negative_smb3signGtoHd smb2.session.bind_negative_smb3signC30toGs smb2.session.bind_negative_smb3signC30toGd smb2.session.bind_negative_smb3signH2XtoGs smb2.session.bind_negative_smb3signH2XtoGd smb2.session.bind_negative_smb3signGtoC30s smb2.session.bind_negative_smb3signGtoC30d smb2.session.bind_negative_smb3signGtoH2Xs smb2.session.bind_negative_smb3signGtoH2Xd' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=180 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

The anonymous encryption and anonymous signing interop cases also pass.
Anonymous sessions now keep SMB signing opportunistic: signed anonymous
requests are verified and signed responses are returned when the exported
anonymous session key is present, bad anonymous signatures return
`STATUS_ACCESS_DENIED` without disconnecting, and unsigned anonymous requests
remain accepted. SMB 3.1.1 anonymous signing uses the preauth-derived signing
key without also enabling standalone anonymous transform decryption; anonymous
encryption remains allowed only after an authenticated session exists on the
same connection.

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.session.anon-encryption1 smb2.session.anon-encryption2 smb2.session.anon-signing1 smb2.session.anon-signing2' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=120 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```

The wider session sweep now passes:

```sh
GOSMB_RUN_SMBTORTURE=1 \
SMBTORTURE=/Users/bill/.local/bin/smbtorture \
GOSMB_SMBTORTURE_TESTS='smb2.session' \
GOSMB_SMBTORTURE_TIMEOUT_SECS=240 \
cargo test --features quic --test smbtorture_smoke smbtorture_smoke -- --nocapture
```
