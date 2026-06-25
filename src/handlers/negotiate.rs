//! NEGOTIATE handler.

use std::sync::Arc;

use crate::proto::auth::spnego::encode_init_response;
use crate::proto::crypto::SigningAlgo;
use crate::proto::header::Smb2Header;
use crate::proto::messages::{
    CompressionCapabilities, Dialect, EncryptionCapabilities, NegotiateContext, NegotiateRequest,
    NegotiateResponse, PreauthIntegrityCapabilities, RdmaTransformCapabilities,
    SigningCapabilities,
};
use tracing::info;
use uuid::Uuid;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::{fill_random, now_filetime, utf16le_to_string};

// MS-SMB2 §2.2.4 SecurityMode bits.
pub(crate) const NEGOTIATE_SECURITY_MODE: u16 = 0x0001;
pub(crate) const NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;

pub(crate) fn negotiate_security_mode(require_signing: bool) -> u16 {
    NEGOTIATE_SECURITY_MODE
        | if require_signing {
            NEGOTIATE_SIGNING_REQUIRED
        } else {
            0
        }
}

const CAP_DFS: u32 = 0x0000_0001;
const CAP_LEASING: u32 = 0x0000_0002;
const CAP_LARGE_MTU: u32 = 0x0000_0004;
const CAP_ENCRYPTION: u32 = 0x0000_0040;
pub(crate) const NEGOTIATE_CAPABILITIES: u32 = CAP_DFS | CAP_LEASING | CAP_LARGE_MTU;

pub(crate) fn negotiate_capabilities(encryption_required: bool) -> u32 {
    NEGOTIATE_CAPABILITIES
        | if encryption_required {
            CAP_ENCRYPTION
        } else {
            0
        }
}

pub(crate) fn negotiate_capabilities_for_dialect(
    dialect: Option<Dialect>,
    advertise_encryption: bool,
) -> u32 {
    match dialect {
        // SMB 2.0.2 does not define the SMB 2.1+ global capabilities. Samba's
        // SMB 2.0.2 interop path rejects the connection if we advertise the
        // newer capability mix while selecting dialect 0x0202.
        Some(Dialect::Smb202) => 0,
        _ => negotiate_capabilities(advertise_encryption),
    }
}

#[derive(Debug, Clone)]
struct Smb311Negotiation {
    selected_signing_algorithm: Option<u16>,
    posix_requested: bool,
    net_name: Option<String>,
    compression_algorithms: Vec<u16>,
    compression_chained: bool,
    selected_compression_algorithm: u16,
    rdma_transform_ids: Vec<u16>,
    encryption_ciphers: Vec<u16>,
    selected_encryption_cipher: u16,
    transport_security_accepted: bool,
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    _hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match NegotiateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.security_mode & NEGOTIATE_SIGNING_REQUIRED != 0 {
        *conn.client_requires_signing.write().await = true;
    }

    let transport_security_accepted =
        conn.secure_transport && smb311_requests_transport_security(&req, body);
    let encryption_required = server.config.encrypt_data && !transport_security_accepted;

    // Pick the highest dialect we support that the client offered.
    const SUPPORTED: &[u16] = &[0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    let mut chosen: Option<u16> = None;
    for &d in &req.dialects {
        if SUPPORTED.contains(&d)
            && dialect_compatible_with_encryption(d, encryption_required, &req, body)
        {
            chosen = match chosen {
                None => Some(d),
                Some(prev) if d > prev => Some(d),
                Some(prev) => Some(prev),
            };
        }
    }
    let chosen = match chosen {
        Some(d) => d,
        None => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };
    let dialect = match Dialect::from_u16(chosen) {
        Some(dialect) => dialect,
        None => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };
    let mut smb311 = if dialect == Dialect::Smb311 {
        match validate_smb311_negotiate(
            &req,
            body,
            encryption_required,
            transport_security_accepted,
        ) {
            Ok(negotiation) => Some(negotiation),
            Err(status) => return HandlerResponse::err(status),
        }
    } else {
        None
    };
    if server.config.disable_compression
        && let Some(negotiation) = smb311.as_mut()
    {
        negotiation.compression_algorithms.clear();
        negotiation.compression_chained = false;
        negotiation.selected_compression_algorithm = 0;
    }
    let selected_signing_algorithm = smb311
        .as_ref()
        .and_then(|negotiation| negotiation.selected_signing_algorithm);
    let selected_encryption_cipher = if dialect == Dialect::Smb311 {
        smb311
            .as_ref()
            .map_or(0, |negotiation| negotiation.selected_encryption_cipher)
    } else {
        selected_encryption_cipher_for_dialect(dialect, None, encryption_required)
    };
    let advertise_smb_encryption =
        dialect_supports_smb_encryption(dialect) && !transport_security_accepted;

    *conn.dialect.write().await = Some(dialect);
    *conn.client_guid.write().await = Uuid::from_bytes(req.client_guid);
    *conn.negotiated_net_name.write().await = smb311
        .as_ref()
        .and_then(|negotiation| negotiation.net_name.clone());
    *conn.compression_algorithms.write().await = smb311
        .as_ref()
        .map(|negotiation| negotiation.compression_algorithms.clone())
        .unwrap_or_default();
    *conn.compression_chained.write().await = smb311
        .as_ref()
        .is_some_and(|negotiation| negotiation.compression_chained);
    *conn.compression_algorithm.write().await = smb311
        .as_ref()
        .map_or(0, |negotiation| negotiation.selected_compression_algorithm);
    *conn.rdma_transform_ids.write().await = smb311
        .as_ref()
        .map(|negotiation| negotiation.rdma_transform_ids.clone())
        .unwrap_or_default();
    *conn.posix_extensions.write().await = dialect == Dialect::Smb311
        && smb311
            .as_ref()
            .is_some_and(|negotiation| negotiation.posix_requested);
    *conn.encryption_ciphers.write().await = smb311
        .as_ref()
        .map(|negotiation| negotiation.encryption_ciphers.clone())
        .unwrap_or_default();
    *conn.encryption_cipher.write().await = selected_encryption_cipher;
    *conn.transport_security.write().await = smb311
        .as_ref()
        .is_some_and(|negotiation| negotiation.transport_security_accepted);
    *conn.signing_algo.write().await = match (dialect, selected_signing_algorithm) {
        (Dialect::Smb202 | Dialect::Smb210, _) => SigningAlgo::HmacSha256,
        (Dialect::Smb311, Some(SigningCapabilities::ALGORITHM_HMAC_SHA256)) => {
            SigningAlgo::HmacSha256
        }
        (Dialect::Smb311, Some(SigningCapabilities::ALGORITHM_AES_GMAC)) => SigningAlgo::AesGmac,
        _ => SigningAlgo::AesCmac,
    };
    *conn.signing_context_present.write().await = selected_signing_algorithm.is_some();

    // Build SPNEGO security blob (mech-list-only, advertising NTLMSSP).
    let security_blob = encode_init_response();
    let security_buffer_offset: u16 = 64 + 64; // SMB2 header + fixed NEG response (64 bytes)
    let security_buffer_length: u16 = security_blob.len() as u16;

    // For 3.1.1 build negotiate contexts.
    let mut contexts_bytes: Vec<u8> = Vec::new();
    let mut context_count: u16 = 0;
    let mut negotiate_context_offset: u32 = 0;

    if dialect == Dialect::Smb311 {
        let client_requested_posix = smb311
            .as_ref()
            .is_some_and(|negotiation| negotiation.posix_requested);

        // PREAUTH_INTEGRITY_CAPABILITIES
        let mut salt = [0u8; 32];
        fill_random(&mut salt);
        let preauth_caps = PreauthIntegrityCapabilities {
            hash_algorithm_count: 1,
            salt_length: 32,
            hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
            salt: salt.to_vec(),
        };
        let preauth_data = {
            use binrw::BinWrite;
            let mut c = std::io::Cursor::new(Vec::new());
            BinWrite::write(&preauth_caps, &mut c).expect("preauth negotiate context encodes");
            c.into_inner()
        };
        let preauth_ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
            data_length: preauth_data.len() as u16,
            reserved: 0,
            data: preauth_data,
        };

        let mut ctxs = vec![preauth_ctx];
        if let Some(signing_algorithm) = selected_signing_algorithm {
            let signing_caps = SigningCapabilities {
                signing_algorithm_count: 1,
                signing_algorithms: vec![signing_algorithm],
            };
            let signing_data = {
                use binrw::BinWrite;
                let mut c = std::io::Cursor::new(Vec::new());
                BinWrite::write(&signing_caps, &mut c).expect("signing negotiate context encodes");
                c.into_inner()
            };
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_SIGNING,
                data_length: signing_data.len() as u16,
                reserved: 0,
                data: signing_data,
            });
        }
        if client_requested_posix {
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_POSIX,
                data_length: NegotiateContext::POSIX_EXTENSIONS_GUID.len() as u16,
                reserved: 0,
                data: NegotiateContext::POSIX_EXTENSIONS_GUID.to_vec(),
            });
        }
        if let Some(compression_algorithm) = smb311
            .as_ref()
            .map(|negotiation| negotiation.selected_compression_algorithm)
            .filter(|algorithm| *algorithm != 0)
        {
            let compression_caps = CompressionCapabilities {
                compression_algorithm_count: 1,
                padding: 0,
                flags: CompressionCapabilities::FLAG_CHAINED,
                compression_algorithms: vec![compression_algorithm],
            };
            let compression_data = {
                use binrw::BinWrite;
                let mut c = std::io::Cursor::new(Vec::new());
                BinWrite::write(&compression_caps, &mut c)
                    .expect("compression negotiate context encodes");
                c.into_inner()
            };
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_COMPRESSION,
                data_length: compression_data.len() as u16,
                reserved: 0,
                data: compression_data,
            });
        }
        if selected_encryption_cipher != 0 {
            let encryption_caps = EncryptionCapabilities {
                cipher_count: 1,
                ciphers: vec![selected_encryption_cipher],
            };
            let encryption_data = {
                use binrw::BinWrite;
                let mut c = std::io::Cursor::new(Vec::new());
                BinWrite::write(&encryption_caps, &mut c)
                    .expect("encryption negotiate context encodes");
                c.into_inner()
            };
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_ENCRYPTION,
                data_length: encryption_data.len() as u16,
                reserved: 0,
                data: encryption_data,
            });
        }
        if smb311
            .as_ref()
            .is_some_and(|negotiation| negotiation.transport_security_accepted)
        {
            ctxs.push(transport_capabilities_context());
        }
        if let Err(e) = NegotiateContext::encode_list(&ctxs, &mut contexts_bytes) {
            tracing::error!(error = %e, "encode_list failed");
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        context_count = ctxs.len() as u16;

        // The contexts go after security buffer, 8-byte aligned.
        let post_security = security_buffer_offset as u32 + security_buffer_length as u32;
        // Round up to next multiple of 8 from the start of the SMB2 header.
        negotiate_context_offset = (post_security + 7) & !7;
    }

    let max_read_size = *conn.max_read_size.read().await;
    let max_write_size = *conn.max_write_size.read().await;
    let max_transact_size = max_read_size; // common practice

    let resp = NegotiateResponse {
        structure_size: 65,
        security_mode: negotiate_security_mode(server.config.require_signing),
        dialect_revision: chosen,
        negotiate_context_count_or_reserved: context_count,
        server_guid: *server.config.server_guid.as_bytes(),
        capabilities: negotiate_capabilities_for_dialect(Some(dialect), advertise_smb_encryption),
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time: now_filetime(),
        server_start_time: server.server_start_filetime,
        security_buffer_offset,
        security_buffer_length,
        negotiate_context_offset_or_reserved2: negotiate_context_offset,
        security_buffer: security_blob,
    };

    let mut body_out = Vec::new();
    if let Err(e) = resp.write_to(&mut body_out) {
        tracing::error!(error = %e, "encode NEGOTIATE response");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // Append padding to align contexts at `negotiate_context_offset`.
    if dialect == Dialect::Smb311 && context_count > 0 {
        let cur = 64 + body_out.len() as u32; // header + body so far
        if cur < negotiate_context_offset {
            let pad = (negotiate_context_offset - cur) as usize;
            body_out.extend(std::iter::repeat_n(0u8, pad));
        }
        body_out.extend_from_slice(&contexts_bytes);
    }
    info!(?dialect, "NEGOTIATE complete");
    let mut hr = HandlerResponse::ok(body_out);
    hr.skip_signing = true;
    hr
}

#[cfg(test)]
fn client_requested_posix_extensions(req: &NegotiateRequest, body: &[u8]) -> bool {
    negotiate_contexts(req, body)
        .ok()
        .is_some_and(|contexts| client_requested_posix_extensions_from_contexts(&contexts).is_ok())
}

fn validate_smb311_negotiate(
    req: &NegotiateRequest,
    body: &[u8],
    require_encryption: bool,
    transport_security_accepted: bool,
) -> Result<Smb311Negotiation, u32> {
    let contexts = negotiate_contexts(req, body)?;

    let preauth_count = contexts
        .iter()
        .filter(|ctx| ctx.context_type == NegotiateContext::TYPE_PREAUTH_INTEGRITY)
        .count();
    if preauth_count != 1 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let preauth = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_PREAUTH_INTEGRITY)
        .expect("preauth count checked");
    let preauth_caps =
        parse_preauth_capabilities(&preauth.data).ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
    if !preauth_caps
        .hash_algorithms
        .contains(&PreauthIntegrityCapabilities::HASH_SHA512)
    {
        return Err(ntstatus::STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
    }

    for singleton_type in [
        NegotiateContext::TYPE_ENCRYPTION,
        NegotiateContext::TYPE_COMPRESSION,
        NegotiateContext::TYPE_RDMA_TRANSFORM,
        NegotiateContext::TYPE_SIGNING,
        NegotiateContext::TYPE_TRANSPORT_CAPS,
        NegotiateContext::TYPE_POSIX,
    ] {
        let count = contexts
            .iter()
            .filter(|ctx| ctx.context_type == singleton_type)
            .count();
        if count > 1 {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }

    let selected_signing_algorithm = selected_signing_algorithm_from_contexts(&contexts)?;
    let posix_requested = client_requested_posix_extensions_from_contexts(&contexts)?;
    let net_name = requested_net_name_from_contexts(&contexts);
    let compression = requested_compression_from_contexts(&contexts)?;
    let selected_compression_algorithm = selected_compression_algorithm(
        compression
            .as_ref()
            .map(|(algorithms, chained)| (algorithms.as_slice(), *chained)),
    );
    let rdma_transform_ids = requested_rdma_transform_ids_from_contexts(&contexts)?;
    let encryption_ciphers = requested_encryption_ciphers_from_contexts(&contexts);
    let selected_encryption_cipher = selected_encryption_cipher(
        (!encryption_ciphers.is_empty()).then_some(encryption_ciphers.as_slice()),
        require_encryption,
    );
    requested_transport_security_from_contexts(&contexts)?;

    Ok(Smb311Negotiation {
        selected_signing_algorithm,
        posix_requested,
        net_name,
        compression_algorithms: compression
            .as_ref()
            .map(|(algorithms, _)| algorithms.clone())
            .unwrap_or_default(),
        compression_chained: compression.is_some_and(|(_, chained)| chained),
        selected_compression_algorithm,
        rdma_transform_ids,
        encryption_ciphers,
        selected_encryption_cipher,
        transport_security_accepted,
    })
}

fn selected_signing_algorithm_from_contexts(
    contexts: &[NegotiateContext],
) -> Result<Option<u16>, u32> {
    let signing = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_SIGNING);
    let Some(signing) = signing else {
        return Ok(None);
    };
    let caps =
        parse_signing_capabilities(&signing.data).ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
    if caps.signing_algorithm_count == 0 || caps.signing_algorithms.is_empty() {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if caps
        .signing_algorithms
        .contains(&SigningCapabilities::ALGORITHM_AES_GMAC)
    {
        Ok(Some(SigningCapabilities::ALGORITHM_AES_GMAC))
    } else if caps
        .signing_algorithms
        .contains(&SigningCapabilities::ALGORITHM_AES_CMAC)
    {
        Ok(Some(SigningCapabilities::ALGORITHM_AES_CMAC))
    } else if caps
        .signing_algorithms
        .contains(&SigningCapabilities::ALGORITHM_HMAC_SHA256)
    {
        Ok(Some(SigningCapabilities::ALGORITHM_HMAC_SHA256))
    } else {
        Ok(None)
    }
}

fn client_requested_posix_extensions_from_contexts(
    contexts: &[NegotiateContext],
) -> Result<bool, u32> {
    let posix = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_POSIX);
    let Some(posix) = posix else {
        return Ok(false);
    };
    if posix.data == NegotiateContext::POSIX_EXTENSIONS_GUID {
        Ok(true)
    } else {
        Err(ntstatus::STATUS_INVALID_PARAMETER)
    }
}

fn requested_net_name_from_contexts(contexts: &[NegotiateContext]) -> Option<String> {
    let net_name = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_NETNAME_NEGOTIATE)?;
    let decoded = utf16le_to_string(&net_name.data);
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

fn requested_compression_from_contexts(
    contexts: &[NegotiateContext],
) -> Result<Option<(Vec<u16>, bool)>, u32> {
    let compression = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_COMPRESSION);
    let Some(compression) = compression else {
        return Ok(None);
    };
    let caps = parse_compression_capabilities(&compression.data)
        .ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
    if caps.compression_algorithm_count == 0 || caps.compression_algorithms.is_empty() {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(Some((
        caps.compression_algorithms,
        caps.flags & CompressionCapabilities::FLAG_CHAINED != 0,
    )))
}

fn requested_rdma_transform_ids_from_contexts(
    contexts: &[NegotiateContext],
) -> Result<Vec<u16>, u32> {
    let rdma = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_RDMA_TRANSFORM);
    let Some(rdma) = rdma else {
        return Ok(Vec::new());
    };
    let Some(caps) = parse_rdma_transform_capabilities(&rdma.data) else {
        return Ok(Vec::new());
    };
    Ok(caps.rdma_transform_ids)
}

fn requested_encryption_ciphers_from_contexts(contexts: &[NegotiateContext]) -> Vec<u16> {
    let encryption = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_ENCRYPTION);
    let Some(encryption) = encryption else {
        return Vec::new();
    };
    parse_encryption_capabilities(&encryption.data)
        .map(|caps| caps.ciphers)
        .unwrap_or_default()
}

fn requested_transport_security_from_contexts(contexts: &[NegotiateContext]) -> Result<bool, u32> {
    let transport = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_TRANSPORT_CAPS);
    let Some(transport) = transport else {
        return Ok(false);
    };
    if transport.data.len() < 4 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let flags = u32::from_le_bytes(transport.data[0..4].try_into().expect("length checked"));
    Ok(flags & NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY != 0)
}

fn dialect_compatible_with_encryption(
    dialect: u16,
    require_encryption: bool,
    req: &NegotiateRequest,
    body: &[u8],
) -> bool {
    if !require_encryption {
        return true;
    }
    match dialect {
        0x0300 | 0x0302 => true,
        0x0311 => smb311_offers_encryption(req, body),
        _ => false,
    }
}

fn smb311_offers_encryption(req: &NegotiateRequest, body: &[u8]) -> bool {
    negotiate_contexts(req, body)
        .ok()
        .is_some_and(|contexts| !requested_encryption_ciphers_from_contexts(&contexts).is_empty())
}

fn smb311_requests_transport_security(req: &NegotiateRequest, body: &[u8]) -> bool {
    negotiate_contexts(req, body)
        .ok()
        .and_then(|contexts| requested_transport_security_from_contexts(&contexts).ok())
        .unwrap_or(false)
}

fn transport_capabilities_context() -> NegotiateContext {
    NegotiateContext {
        context_type: NegotiateContext::TYPE_TRANSPORT_CAPS,
        data_length: 4,
        reserved: 0,
        data: NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
            .to_le_bytes()
            .to_vec(),
    }
}

fn selected_encryption_cipher(ciphers: Option<&[u16]>, require_encryption: bool) -> u16 {
    if !require_encryption && ciphers.is_none() {
        return 0;
    }
    let Some(ciphers) = ciphers else {
        return 0;
    };
    for candidate in [
        EncryptionCapabilities::CIPHER_AES_256_GCM,
        EncryptionCapabilities::CIPHER_AES_128_GCM,
        EncryptionCapabilities::CIPHER_AES_256_CCM,
        EncryptionCapabilities::CIPHER_AES_128_CCM,
    ] {
        if ciphers.contains(&candidate) {
            return candidate;
        }
    }
    0
}

fn dialect_supports_smb_encryption(dialect: Dialect) -> bool {
    matches!(dialect, Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
}

fn selected_encryption_cipher_for_dialect(
    dialect: Dialect,
    ciphers: Option<&[u16]>,
    require_encryption: bool,
) -> u16 {
    match dialect {
        Dialect::Smb311 => selected_encryption_cipher(ciphers, require_encryption),
        Dialect::Smb300 | Dialect::Smb302 => EncryptionCapabilities::CIPHER_AES_128_CCM,
        _ => 0,
    }
}

fn selected_compression_algorithm(compression: Option<(&[u16], bool)>) -> u16 {
    let Some((algorithms, chained)) = compression else {
        return 0;
    };
    if algorithms.contains(&CompressionCapabilities::ALGORITHM_LZ77) {
        CompressionCapabilities::ALGORITHM_LZ77
    } else if chained && algorithms.contains(&CompressionCapabilities::ALGORITHM_PATTERN_V1) {
        CompressionCapabilities::ALGORITHM_PATTERN_V1
    } else {
        0
    }
}

fn negotiate_contexts(req: &NegotiateRequest, body: &[u8]) -> Result<Vec<NegotiateContext>, u32> {
    let context_offset = (req.negotiate_context_offset_or_client_start_time & 0xFFFF_FFFF) as usize;
    let context_count = ((req.negotiate_context_offset_or_client_start_time >> 32) & 0xFFFF) as u16;
    if context_count == 0 || context_offset < 64 {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let body_offset = context_offset - 64;
    if body_offset >= body.len() {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    NegotiateContext::parse_list(&body[body_offset..], context_count)
        .map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)
}

fn parse_preauth_capabilities(data: &[u8]) -> Option<PreauthIntegrityCapabilities> {
    use binrw::BinRead;
    let mut cursor = std::io::Cursor::new(data);
    PreauthIntegrityCapabilities::read(&mut cursor).ok()
}

fn parse_compression_capabilities(data: &[u8]) -> Option<CompressionCapabilities> {
    use binrw::BinRead;
    let mut cursor = std::io::Cursor::new(data);
    CompressionCapabilities::read(&mut cursor).ok()
}

fn parse_encryption_capabilities(data: &[u8]) -> Option<EncryptionCapabilities> {
    use binrw::BinRead;
    let mut cursor = std::io::Cursor::new(data);
    let caps = EncryptionCapabilities::read(&mut cursor).ok()?;
    if caps.cipher_count == 0 || caps.ciphers.is_empty() {
        None
    } else {
        Some(caps)
    }
}

fn parse_rdma_transform_capabilities(data: &[u8]) -> Option<RdmaTransformCapabilities> {
    use binrw::BinRead;
    let mut cursor = std::io::Cursor::new(data);
    let caps = RdmaTransformCapabilities::read(&mut cursor).ok()?;
    if caps.transform_count == 0 || caps.rdma_transform_ids.is_empty() {
        None
    } else {
        Some(caps)
    }
}

fn parse_signing_capabilities(data: &[u8]) -> Option<SigningCapabilities> {
    use binrw::BinRead;
    let mut cursor = std::io::Cursor::new(data);
    SigningCapabilities::read(&mut cursor).ok()
}

/// Build the SMB2 NEGOTIATE response sent in reply to an SMB1 multi-protocol
/// NEGOTIATE_REQUEST that listed an SMB2 dialect (MS-SMB2 §3.3.5.3.1).
///
/// We do NOT commit the connection dialect here — the client will follow up
/// with a real SMB2 NEGOTIATE which goes through [`handle`]. This response
/// only tells the client "yes, I speak SMB2; send me an SMB2 NEGOTIATE next".
pub async fn multi_protocol_response(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    chosen: u16,
) -> HandlerResponse {
    let security_blob = encode_init_response();
    let security_buffer_offset: u16 = 64 + 64;
    let security_buffer_length: u16 = security_blob.len() as u16;
    let max_read_size = *conn.max_read_size.read().await;
    let max_write_size = *conn.max_write_size.read().await;
    let max_transact_size = max_read_size;

    let resp = NegotiateResponse {
        structure_size: 65,
        security_mode: negotiate_security_mode(server.config.require_signing),
        dialect_revision: chosen,
        negotiate_context_count_or_reserved: 0,
        server_guid: *server.config.server_guid.as_bytes(),
        capabilities: 0,
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time: now_filetime(),
        server_start_time: server.server_start_filetime,
        security_buffer_offset,
        security_buffer_length,
        negotiate_context_offset_or_reserved2: 0,
        security_buffer: security_blob,
    };

    let mut body_out = Vec::new();
    if let Err(e) = resp.write_to(&mut body_out) {
        tracing::error!(error = %e, "encode multi-protocol NEGOTIATE response");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    info!(
        chosen = %format_args!("0x{chosen:04X}"),
        "SMB1 multi-protocol -> SMB2"
    );
    let mut hr = HandlerResponse::ok(body_out);
    hr.skip_signing = true;
    hr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preauth_context() -> NegotiateContext {
        use binrw::BinWrite;
        let preauth = PreauthIntegrityCapabilities {
            hash_algorithm_count: 1,
            salt_length: 0,
            hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
            salt: vec![],
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        BinWrite::write(&preauth, &mut cursor).unwrap();
        let data = cursor.into_inner();
        NegotiateContext {
            context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
            data_length: data.len() as u16,
            reserved: 0,
            data,
        }
    }

    fn negotiate_body_with_contexts(ctxs: &[NegotiateContext]) -> (NegotiateRequest, Vec<u8>) {
        negotiate_body(&[Dialect::Smb311.as_u16()], ctxs)
    }

    fn negotiate_body(dialects: &[u16], ctxs: &[NegotiateContext]) -> (NegotiateRequest, Vec<u8>) {
        let mut req = NegotiateRequest {
            structure_size: 36,
            dialect_count: dialects.len() as u16,
            security_mode: 1,
            reserved: 0,
            capabilities: 0,
            client_guid: [0xAB; 16],
            negotiate_context_offset_or_client_start_time: 0,
            dialects: dialects.to_vec(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        if !ctxs.is_empty() {
            let context_offset = 64 + ((body.len() + 7) & !7);
            req.negotiate_context_offset_or_client_start_time =
                context_offset as u64 | ((ctxs.len() as u64) << 32);
            body.clear();
            req.write_to(&mut body).unwrap();
            body.resize(context_offset - 64, 0);
            NegotiateContext::encode_list(ctxs, &mut body).unwrap();
        }
        (NegotiateRequest::parse(&body).unwrap(), body)
    }

    fn transport_context() -> NegotiateContext {
        transport_capabilities_context()
    }

    fn posix_context() -> NegotiateContext {
        NegotiateContext {
            context_type: NegotiateContext::TYPE_POSIX,
            data_length: NegotiateContext::POSIX_EXTENSIONS_GUID.len() as u16,
            reserved: 0,
            data: NegotiateContext::POSIX_EXTENSIONS_GUID.to_vec(),
        }
    }

    fn compression_context(chained: bool, algorithms: &[u16]) -> NegotiateContext {
        use binrw::BinWrite;
        let caps = CompressionCapabilities {
            compression_algorithm_count: algorithms.len() as u16,
            padding: 0,
            flags: if chained {
                CompressionCapabilities::FLAG_CHAINED
            } else {
                0
            },
            compression_algorithms: algorithms.to_vec(),
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        BinWrite::write(&caps, &mut cursor).unwrap();
        let data = cursor.into_inner();
        NegotiateContext {
            context_type: NegotiateContext::TYPE_COMPRESSION,
            data_length: data.len() as u16,
            reserved: 0,
            data,
        }
    }

    fn encryption_context(ciphers: &[u16]) -> NegotiateContext {
        use binrw::BinWrite;
        let caps = EncryptionCapabilities {
            cipher_count: ciphers.len() as u16,
            ciphers: ciphers.to_vec(),
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        BinWrite::write(&caps, &mut cursor).unwrap();
        let data = cursor.into_inner();
        NegotiateContext {
            context_type: NegotiateContext::TYPE_ENCRYPTION,
            data_length: data.len() as u16,
            reserved: 0,
            data,
        }
    }

    fn rdma_transform_context(transform_ids: &[u16]) -> NegotiateContext {
        use binrw::BinWrite;
        let caps = RdmaTransformCapabilities {
            transform_count: transform_ids.len() as u16,
            reserved1: 0,
            reserved2: 0,
            rdma_transform_ids: transform_ids.to_vec(),
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        BinWrite::write(&caps, &mut cursor).unwrap();
        let data = cursor.into_inner();
        NegotiateContext {
            context_type: NegotiateContext::TYPE_RDMA_TRANSFORM,
            data_length: data.len() as u16,
            reserved: 0,
            data,
        }
    }

    fn response_contexts(body: &[u8]) -> Vec<NegotiateContext> {
        let resp = NegotiateResponse::parse(body).expect("parse negotiate response");
        let context_offset = resp.negotiate_context_offset_or_reserved2 as usize - 64;
        NegotiateContext::parse_list(
            &body[context_offset..],
            resp.negotiate_context_count_or_reserved,
        )
        .expect("parse negotiate response contexts")
    }

    fn response_transport_security_accepted(body: &[u8]) -> bool {
        response_contexts(body)
            .iter()
            .find(|ctx| ctx.context_type == NegotiateContext::TYPE_TRANSPORT_CAPS)
            .is_some_and(|ctx| {
                ctx.data.len() >= 4
                    && u32::from_le_bytes(ctx.data[0..4].try_into().unwrap())
                        & NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
                        != 0
            })
    }

    #[test]
    fn detects_requested_posix_extensions_context() {
        let (req, body) = negotiate_body_with_contexts(&[posix_context()]);
        assert!(client_requested_posix_extensions(&req, &body));
    }

    #[test]
    fn rejects_malformed_posix_extensions_context() {
        let ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_POSIX,
            data_length: 3,
            reserved: 0,
            data: vec![1, 2, 3],
        };
        let (req, body) = negotiate_body_with_contexts(&[ctx]);
        assert!(!client_requested_posix_extensions(&req, &body));
    }

    #[test]
    fn records_request_only_netname_context() {
        let net_name = crate::utils::utf16le("quic.test");
        let ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_NETNAME_NEGOTIATE,
            data_length: net_name.len() as u16,
            reserved: 0,
            data: net_name,
        };
        let (req, body) = negotiate_body_with_contexts(&[preauth_context(), ctx]);
        let negotiation =
            validate_smb311_negotiate(&req, &body, false, false).expect("valid negotiate");
        assert_eq!(negotiation.net_name.as_deref(), Some("quic.test"));
    }

    #[test]
    fn rejects_malformed_transport_capabilities_context() {
        let ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_TRANSPORT_CAPS,
            data_length: 2,
            reserved: 0,
            data: vec![1, 0],
        };
        let (req, body) = negotiate_body_with_contexts(&[preauth_context(), ctx]);

        let err = validate_smb311_negotiate(&req, &body, false, false).expect_err("invalid");
        assert_eq!(err, ntstatus::STATUS_INVALID_PARAMETER);
    }

    #[tokio::test]
    async fn negotiate_records_posix_extensions_and_echoes_support() {
        let (_req, body) = negotiate_body_with_contexts(&[preauth_context(), posix_context()]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(*conn.posix_extensions.read().await);
        let posix = response_contexts(&resp.body)
            .into_iter()
            .find(|ctx| ctx.context_type == NegotiateContext::TYPE_POSIX)
            .expect("POSIX response context");
        assert_eq!(posix.data, NegotiateContext::POSIX_EXTENSIONS_GUID);
    }

    #[tokio::test]
    async fn negotiate_advertises_wan_friendly_transfer_sizes() {
        let (_req, body) = negotiate_body_with_contexts(&[preauth_context()]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let negotiate = NegotiateResponse::parse(&resp.body).expect("parse negotiate response");
        assert_eq!(negotiate.max_transact_size, 8 * 1024 * 1024);
        assert_eq!(negotiate.max_read_size, 8 * 1024 * 1024);
        assert_eq!(negotiate.max_write_size, 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn negotiate_prefers_highest_supported_client_dialect() {
        let (_req, body) = negotiate_body(
            &[
                Dialect::Smb202.as_u16(),
                Dialect::Smb302.as_u16(),
                Dialect::Smb300.as_u16(),
            ],
            &[],
        );
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let negotiate = NegotiateResponse::parse(&resp.body).expect("parse negotiate response");
        assert_eq!(negotiate.dialect_revision, Dialect::Smb302.as_u16());
        assert_eq!(*conn.dialect.read().await, Some(Dialect::Smb302));
    }

    #[tokio::test]
    async fn negotiate_records_unsupported_compression_without_advertising_it() {
        let (_req, body) = negotiate_body_with_contexts(&[
            preauth_context(),
            compression_context(true, &[CompressionCapabilities::ALGORITHM_LZ77_HUFFMAN]),
        ]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert_eq!(
            *conn.compression_algorithms.read().await,
            vec![CompressionCapabilities::ALGORITHM_LZ77_HUFFMAN]
        );
        assert!(*conn.compression_chained.read().await);
        assert_eq!(*conn.compression_algorithm.read().await, 0);
        assert!(
            !response_contexts(&resp.body)
                .iter()
                .any(|ctx| ctx.context_type == NegotiateContext::TYPE_COMPRESSION),
            "unsupported compression offers are recorded but not advertised"
        );
    }

    #[tokio::test]
    async fn negotiate_records_encryption_ciphers_without_enforcement() {
        let ciphers = vec![
            EncryptionCapabilities::CIPHER_AES_128_CCM,
            EncryptionCapabilities::CIPHER_AES_128_GCM,
            EncryptionCapabilities::CIPHER_AES_256_CCM,
            EncryptionCapabilities::CIPHER_AES_256_GCM,
        ];
        let (_req, body) =
            negotiate_body_with_contexts(&[preauth_context(), encryption_context(&ciphers)]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert_eq!(*conn.encryption_ciphers.read().await, ciphers);
        assert_eq!(
            *conn.encryption_cipher.read().await,
            EncryptionCapabilities::CIPHER_AES_256_GCM
        );
        let encryption = response_contexts(&resp.body)
            .into_iter()
            .find(|ctx| ctx.context_type == NegotiateContext::TYPE_ENCRYPTION)
            .and_then(|ctx| parse_encryption_capabilities(&ctx.data))
            .expect("optional encryption offer is advertised");
        assert_eq!(
            encryption.ciphers,
            vec![EncryptionCapabilities::CIPHER_AES_256_GCM]
        );
    }

    #[tokio::test]
    async fn negotiate_records_rdma_transforms_without_advertising_them() {
        let (_req, body) = negotiate_body_with_contexts(&[
            preauth_context(),
            rdma_transform_context(&[
                RdmaTransformCapabilities::TRANSFORM_ENCRYPTION,
                RdmaTransformCapabilities::TRANSFORM_SIGNING,
            ]),
        ]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert_eq!(
            *conn.rdma_transform_ids.read().await,
            vec![
                RdmaTransformCapabilities::TRANSFORM_ENCRYPTION,
                RdmaTransformCapabilities::TRANSFORM_SIGNING,
            ]
        );
        assert!(
            !response_contexts(&resp.body)
                .iter()
                .any(|ctx| ctx.context_type == NegotiateContext::TYPE_RDMA_TRANSFORM),
            "TCP/QUIC server records RDMA transform offers but must not advertise RDMA"
        );
    }

    #[tokio::test]
    async fn negotiate_disable_compression_ignores_recorded_offer_state() {
        let (_req, body) = negotiate_body_with_contexts(&[
            preauth_context(),
            compression_context(
                true,
                &[
                    CompressionCapabilities::ALGORITHM_PATTERN_V1,
                    CompressionCapabilities::ALGORITHM_LZ77,
                ],
            ),
        ]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .disable_compression(true)
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(conn.compression_algorithms.read().await.is_empty());
        assert!(!*conn.compression_chained.read().await);
        assert_eq!(*conn.compression_algorithm.read().await, 0);
        assert!(
            !response_contexts(&resp.body)
                .iter()
                .any(|ctx| ctx.context_type == NegotiateContext::TYPE_COMPRESSION),
            "disabled compression must not be advertised"
        );
    }

    #[tokio::test]
    async fn negotiate_records_client_signing_required_bit() {
        let (_req, mut body) = negotiate_body_with_contexts(&[preauth_context()]);
        body[4..6]
            .copy_from_slice(&(NEGOTIATE_SECURITY_MODE | NEGOTIATE_SIGNING_REQUIRED).to_le_bytes());
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(*conn.client_requires_signing.read().await);
    }

    #[tokio::test]
    async fn secure_transport_accepts_transport_security_without_smb_encryption() {
        let (_req, body) = negotiate_body_with_contexts(&[preauth_context(), transport_context()]);
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .encrypt_data(true)
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new_with_transport_security(
            server.config.server_guid,
            server.config.max_read_size,
            server.config.max_write_size,
            server.config.max_credits,
            true,
        ));

        let resp = handle(&server, &conn, &Smb2Header::default(), &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(*conn.transport_security.read().await);
        assert_eq!(*conn.encryption_cipher.read().await, 0);
        let negotiate = NegotiateResponse::parse(&resp.body).expect("parse negotiate response");
        assert_eq!(negotiate.dialect_revision, Dialect::Smb311.as_u16());
        assert_eq!(negotiate.capabilities & CAP_ENCRYPTION, 0);
        assert!(response_transport_security_accepted(&resp.body));
    }

    #[test]
    fn selected_encryption_cipher_uses_gosmb_preference_order_when_required() {
        let ciphers = [
            EncryptionCapabilities::CIPHER_AES_128_CCM,
            EncryptionCapabilities::CIPHER_AES_128_GCM,
            EncryptionCapabilities::CIPHER_AES_256_CCM,
            EncryptionCapabilities::CIPHER_AES_256_GCM,
        ];
        assert_eq!(
            selected_encryption_cipher(Some(&ciphers), false),
            EncryptionCapabilities::CIPHER_AES_256_GCM
        );
        assert_eq!(selected_encryption_cipher(None, false), 0);
        assert_eq!(
            selected_encryption_cipher(Some(&ciphers), true),
            EncryptionCapabilities::CIPHER_AES_256_GCM
        );
        assert_eq!(
            selected_encryption_cipher(
                Some(&[
                    EncryptionCapabilities::CIPHER_AES_128_CCM,
                    EncryptionCapabilities::CIPHER_AES_128_GCM,
                ]),
                true,
            ),
            EncryptionCapabilities::CIPHER_AES_128_GCM
        );
    }
}
