use std::cmp::Ordering;

const RPC_VERSION: u8 = 5;
const RPC_VERSION_MINOR: u8 = 0;
const RPC_TYPE_REQUEST: u8 = 0;
const RPC_TYPE_RESPONSE: u8 = 2;
const RPC_TYPE_FAULT: u8 = 3;
const RPC_TYPE_BIND: u8 = 11;
const RPC_TYPE_BIND_ACK: u8 = 12;
const RPC_FLAG_FIRST: u8 = 0x01;
const RPC_FLAG_LAST: u8 = 0x02;
const SRVSVC_NET_SHARE_ENUM_ALL_OPNUM: u16 = 15;
const NDR_SYNTAX_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RpcShare {
    pub name: String,
    pub share_type: u32,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcRequest {
    packet_type: u8,
    call_id: u32,
    context_id: u16,
    opnum: u16,
}

pub(crate) fn handle_srvsvc_rpc(input: &[u8], shares: &[RpcShare]) -> Option<Vec<u8>> {
    handle_pipe_rpc("srvsvc", input, shares)
}

pub(crate) fn handle_lsarpc_rpc(input: &[u8]) -> Option<Vec<u8>> {
    handle_pipe_rpc("lsarpc", input, &[])
}

fn handle_pipe_rpc(pipe: &str, input: &[u8], shares: &[RpcShare]) -> Option<Vec<u8>> {
    let req = parse_rpc_request(input)?;
    match req.packet_type {
        RPC_TYPE_BIND => Some(encode_rpc_bind_ack(req.call_id, pipe)),
        RPC_TYPE_REQUEST => {
            if !pipe.eq_ignore_ascii_case("srvsvc") || req.opnum != SRVSVC_NET_SHARE_ENUM_ALL_OPNUM
            {
                return Some(encode_rpc_fault(req.call_id, req.context_id, 0x0000_06d1));
            }
            Some(encode_rpc_response(
                req.call_id,
                req.context_id,
                &encode_net_share_enum_all_stub(shares),
            ))
        }
        _ => None,
    }
}

fn parse_rpc_request(input: &[u8]) -> Option<RpcRequest> {
    if input.len() < 16 || input[0] != RPC_VERSION {
        return None;
    }
    let frag_len = u16::from_le_bytes(input[8..10].try_into().ok()?) as usize;
    let input = if frag_len > 0 && frag_len <= input.len() {
        &input[..frag_len]
    } else {
        input
    };
    let packet_type = input[2];
    let call_id = u32::from_le_bytes(input[12..16].try_into().ok()?);
    match packet_type {
        RPC_TYPE_BIND => Some(RpcRequest {
            packet_type,
            call_id,
            context_id: 0,
            opnum: 0,
        }),
        RPC_TYPE_REQUEST => {
            if input.len() < 24 {
                return None;
            }
            Some(RpcRequest {
                packet_type,
                call_id,
                context_id: u16::from_le_bytes(input[20..22].try_into().ok()?),
                opnum: u16::from_le_bytes(input[22..24].try_into().ok()?),
            })
        }
        _ => None,
    }
}

fn encode_rpc_bind_ack(call_id: u32, pipe: &str) -> Vec<u8> {
    let secondary_addr = format!(r"\PIPE\{pipe}").into_bytes();
    let result_off = round_up(26 + secondary_addr.len() + 1, 4);
    let body_len = result_off - 16 + 28;
    let mut out = vec![0u8; 16 + body_len];
    encode_rpc_header(&mut out, RPC_TYPE_BIND_ACK, call_id);
    out[16..18].copy_from_slice(&4280u16.to_le_bytes());
    out[18..20].copy_from_slice(&4280u16.to_le_bytes());
    out[20..24].copy_from_slice(&0x1000u32.to_le_bytes());
    out[24..26].copy_from_slice(&((secondary_addr.len() + 1) as u16).to_le_bytes());
    out[26..26 + secondary_addr.len()].copy_from_slice(&secondary_addr);
    let off = result_off;
    out[off] = 1;
    out[off + 4..off + 6].copy_from_slice(&0u16.to_le_bytes());
    out[off + 6..off + 8].copy_from_slice(&0u16.to_le_bytes());
    out[off + 8..off + 24].copy_from_slice(&NDR_SYNTAX_UUID);
    out[off + 24..off + 28].copy_from_slice(&2u32.to_le_bytes());
    let len = out.len() as u16;
    out[8..10].copy_from_slice(&len.to_le_bytes());
    out
}

fn encode_rpc_response(call_id: u32, context_id: u16, stub: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 24 + stub.len()];
    encode_rpc_header(&mut out, RPC_TYPE_RESPONSE, call_id);
    out[16..20].copy_from_slice(&(stub.len() as u32).to_le_bytes());
    out[20..22].copy_from_slice(&context_id.to_le_bytes());
    out[24..].copy_from_slice(stub);
    out
}

fn encode_rpc_fault(call_id: u32, context_id: u16, status: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    encode_rpc_header(&mut out, RPC_TYPE_FAULT, call_id);
    out[16..20].copy_from_slice(&8u32.to_le_bytes());
    out[20..22].copy_from_slice(&context_id.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out
}

fn encode_rpc_header(out: &mut [u8], packet_type: u8, call_id: u32) {
    out[0] = RPC_VERSION;
    out[1] = RPC_VERSION_MINOR;
    out[2] = packet_type;
    out[3] = RPC_FLAG_FIRST | RPC_FLAG_LAST;
    out[4] = 0x10;
    let len = out.len() as u16;
    out[8..10].copy_from_slice(&len.to_le_bytes());
    out[12..16].copy_from_slice(&call_id.to_le_bytes());
}

fn encode_net_share_enum_all_stub(shares: &[RpcShare]) -> Vec<u8> {
    let mut shares = shares.to_vec();
    shares.sort_by(|a, b| {
        let a = a.name.to_ascii_lowercase();
        let b = b.name.to_ascii_lowercase();
        a.cmp(&b).then(Ordering::Equal)
    });

    let count = shares.len();
    let mut out = vec![0u8; 24 + count * 12];
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&1u32.to_le_bytes());
    out[8..12].copy_from_slice(&0x0002_0000u32.to_le_bytes());
    out[12..16].copy_from_slice(&(count as u32).to_le_bytes());
    if count > 0 {
        out[16..20].copy_from_slice(&0x0002_0004u32.to_le_bytes());
    }
    out[20..24].copy_from_slice(&(count as u32).to_le_bytes());

    let mut next_ref = 0x0002_0008u32;
    for (idx, share) in shares.iter().enumerate() {
        let off = 24 + idx * 12;
        out[off..off + 4].copy_from_slice(&next_ref.to_le_bytes());
        next_ref += 4;
        out[off + 4..off + 8].copy_from_slice(&share.share_type.to_le_bytes());
        out[off + 8..off + 12].copy_from_slice(&next_ref.to_le_bytes());
        next_ref += 4;
    }
    for share in &shares {
        append_ndr_string(&mut out, &share.name);
        append_ndr_string(&mut out, &share.comment);
    }
    append_u32(&mut out, count as u32);
    append_u32(&mut out, 0);
    append_u32(&mut out, 0);
    out
}

fn append_ndr_string(out: &mut Vec<u8>, s: &str) {
    let encoded: Vec<u16> = format!("{s}\0").encode_utf16().collect();
    append_u32(out, encoded.len() as u32);
    append_u32(out, 0);
    append_u32(out, encoded.len() as u32);
    for unit in encoded {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

const fn round_up(n: usize, align: usize) -> usize {
    if align == 0 {
        n
    } else {
        (n + align - 1) & !(align - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc_bind_request(call_id: u32) -> Vec<u8> {
        let mut req = vec![0u8; 72];
        req[0] = RPC_VERSION;
        req[1] = RPC_VERSION_MINOR;
        req[2] = RPC_TYPE_BIND;
        req[3] = RPC_FLAG_FIRST | RPC_FLAG_LAST;
        req[4] = 0x10;
        let len = req.len() as u16;
        req[8..10].copy_from_slice(&len.to_le_bytes());
        req[12..16].copy_from_slice(&call_id.to_le_bytes());
        req
    }

    #[test]
    fn srvsvc_bind_ack_preserves_call_id() {
        let got = handle_srvsvc_rpc(&rpc_bind_request(7), &[]).expect("bind ack");

        assert_eq!(got[2], RPC_TYPE_BIND_ACK);
        assert_eq!(u32::from_le_bytes(got[12..16].try_into().unwrap()), 7);
        assert_bind_ack_result(&got);
    }

    #[test]
    fn lsarpc_bind_ack_advertises_pipe_name() {
        let got = handle_lsarpc_rpc(&rpc_bind_request(9)).expect("bind ack");

        assert_eq!(got[2], RPC_TYPE_BIND_ACK);
        assert_eq!(u32::from_le_bytes(got[12..16].try_into().unwrap()), 9);
        assert!(
            got.windows(br"\PIPE\lsarpc".len())
                .any(|w| w == br"\PIPE\lsarpc")
        );
        assert_bind_ack_result(&got);
    }

    #[test]
    fn srvsvc_share_enum_returns_share_records() {
        let mut req = vec![0u8; 24];
        req[0] = RPC_VERSION;
        req[1] = RPC_VERSION_MINOR;
        req[2] = RPC_TYPE_REQUEST;
        req[3] = RPC_FLAG_FIRST | RPC_FLAG_LAST;
        req[4] = 0x10;
        let len = req.len() as u16;
        req[8..10].copy_from_slice(&len.to_le_bytes());
        req[12..16].copy_from_slice(&8u32.to_le_bytes());
        req[22..24].copy_from_slice(&SRVSVC_NET_SHARE_ENUM_ALL_OPNUM.to_le_bytes());

        let got = handle_srvsvc_rpc(
            &req,
            &[RpcShare {
                name: "VIRTUAL".to_string(),
                share_type: 0,
                comment: String::new(),
            }],
        )
        .expect("response");

        assert_eq!(got[2], RPC_TYPE_RESPONSE);
        let stub = &got[24..];
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 1);
    }

    fn assert_bind_ack_result(got: &[u8]) {
        let secondary_addr_len = u16::from_le_bytes(got[24..26].try_into().unwrap()) as usize;
        let result_off = round_up(26 + secondary_addr_len, 4);
        assert_eq!(got[result_off], 1);
        assert_eq!(
            u16::from_le_bytes(got[result_off + 4..result_off + 6].try_into().unwrap()),
            0
        );
        assert_eq!(
            &got[result_off + 8..result_off + 24],
            NDR_SYNTAX_UUID.as_slice()
        );
        assert_eq!(
            u32::from_le_bytes(got[result_off + 24..result_off + 28].try_into().unwrap()),
            2
        );
    }
}
