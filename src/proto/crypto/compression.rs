//! SMB 3.1.1 compression transform helpers.
//!
//! Supports the algorithms GoSMB negotiates today: XPRESS LZ77 and
//! Pattern_V1, including chained transform frames.

use thiserror::Error;

use crate::proto::messages::CompressionCapabilities;

pub const COMPRESSION_MAGIC: [u8; 4] = [0xFC, b'S', b'M', b'B'];
pub const COMPRESSION_TRANSFORM_HEADER_SIZE: usize = 16;
const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
const COMPRESSION_FLAG_CHAINED: u16 = 0x0001;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CompressionError {
    #[error("unsupported SMB compression algorithm")]
    Unsupported,
    #[error("invalid SMB compression transform")]
    Invalid,
}

pub type CompressionResult<T> = Result<T, CompressionError>;

pub fn is_compression_transform(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == COMPRESSION_MAGIC
}

pub fn decompress_transform(
    frame: &[u8],
    allowed: &[u16],
    max_original: u32,
) -> CompressionResult<Vec<u8>> {
    if frame.len() < COMPRESSION_TRANSFORM_HEADER_SIZE || frame[..4] != COMPRESSION_MAGIC {
        return Err(CompressionError::Invalid);
    }
    let original_size = read_u32(frame, 4)? as usize;
    if original_size == 0 || (max_original != 0 && original_size > max_original as usize) {
        return Err(CompressionError::Invalid);
    }
    let algorithm = read_u16(frame, 8)?;
    let flags = read_u16(frame, 10)?;
    let offset = read_u32(frame, 12)? as usize;
    match flags {
        0 => {
            if !compression_allowed(algorithm, allowed) {
                return Err(CompressionError::Unsupported);
            }
            let prefix_end = COMPRESSION_TRANSFORM_HEADER_SIZE
                .checked_add(offset)
                .ok_or(CompressionError::Invalid)?;
            if prefix_end > frame.len() {
                return Err(CompressionError::Invalid);
            }
            let prefix = &frame[COMPRESSION_TRANSFORM_HEADER_SIZE..prefix_end];
            let payload = decompress_payload(algorithm, &frame[prefix_end..], original_size)?;
            let mut out = Vec::with_capacity(prefix.len() + payload.len());
            out.extend_from_slice(prefix);
            out.extend_from_slice(&payload);
            validate_plain(&out, original_size)?;
            Ok(out)
        }
        COMPRESSION_FLAG_CHAINED => {
            let out = decompress_chained(&frame[8..], allowed, original_size)?;
            validate_plain(&out, original_size)?;
            Ok(out)
        }
        _ => Err(CompressionError::Invalid),
    }
}

pub fn compress_lz77_transform(plain: &[u8]) -> Option<Vec<u8>> {
    if plain.len() <= COMPRESSION_TRANSFORM_HEADER_SIZE || plain[..4] != SMB2_MAGIC {
        return None;
    }
    let compressed = compress_xpress_lz77(plain);
    if compressed.len() >= plain.len() {
        return None;
    }
    let mut out = Vec::with_capacity(COMPRESSION_TRANSFORM_HEADER_SIZE + compressed.len());
    out.extend_from_slice(&COMPRESSION_MAGIC);
    out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    out.extend_from_slice(&CompressionCapabilities::ALGORITHM_LZ77.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&compressed);
    Some(out)
}

pub fn compress_pattern_transform(plain: &[u8]) -> Option<Vec<u8>> {
    if plain.len() <= 32 || plain[..4] != SMB2_MAGIC {
        return None;
    }
    let pattern = *plain.last()?;
    let mut start = plain.len() - 1;
    while start > 0 && plain[start - 1] == pattern {
        start -= 1;
    }
    let repetitions = plain.len() - start;
    if repetitions <= 32 {
        return None;
    }
    let prefix = &plain[..start];
    let compressed_size = if prefix.is_empty() {
        8 + 8 + 8
    } else {
        8 + 8 + prefix.len() + 8 + 8
    };
    if compressed_size >= plain.len() {
        return None;
    }

    let mut out = Vec::with_capacity(compressed_size);
    out.extend_from_slice(&COMPRESSION_MAGIC);
    out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    if !prefix.is_empty() {
        out.extend_from_slice(&CompressionCapabilities::ALGORITHM_NONE.to_le_bytes());
        out.extend_from_slice(&COMPRESSION_FLAG_CHAINED.to_le_bytes());
        out.extend_from_slice(&(prefix.len() as u32).to_le_bytes());
        out.extend_from_slice(prefix);
    }
    out.extend_from_slice(&CompressionCapabilities::ALGORITHM_PATTERN_V1.to_le_bytes());
    out.extend_from_slice(
        &if prefix.is_empty() {
            COMPRESSION_FLAG_CHAINED
        } else {
            0
        }
        .to_le_bytes(),
    );
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&[pattern, 0, 0, 0]);
    out.extend_from_slice(&(repetitions as u32).to_le_bytes());
    Some(out)
}

pub fn compress_response(plain: &[u8], algorithm: u16) -> Option<Vec<u8>> {
    match algorithm {
        CompressionCapabilities::ALGORITHM_LZ77 => compress_lz77_transform(plain),
        CompressionCapabilities::ALGORITHM_PATTERN_V1 => compress_pattern_transform(plain),
        _ => None,
    }
}

pub fn decompress_xpress_lz77(input: &[u8], max_output: usize) -> CompressionResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut in_off = 0usize;
    let mut nibble_off: Option<usize> = None;
    let mut flags = 0u32;
    let mut flag_count = 0u8;

    while in_off < input.len() {
        if flag_count == 0 {
            if in_off + 4 > input.len() {
                return Err(CompressionError::Invalid);
            }
            flags = u32::from_le_bytes(input[in_off..in_off + 4].try_into().unwrap());
            in_off += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        if flags & (1 << u32::from(flag_count)) == 0 {
            if in_off >= input.len() || out.len() + 1 > max_output {
                return Err(CompressionError::Invalid);
            }
            out.push(input[in_off]);
            in_off += 1;
            continue;
        }

        if in_off + 2 > input.len() {
            return Err(CompressionError::Invalid);
        }
        let token = u16::from_le_bytes(input[in_off..in_off + 2].try_into().unwrap()) as usize;
        in_off += 2;
        let offset = token / 8 + 1;
        let mut length = token % 8;
        if length == 7 {
            if let Some(nibble) = nibble_off.take() {
                if nibble >= input.len() {
                    return Err(CompressionError::Invalid);
                }
                length = usize::from(input[nibble] >> 4);
            } else {
                if in_off >= input.len() {
                    return Err(CompressionError::Invalid);
                }
                length = usize::from(input[in_off] & 0x0F);
                nibble_off = Some(in_off);
                in_off += 1;
            }
            if length == 15 {
                if in_off >= input.len() {
                    return Err(CompressionError::Invalid);
                }
                length = usize::from(input[in_off]);
                in_off += 1;
                if length == 255 {
                    if in_off + 2 > input.len() {
                        return Err(CompressionError::Invalid);
                    }
                    length =
                        u16::from_le_bytes(input[in_off..in_off + 2].try_into().unwrap()) as usize;
                    in_off += 2;
                    if length == 0 {
                        if in_off + 4 > input.len() {
                            return Err(CompressionError::Invalid);
                        }
                        length = u32::from_le_bytes(input[in_off..in_off + 4].try_into().unwrap())
                            as usize;
                        in_off += 4;
                    }
                    if length < 22 {
                        return Err(CompressionError::Invalid);
                    }
                    length -= 22;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        if offset > out.len() || out.len() + length > max_output {
            return Err(CompressionError::Invalid);
        }
        for _ in 0..length {
            let b = out[out.len() - offset];
            out.push(b);
        }
    }
    if out.len() != max_output {
        return Err(CompressionError::Invalid);
    }
    Ok(out)
}

pub fn compress_xpress_lz77(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0, 0, 0, 0];
    let mut flag_off = 0usize;
    let mut flags = 0u32;
    let mut flag_count = 0u8;
    let mut nibble_off: Option<usize> = None;
    let mut in_off = 0usize;

    while in_off < input.len() {
        let (offset, length) = find_xpress_match(input, in_off);
        if length < 3 {
            out.push(input[in_off]);
            in_off += 1;
            flags <<= 1;
        } else {
            let encoded_len = length - 3;
            let encoded_off = offset - 1;
            let token_len = encoded_len.min(7);
            let token = ((encoded_off << 3) | token_len) as u16;
            out.extend_from_slice(&token.to_le_bytes());
            if encoded_len >= 7 {
                let extra = encoded_len - 7;
                if let Some(nibble) = nibble_off.take() {
                    if extra < 15 {
                        out[nibble] |= (extra as u8) << 4;
                    } else {
                        out[nibble] |= 15 << 4;
                        append_xpress_long_length(&mut out, extra - 15, length);
                    }
                } else {
                    nibble_off = Some(out.len());
                    if extra < 15 {
                        out.push(extra as u8);
                    } else {
                        out.push(15);
                        append_xpress_long_length(&mut out, extra - 15, length);
                    }
                }
            }
            in_off += length;
            flags = (flags << 1) | 1;
        }
        flag_count += 1;
        if flag_count == 32 {
            out[flag_off..flag_off + 4].copy_from_slice(&flags.to_le_bytes());
            flag_off = out.len();
            out.extend_from_slice(&[0, 0, 0, 0]);
            flags = 0;
            flag_count = 0;
        }
    }
    if flag_count == 0 {
        out.truncate(out.len() - 4);
        return out;
    }
    flags <<= u32::from(32 - flag_count);
    flags |= (1u32 << u32::from(32 - flag_count)) - 1;
    out[flag_off..flag_off + 4].copy_from_slice(&flags.to_le_bytes());
    out
}

fn decompress_chained(
    data: &[u8],
    allowed: &[u16],
    original_size: usize,
) -> CompressionResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        if off + 8 > data.len() {
            return Err(CompressionError::Invalid);
        }
        let algorithm = read_u16(data, off)?;
        let flags = read_u16(data, off + 2)?;
        let length = read_u32(data, off + 4)? as usize;
        if off == 0 {
            if flags & COMPRESSION_FLAG_CHAINED == 0 {
                return Err(CompressionError::Invalid);
            }
        } else if flags != 0 {
            return Err(CompressionError::Invalid);
        }
        off += 8;
        let end = off.checked_add(length).ok_or(CompressionError::Invalid)?;
        if end > data.len() {
            return Err(CompressionError::Invalid);
        }
        let payload = &data[off..end];
        off = end;
        if algorithm != CompressionCapabilities::ALGORITHM_NONE
            && !compression_allowed(algorithm, allowed)
        {
            return Err(CompressionError::Unsupported);
        }
        let expected = original_size
            .checked_sub(out.len())
            .ok_or(CompressionError::Invalid)?;
        let part = decompress_chained_payload(algorithm, payload, expected)?;
        out.extend_from_slice(&part);
        if out.len() > original_size {
            return Err(CompressionError::Invalid);
        }
    }
    Ok(out)
}

fn decompress_chained_payload(
    algorithm: u16,
    payload: &[u8],
    expected_max: usize,
) -> CompressionResult<Vec<u8>> {
    if algorithm != CompressionCapabilities::ALGORITHM_LZ77 {
        return decompress_payload(algorithm, payload, expected_max);
    }
    if payload.len() < 4 {
        return Err(CompressionError::Invalid);
    }
    let original_size = read_u32(payload, 0)? as usize;
    if original_size > expected_max {
        return Err(CompressionError::Invalid);
    }
    decompress_xpress_lz77(&payload[4..], original_size)
}

fn decompress_payload(
    algorithm: u16,
    payload: &[u8],
    expected_max: usize,
) -> CompressionResult<Vec<u8>> {
    match algorithm {
        CompressionCapabilities::ALGORITHM_NONE => Ok(payload.to_vec()),
        CompressionCapabilities::ALGORITHM_LZ77 => decompress_xpress_lz77(payload, expected_max),
        CompressionCapabilities::ALGORITHM_PATTERN_V1 => {
            if payload.len() != 8 {
                return Err(CompressionError::Invalid);
            }
            let repetitions = read_u32(payload, 4)? as usize;
            if repetitions > expected_max {
                return Err(CompressionError::Invalid);
            }
            Ok(vec![payload[0]; repetitions])
        }
        _ => Err(CompressionError::Unsupported),
    }
}

fn validate_plain(out: &[u8], original_size: usize) -> CompressionResult<()> {
    if out.len() != original_size || out.len() < 4 || out[..4] != SMB2_MAGIC {
        return Err(CompressionError::Invalid);
    }
    Ok(())
}

fn compression_allowed(algorithm: u16, allowed: &[u16]) -> bool {
    allowed.contains(&algorithm)
}

fn find_xpress_match(input: &[u8], pos: usize) -> (usize, usize) {
    const MAX_WINDOW: usize = 8192;
    const MAX_MATCH: usize = 8192;
    let max_offset = pos.min(MAX_WINDOW);
    let max_length = (input.len() - pos).min(MAX_MATCH);
    if max_length < 3 {
        return (0, 0);
    }
    let mut best_offset = 0usize;
    let mut best_length = 0usize;
    for offset in 1..=max_offset {
        let mut length = 0usize;
        let base = pos - offset;
        while length < max_length && input[base + length] == input[pos + length] {
            length += 1;
        }
        if length > best_length {
            best_length = length;
            best_offset = offset;
            if best_length == max_length {
                break;
            }
        }
    }
    if best_length < 3 {
        (0, 0)
    } else {
        (best_offset, best_length)
    }
}

fn append_xpress_long_length(out: &mut Vec<u8>, extra: usize, length: usize) {
    if extra < 255 {
        out.push(extra as u8);
        return;
    }
    out.push(255);
    let stored_length = length - 3;
    if stored_length < (1 << 16) {
        out.extend_from_slice(&(stored_length as u16).to_le_bytes());
    } else {
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(stored_length as u32).to_le_bytes());
    }
}

fn read_u16(data: &[u8], off: usize) -> CompressionResult<u16> {
    let end = off.checked_add(2).ok_or(CompressionError::Invalid)?;
    let bytes = data.get(off..end).ok_or(CompressionError::Invalid)?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], off: usize) -> CompressionResult<u32> {
    let end = off.checked_add(4).ok_or(CompressionError::Invalid)?;
    let bytes = data.get(off..end).ok_or(CompressionError::Invalid)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_xpress_lz77_known_literal_vector() {
        let compressed = [
            0x3f, 0x00, 0x00, 0x00, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j',
            b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x',
            b'y', b'z',
        ];
        let got = decompress_xpress_lz77(&compressed, 26).expect("decompress");
        assert_eq!(got, b"abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn compress_decompress_xpress_lz77_round_trip() {
        let plain = b"The quick brown fox jumps over the lazy dog. ".repeat(64);
        let compressed = compress_xpress_lz77(&plain);
        assert!(compressed.len() < plain.len());
        let got = decompress_xpress_lz77(&compressed, plain.len()).expect("decompress");
        assert_eq!(got, plain);
    }

    #[test]
    fn decompress_xpress_lz77_rejects_oversize() {
        let plain = b"abcabcabc".repeat(16);
        let compressed = compress_xpress_lz77(&plain);
        assert!(decompress_xpress_lz77(&compressed, plain.len() - 1).is_err());
    }

    #[test]
    fn compress_decompress_chained_pattern_transform() {
        let mut plain = SMB2_MAGIC.to_vec();
        plain.extend(std::iter::repeat_n(0xFE, 128));
        let compressed = compress_pattern_transform(&plain).expect("compressed");
        assert_eq!(&compressed[..4], &COMPRESSION_MAGIC);
        assert_eq!(
            u16::from_le_bytes(compressed[8..10].try_into().unwrap()),
            CompressionCapabilities::ALGORITHM_NONE
        );
        assert_eq!(
            u16::from_le_bytes(compressed[20..22].try_into().unwrap()),
            CompressionCapabilities::ALGORITHM_PATTERN_V1
        );
        assert_eq!(
            u32::from_le_bytes(compressed[24..28].try_into().unwrap()),
            8
        );
        let got = decompress_transform(
            &compressed,
            &[CompressionCapabilities::ALGORITHM_PATTERN_V1],
            1 << 20,
        )
        .expect("decompress");
        assert_eq!(got, plain);
    }

    #[test]
    fn decompress_chained_none_and_pattern() {
        let mut plain = SMB2_MAGIC.to_vec();
        plain.extend(std::iter::repeat_n(0x20, 64));
        let mut frame = Vec::new();
        frame.extend_from_slice(&COMPRESSION_MAGIC);
        frame.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        frame.extend_from_slice(&CompressionCapabilities::ALGORITHM_NONE.to_le_bytes());
        frame.extend_from_slice(&COMPRESSION_FLAG_CHAINED.to_le_bytes());
        frame.extend_from_slice(&4u32.to_le_bytes());
        frame.extend_from_slice(&SMB2_MAGIC);
        frame.extend_from_slice(&CompressionCapabilities::ALGORITHM_PATTERN_V1.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&8u32.to_le_bytes());
        frame.extend_from_slice(&[0x20, 0, 0, 0]);
        frame.extend_from_slice(&64u32.to_le_bytes());
        let got = decompress_transform(
            &frame,
            &[CompressionCapabilities::ALGORITHM_PATTERN_V1],
            1 << 20,
        )
        .expect("decompress");
        assert_eq!(got, plain);
    }

    #[test]
    fn compress_decompress_lz77_transform() {
        let mut plain = SMB2_MAGIC.to_vec();
        plain.extend(b"hello hello hello hello ".repeat(64));
        let compressed = compress_lz77_transform(&plain).expect("compressed");
        assert_eq!(&compressed[..4], &COMPRESSION_MAGIC);
        assert_eq!(
            u16::from_le_bytes(compressed[8..10].try_into().unwrap()),
            CompressionCapabilities::ALGORITHM_LZ77
        );
        let got = decompress_transform(
            &compressed,
            &[CompressionCapabilities::ALGORITHM_LZ77],
            1 << 20,
        )
        .expect("decompress");
        assert_eq!(got, plain);
    }

    #[test]
    fn decompress_chained_lz77_payload() {
        let mut plain = SMB2_MAGIC.to_vec();
        plain.extend(b"abcabcabcabc".repeat(20));
        let compressed = compress_xpress_lz77(&plain);
        let mut frame = Vec::new();
        frame.extend_from_slice(&COMPRESSION_MAGIC);
        frame.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        frame.extend_from_slice(&CompressionCapabilities::ALGORITHM_LZ77.to_le_bytes());
        frame.extend_from_slice(&COMPRESSION_FLAG_CHAINED.to_le_bytes());
        frame.extend_from_slice(&((4 + compressed.len()) as u32).to_le_bytes());
        frame.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        frame.extend_from_slice(&compressed);
        let got = decompress_transform(&frame, &[CompressionCapabilities::ALGORITHM_LZ77], 1 << 20)
            .expect("decompress");
        assert_eq!(got, plain);
    }

    #[test]
    fn decompress_rejects_unsupported_algorithm() {
        let mut frame = vec![0; 24];
        frame[..4].copy_from_slice(&COMPRESSION_MAGIC);
        frame[4..8].copy_from_slice(&64u32.to_le_bytes());
        frame[8..10].copy_from_slice(&CompressionCapabilities::ALGORITHM_LZ77.to_le_bytes());
        assert_eq!(
            decompress_transform(
                &frame,
                &[CompressionCapabilities::ALGORITHM_PATTERN_V1],
                1 << 20
            )
            .unwrap_err(),
            CompressionError::Unsupported
        );
    }
}
