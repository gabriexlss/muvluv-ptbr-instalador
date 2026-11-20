use anyhow::{bail, Result};

pub const ENCRYPTED_SIZE_XOR1: u32 = 0xC92E568B;
pub const ENCRYPTED_SIZE_XOR2: u32 = 0xC92E568F;
pub const ENCRYPTED_KEY_STEP: u32 = 0xA3B376C9;
pub const RIO_KEY: u32 = 0x7E6B8CE2;
pub const ICI_KEY: u32 = 0xB29D5A0C;
pub const EXTENT_OFFSET_BIAS: u32 = 0xA2FB6AD1;
pub const EXTENT_SIZE_BIAS: u32 = 0xE7B5D9F8;

pub const ICI_SIGNATURE: u32 = 0x673CE92A;
pub const ENCRYPTED_SIGNATURE: u32 = 0x1EDB927C;
pub const RIO_SIGNATURE: u32 = 0x596E32CD;
pub const OBJECT_SIGNATURE: u32 = 0x29F6CBA4;

pub fn round_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    ((value + alignment - 1) / alignment) * alignment
}

pub fn decode_extent_offset(raw_offset: u32, unit_size: u64) -> u64 {
    let units = u64::from(raw_offset.wrapping_sub(EXTENT_OFFSET_BIAS));
    units * unit_size
}

pub fn encode_extent_offset(byte_offset: u64, unit_size: u64) -> Result<u32> {
    if unit_size == 0 || byte_offset % unit_size != 0 {
        bail!(
            "byteOffset 0x{:X} not aligned to unitSize {}",
            byte_offset,
            unit_size
        );
    }
    let units = byte_offset / unit_size;
    if units > u64::from(u32::MAX) {
        bail!("byteOffset 0x{:X} exceeds 32-bit units", byte_offset);
    }
    Ok((units as u32).wrapping_add(EXTENT_OFFSET_BIAS))
}

pub fn decode_extent_size(raw_size: u32) -> u32 {
    let a = raw_size.wrapping_sub(EXTENT_SIZE_BIAS);
    let low19 = a >> 13;
    (a.wrapping_sub(low19 & 0xFFF) << 19) | low19
}

pub fn encode_extent_size(size: u32) -> Result<u32> {
    let low19 = size & 0x7FFFF;
    let high13 = size >> 19;
    let low13 = high13.wrapping_add(low19 & 0xFFF) & 0x1FFF;
    let shuffled = (low19 << 13) | low13;
    let encoded = shuffled.wrapping_add(EXTENT_SIZE_BIAS);
    if decode_extent_size(encoded) != size {
        bail!("extent size round-trip failed for {}", size);
    }
    Ok(encoded)
}

#[inline]
fn advance_key(key: u32) -> u32 {
    let bit = (key >> 15) & 1;
    !(bit
        .wrapping_add(key.wrapping_mul(2))
        .wrapping_add(ENCRYPTED_KEY_STEP))
}

pub fn decode_encrypted_header(header: &[u8]) -> Result<u32> {
    if header.len() < 8 {
        bail!("encrypted header truncated");
    }
    let stored1 = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let stored2 = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let size1 = !(stored1 ^ ENCRYPTED_SIZE_XOR1);
    let size2 = (stored2 ^ ENCRYPTED_SIZE_XOR2) >> 3;
    if size1 != size2 {
        bail!("encrypted header size mismatch: {} != {}", size1, size2);
    }
    Ok(size1)
}

pub fn generic_encrypted_storage_size(plain_size: u32) -> u64 {
    8 + u64::from(plain_size) + 2 * u64::from(plain_size / 0x20)
}

pub fn crsa_encrypted_storage_size(plain_size: u32) -> u64 {
    let chunks = (u64::from(plain_size) + 0x1F) / 0x20;
    8 + u64::from(plain_size) + 2 * chunks
}

/// Matches GARbro ReadEncrypted (no final partial checksum).
pub fn decode_encrypted_generic(data: &[u8], key: u32) -> Result<(Vec<u8>, usize)> {
    let size = decode_encrypted_header(data)? as usize;
    let expected = generic_encrypted_storage_size(size as u32) as usize;
    if data.len() < expected {
        bail!(
            "generic encrypted block truncated: need {}, got {}",
            expected,
            data.len()
        );
    }
    let mut out = vec![0u8; size];
    let mut src = 8usize;
    let mut dst = 0usize;
    let mut state = key;

    while dst < size {
        let portion = (size - dst).min(0x20);
        let mut checksum: u16 = 0;
        for i in 0..portion {
            let b = data[src + i] ^ ((state & 0xFF) as u8);
            out[dst + i] = b;
            checksum = checksum.wrapping_add(u16::from(b).wrapping_mul((portion - i) as u16));
            state = advance_key(state);
        }
        src += portion;
        dst += portion;
        if portion < 0x20 {
            break;
        }
        let stored = u16::from_le_bytes(data[src..src + 2].try_into().unwrap());
        if stored != checksum {
            bail!(
                "checksum mismatch at 0x{:X}: got 0x{:04X} want 0x{:04X}",
                src,
                stored,
                checksum
            );
        }
        src += 2;
    }

    Ok((out, src))
}

/// Decodes a CRsa encrypted stream including optional/required final partial checksum.
/// Returns (plaintext, consumed_bytes, has_final_partial_checksum).
pub fn decode_crsa_encrypted(data: &[u8], key: u32) -> Result<(Vec<u8>, usize, bool)> {
    let size = decode_encrypted_header(data)? as usize;
    let generic_need = generic_encrypted_storage_size(size as u32) as usize;
    let strict_need = crsa_encrypted_storage_size(size as u32) as usize;
    if data.len() < generic_need {
        bail!(
            "CRsa encrypted block truncated: need {}, got {}",
            generic_need,
            data.len()
        );
    }
    let mut out = vec![0u8; size];
    let mut src = 8usize;
    let mut dst = 0usize;
    let mut state = key;
    let mut has_final_partial = false;

    while dst < size {
        let portion = (size - dst).min(0x20);
        let mut checksum: u16 = 0;
        for i in 0..portion {
            let b = data[src + i] ^ ((state & 0xFF) as u8);
            out[dst + i] = b;
            checksum = checksum.wrapping_add(u16::from(b).wrapping_mul((portion - i) as u16));
            state = advance_key(state);
        }
        src += portion;
        dst += portion;
        if portion == 0x20 {
            let stored = u16::from_le_bytes(data[src..src + 2].try_into().unwrap());
            if stored != checksum {
                bail!(
                    "CRsa checksum mismatch at 0x{:X}: got 0x{:04X} want 0x{:04X}",
                    src,
                    stored,
                    checksum
                );
            }
            src += 2;
        } else if data.len() >= strict_need {
            let stored = u16::from_le_bytes(data[src..src + 2].try_into().unwrap());
            if stored == checksum {
                has_final_partial = true;
                src += 2;
            }
        }
    }

    Ok((out, src, has_final_partial))
}

/// Encodes plaintext into rUGP checksum-framed encrypted bytes.
pub fn encode_crsa_encrypted(
    plaintext: &[u8],
    key: u32,
    template_header: &[u8],
    include_final_partial: bool,
) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        bail!("CRsa plaintext must not be empty");
    }
    let size = u32::try_from(plaintext.len())
        .map_err(|_| anyhow::anyhow!("CRsa plaintext exceeds u32"))?;
    let stored1 = (!size) ^ ENCRYPTED_SIZE_XOR1;
    let mut stored2 = (size << 3) ^ ENCRYPTED_SIZE_XOR2;
    if template_header.len() == 8 {
        let orig2 = u32::from_le_bytes(template_header[4..8].try_into().unwrap());
        stored2 = (stored2 & !7u32) | (orig2 & 7u32);
    }

    let cap = crsa_encrypted_storage_size(size) as usize;
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&stored1.to_le_bytes());
    out.extend_from_slice(&stored2.to_le_bytes());

    let mut src = 0usize;
    let mut state = key;
    while src < plaintext.len() {
        let portion = (plaintext.len() - src).min(0x20);
        let mut checksum: u16 = 0;
        for i in 0..portion {
            let b = plaintext[src + i];
            out.push(b ^ ((state & 0xFF) as u8));
            checksum = checksum.wrapping_add(u16::from(b).wrapping_mul((portion - i) as u16));
            state = advance_key(state);
        }
        src += portion;
        if portion == 0x20 || include_final_partial {
            out.extend_from_slice(&checksum.to_le_bytes());
        }
    }

    Ok(out)
}

fn deinterleave(data: &[u8], lanes: usize) -> Vec<u8> {
    let n = data.len();
    let count = n / lanes;
    let tail = n % lanes;
    let mut out = vec![0u8; n];
    let mut src = 0usize;
    let mut dst = 0usize;
    for _ in 0..count {
        for lane in 0..lanes {
            out[dst] = data[src + count * lane];
            dst += 1;
        }
        src += 1;
    }
    if tail > 0 {
        out[dst..].copy_from_slice(&data[n - tail..]);
    }
    out
}

pub fn decrypt_ici_payload(data: &[u8]) -> Vec<u8> {
    let mut s1 = deinterleave(data, 6);
    let mut acc: u8 = 0;
    for v in &mut s1 {
        let cur = (*v).wrapping_sub(acc);
        acc = acc.wrapping_add(cur);
        *v = cur ^ 0xA5;
    }

    let mut s2 = deinterleave(&s1, 5);
    acc = 0;
    for i in (0..s2.len()).rev() {
        let cur = s2[i].wrapping_sub(acc);
        acc = acc.wrapping_add(cur);
        s2[i] = cur;
    }

    let mut s3 = deinterleave(&s2, 3);
    const MASKS: [u8; 3] = [0x18, 0x3F, 0xE2];
    let full = s3.len() - (s3.len() % 3);
    for (i, b) in s3.iter_mut().take(full).enumerate() {
        *b ^= MASKS[i % 3];
    }
    s3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extent_offset_and_size_roundtrip() {
        for off in [0u64, 2, 0x1000, 359_226_836] {
            let raw = encode_extent_offset(off, 2).unwrap();
            assert_eq!(decode_extent_offset(raw, 2), off);
        }
        for sz in [1u32, 32, 0x7FFFF, 0x123456, 0x1000000] {
            let raw = encode_extent_size(sz).unwrap();
            assert_eq!(decode_extent_size(raw), sz);
        }
    }

    #[test]
    fn crsa_crypto_roundtrip() {
        let payload = b"Muv-Luv PT-BR: \xC3\xA1\xC3\xA9\xC3\xAD\xC3\xB3\xC3\xBA \xC3\xA7\xC3\xA3\xC3\xB5! Extra & Unlimited.";
        let enc = encode_crsa_encrypted(payload, RIO_KEY, &[], true).unwrap();
        let (plain, consumed, has_partial) = decode_crsa_encrypted(&enc, RIO_KEY).unwrap();
        assert_eq!(plain, payload);
        assert_eq!(consumed, enc.len());
        assert!(has_partial);

        let (gen_plain, _) = decode_encrypted_generic(&enc, RIO_KEY).unwrap();
        assert_eq!(gen_plain, payload);
    }
}

