//! RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 second step), the format AWS virtual MFA uses.

use hmac::{Hmac, Mac};
use sha1::Sha1;

pub const STEP_SECS: u64 = 30;

/// Decodes RFC 4648 base32, ignoring spaces, padding and case.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let c = c.to_ascii_uppercase();
        let v = match c {
            'A'..='Z' => c as u8 - b'A',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | v as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Returns the 6-digit code for the given Unix time.
pub fn totp_at(seed: &[u8], unix_time: u64) -> u32 {
    let counter = unix_time / STEP_SECS;
    let mut mac = Hmac::<Sha1>::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let code = ((h[off] as u32 & 0x7f) << 24)
        | ((h[off + 1] as u32) << 16)
        | ((h[off + 2] as u32) << 8)
        | (h[off + 3] as u32);
    code % 1_000_000
}

pub fn valid_for_secs(unix_time: u64) -> u64 {
    STEP_SECS - (unix_time % STEP_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 appendix B: ASCII seed "12345678901234567890", T=59 -> 94287082 (8 digits),
        // whose last 6 digits are the 6-digit code.
        assert_eq!(totp_at(b"12345678901234567890", 59), 287082);
        assert_eq!(totp_at(b"12345678901234567890", 1111111109), 81804);
    }

    #[test]
    fn base32_roundtrip_of_known_seed() {
        let seed = base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(seed, b"12345678901234567890");
        assert_eq!(base32_decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap(), seed);
        assert!(base32_decode("not base32!").is_none());
        assert!(base32_decode("").is_none());
    }

    #[test]
    fn countdown() {
        assert_eq!(valid_for_secs(60), 30);
        assert_eq!(valid_for_secs(89), 1);
    }
}
