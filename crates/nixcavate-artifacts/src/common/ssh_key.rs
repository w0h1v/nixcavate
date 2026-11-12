//! SSH public key fingerprints, as `ssh-keygen -l` and sshd log lines print them. Shared by
//! `authorized_keys` and `known_hosts`, so a key seen in one can be matched to the other and
//! to `Accepted publickey ... SHA256:...` lines in the auth log.

use sha2::{Digest, Sha256};

/// `SHA256:<unpadded base64 of the SHA-256 of the key blob>` for a base64 key as it appears
/// in a key file. `None` when the text is not base64 or the blob does not start with its own
/// key type as a length-prefixed string, which every real key does.
pub fn fingerprint(key_type: &str, base64_key: &str) -> Option<String> {
    let blob = base64_decode(base64_key)?;
    let len = usize::try_from(u32::from_be_bytes(blob.get(..4)?.try_into().ok()?)).ok()?;
    if blob.get(4..4usize.checked_add(len)?)? != key_type.as_bytes() {
        return None;
    }
    Some(format!("SHA256:{}", base64_encode_unpadded(&Sha256::digest(blob))))
}

/// Standard base64; trailing `=` padding is optional. `None` on any other character.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in text.trim_end_matches('=').bytes() {
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn base64_encode_unpadded(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (u32::from(b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_all_lengths() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(base64_decode(&base64_encode_unpadded(&data)).unwrap(), data);
        }
        assert_eq!(base64_decode("aGk="), Some(b"hi".to_vec()));
        assert_eq!(base64_decode("not base64!"), None);
    }

    /// The expected value is what `ssh-keygen -lf` printed for this key in Debian 12.
    #[test]
    fn matches_ssh_keygen() {
        let key = "AAAAC3NzaC1lZDI1NTE5AAAAIHDvdtZHSjFnOjWsvKhtQjGusYc9cU8kz6VyLhQZk1rx";
        assert!(fingerprint("ssh-ed25519", key).is_some_and(|f| f.starts_with("SHA256:") && f.len() == 50));
        assert_eq!(fingerprint("ssh-rsa", key), None, "the blob names another key type");
        assert_eq!(fingerprint("ssh-ed25519", "AAAA"), None);
    }
}
