//! Synthesis of MSVC string-literal symbol names (`??_C@_0…`).
//!
//! MSVC emits every string literal as a COMDAT with a deterministic decorated
//! name derived purely from the string's bytes. Those COMDATs are frequently
//! folded/anonymous and carry **no** symbol record in the PDB, so a data
//! reference to one falls through the PDB-symbol lookup to a raw
//! `__delink_pe_<section>_start + offset` section-relative fallback — which
//! never matches the `??_C@…` symbol our own recompiled object references.
//!
//! Since the name is a pure function of the bytes, we reproduce MSVC's mangling
//! here and look the literal up **by address** (reading the bytes at the
//! reference target) rather than by a name that isn't in the PDB.
//!
//! Name format:  `??_C@_0<len><crc>@<text>@`
//!   * `<len>` — byte length *including* the NUL terminator, as a mangled number
//!     (`1..=10` → `'0'..'9'` = value-1; otherwise base-16 nibbles `A`(0)..`P`(15)
//!     most-significant first, terminated by `@`).
//!   * `<crc>` — CRC-32 (poly 0xEDB88320, init 0xFFFFFFFF, **no** final inversion)
//!     over the bytes *including* the NUL, as 8 nibbles `A`..`P`, MSB first.
//!   * `<text>` — up to the first 32 source bytes, escaped (see [`escape_byte`]),
//!     terminated by `@`.

/// Precomputed CRC-32 lookup table (reflected, poly 0xEDB88320).
const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = crc32_table();

/// MSVC's string-literal checksum: CRC-32 with init `0xFFFFFFFF` and **no**
/// final XOR (unlike zlib, which inverts the result).
fn msvc_string_crc(bytes: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in bytes {
        c = CRC32_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// Append `n` nibbles of `v` (most-significant first) using the `A`(0)..`P`(15)
/// alphabet MSVC uses for mangled numbers.
fn push_nibbles(out: &mut String, v: u32, n: u32) {
    for i in (0..n).rev() {
        let nib = (v >> (i * 4)) & 0xF;
        out.push((b'A' + nib as u8) as char);
    }
}

/// Encode a mangled number: `1..=10` as a single digit `'0'..'9'` (value-1),
/// otherwise base-16 nibbles `A`..`P` (MSB first) terminated by `@`.
fn encode_number(out: &mut String, value: u32) {
    if (1..=10).contains(&value) {
        out.push((b'0' + (value - 1) as u8) as char);
        return;
    }
    // Minimal nibble count.
    let mut nibbles = 0u32;
    let mut x = value;
    while x != 0 {
        nibbles += 1;
        x >>= 4;
    }
    if nibbles == 0 {
        nibbles = 1;
    }
    push_nibbles(out, value, nibbles);
    out.push('@');
}

/// The ten single-character escapes MSVC uses for common punctuation, indexed
/// `0..=9` → `?0`..`?9`.  Order is significant.
const SPECIAL: &[u8] = b",/\\:. \n\t'-";

/// Escape one source byte into the string-literal text field.
fn escape_byte(out: &mut String, b: u8) {
    if b.is_ascii_alphanumeric() || b == b'_' {
        out.push(b as char);
    } else if let Some(idx) = SPECIAL.iter().position(|&c| c == b) {
        out.push('?');
        out.push((b'0' + idx as u8) as char);
    } else {
        out.push_str("?$");
        out.push((b'A' + (b >> 4)) as char);
        out.push((b'A' + (b & 0xF)) as char);
    }
}

/// The maximum source-byte prefix MSVC embeds in the decorated name's text field.
const MAX_TEXT_BYTES: usize = 32;

/// Build the MSVC `??_C@` decorated name for a narrow (char) string literal.
///
/// `content` is the string's bytes **without** the terminating NUL; this
/// function appends it (MSVC hashes and counts the NUL).
pub fn narrow_string_symbol(content: &[u8]) -> String {
    // Length and CRC are over the bytes including the NUL terminator.
    let total_len = content.len() as u32 + 1;
    // CRC over content + NUL, without allocating a joined buffer.
    let crc = {
        let mut c = msvc_string_crc(content);
        c = CRC32_TABLE[((c ^ 0) & 0xFF) as usize] ^ (c >> 8);
        c
    };

    let mut out = String::from("??_C@_0");
    encode_number(&mut out, total_len);
    push_nibbles(&mut out, crc, 8);
    out.push('@');
    // Text: escape up to MAX_TEXT_BYTES source bytes (NUL only appears if the
    // whole string fits, since content excludes it and we cap before it).
    let text_bytes = content.len().min(MAX_TEXT_BYTES);
    for &b in &content[..text_bytes] {
        escape_byte(&mut out, b);
    }
    if content.len() < MAX_TEXT_BYTES {
        // Short enough that the NUL terminator is part of the embedded text.
        escape_byte(&mut out, 0);
    }
    out.push('@');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_string_literal_names() {
        // Ground-truth (content, decorated name) pairs extracted from
        // MSVC-compiled objects, spanning the single-digit and multi-nibble
        // length forms and the space/`?5` escape.
        let cases: &[(&[u8], &str)] = &[
            (b"system", "??_C@_06FHFOAHML@system?$AA@"),
            (b"generic", "??_C@_07DCLBNMLN@generic?$AA@"),
            (b"iostream", "??_C@_08LLGCOLLL@iostream?$AA@"),
            (b"tag_resource_lruv", "??_C@_0BC@DKEHMPJE@tag_resource_lruv?$AA@"),
            (b"string too long", "??_C@_0BA@JFNIOLAK@string?5too?5long?$AA@"),
        ];
        for (content, expected) in cases {
            assert_eq!(&narrow_string_symbol(content), expected, "content = {:?}", content);
        }
    }

    #[test]
    fn crc_matches_reference() {
        // "system\0" → 0x575E07CB
        assert_eq!(msvc_string_crc(b"system\x00"), 0x575E_07CB);
    }
}
