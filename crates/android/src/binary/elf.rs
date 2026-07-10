//! A tiny, allocation-free reader for 64-bit little-endian ELF program headers —
//! just enough to check the page-size alignment of `PT_LOAD` segments.

/// Returns `Some(true)` if every `PT_LOAD` segment is 16 KB-aligned,
/// `Some(false)` if at least one is aligned below 16 KB, or `None` if the input
/// isn't a parseable 64-bit little-endian ELF (32-bit libs are exempt).
pub fn is_16k_aligned(bytes: &[u8]) -> Option<bool> {
    const PAGE_16K: u64 = 16 * 1024;
    const PT_LOAD: u32 = 1;

    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return None;
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        return None; // not ELFCLASS64 / ELFDATA2LSB
    }

    let e_phoff = u64_le(bytes, 0x20)? as usize;
    let e_phentsize = u16_le(bytes, 0x36)? as usize;
    let e_phnum = u16_le(bytes, 0x38)? as usize;
    if e_phentsize < 56 {
        return None;
    }

    let mut saw_load = false;
    let mut all_aligned = true;
    for i in 0..e_phnum {
        let base = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        if u32_le(bytes, base)? != PT_LOAD {
            continue;
        }
        saw_load = true;
        let p_align = u64_le(bytes, base + 48)?;
        if p_align < PAGE_16K {
            all_aligned = false;
        }
    }
    saw_load.then_some(all_aligned)
}

fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_le(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 LE with a single PT_LOAD segment at the given alignment.
    fn build_elf(p_align: u64) -> Vec<u8> {
        let mut v = vec![0u8; 64 + 56];
        v[0..4].copy_from_slice(b"\x7fELF");
        v[4] = 2; // ELFCLASS64
        v[5] = 1; // ELFDATA2LSB
        v[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        v[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        v[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        v[64..68].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        v[64 + 48..64 + 56].copy_from_slice(&p_align.to_le_bytes()); // p_align
        v
    }

    #[test]
    fn flags_4k_alignment() {
        assert_eq!(is_16k_aligned(&build_elf(0x1000)), Some(false));
    }

    #[test]
    fn accepts_16k_alignment() {
        assert_eq!(is_16k_aligned(&build_elf(0x4000)), Some(true));
    }

    #[test]
    fn ignores_non_elf_and_32bit() {
        assert_eq!(is_16k_aligned(b"not an elf file at all, really!!"), None);
        let mut e = build_elf(0x1000);
        e[4] = 1; // ELFCLASS32 -> exempt
        assert_eq!(is_16k_aligned(&e), None);
    }
}
