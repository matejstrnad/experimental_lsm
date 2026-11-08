// The layout version of the pinned maps, derived from what they are made of.
// Included by explsm-common/build.rs (which gives it to the Rust side as
// `LAYOUT_VERSION`) and by its tests. Kept to std, as a build script needs.

/// `src` without its C comments, and with each run of whitespace made one
/// space, so rewording a comment or reindenting changes nothing.
pub fn normalize_c(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("/*") {
            rest = after.find("*/").map_or("", |end| &after[end + 2..]);
            out.push(' ');
        } else if let Some(after) = rest.strip_prefix("//") {
            rest = after.find('\n').map_or("", |end| &after[end..]);
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The map definitions of a BPF object's source: every
/// `struct { … } NAME SEC(".maps");`, normalized, in order.
pub fn map_definitions(bpf_c: &str) -> String {
    let src = normalize_c(bpf_c);
    let mut defs = Vec::new();
    let mut from = 0;
    while let Some(at) = src[from..].find("SEC(\".maps\");") {
        let end = from + at + "SEC(\".maps\");".len();
        if let Some(start) = src[..end].rfind("struct {") {
            defs.push(&src[start..end]);
        }
        from = end;
    }
    defs.join("\n")
}

/// FNV-1a of the shared header and the map definitions: what the pinned
/// maps are made of, and the constants that say what their entries mean.
/// Never 0, which `CONFIG[CFG_LAYOUT]` holds before the first daemon.
pub fn layout_version(header: &str, bpf_c: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let text = normalize_c(header) + "\n" + &map_definitions(bpf_c);
    for b in text.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h.max(1)
}
