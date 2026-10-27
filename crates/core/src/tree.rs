//! Code tree hash: a single digest naming an exact set of (path, content)
//! pairs, independent of tar layout, timestamps or permissions.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const TREE_DOMAIN: &str = "attest-tree-v1\n";

/// `files` maps normalized relative paths to sha256(content).
pub fn tree_hash(files: &BTreeMap<String, [u8; 32]>) -> String {
    let mut h = Sha256::new();
    h.update(TREE_DOMAIN.as_bytes());
    for (path, digest) in files {
        h.update(path.as_bytes());
        h.update([0u8]);
        h.update(hex::encode(digest).as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// Same construction, used as a commitment over the files the model read.
pub fn files_commitment<'a>(files: impl IntoIterator<Item = (&'a String, &'a [u8; 32])>) -> String {
    let map: BTreeMap<String, [u8; 32]> = files.into_iter().map(|(k, v)| (k.clone(), *v)).collect();
    tree_hash(&map)
}

/// Reject absolute paths, `..`, empty components and backslashes so a tar
/// entry can only ever name a file inside the bundle.
pub fn normalize_path(p: &str) -> Option<String> {
    if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.contains('\0') {
        return None;
    }
    let mut parts = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => continue,
            ".." => return None,
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        assert_eq!(normalize_path("./a//b/c.rs").as_deref(), Some("a/b/c.rs"));
        assert_eq!(normalize_path("../x"), None);
        assert_eq!(normalize_path("/etc/passwd"), None);
        assert_eq!(normalize_path("a/../../b"), None);
    }

    #[test]
    fn order_independent() {
        let mut a = BTreeMap::new();
        a.insert("b".to_string(), sha256(b"2"));
        a.insert("a".to_string(), sha256(b"1"));
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), sha256(b"1"));
        b.insert("b".to_string(), sha256(b"2"));
        assert_eq!(tree_hash(&a), tree_hash(&b));
        b.insert("c".to_string(), sha256(b""));
        assert_ne!(tree_hash(&a), tree_hash(&b));
    }
}
