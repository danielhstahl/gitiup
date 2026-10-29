//! Where a gitiup host puts things, spelled for a forge that stores git objects.
//!
//! Every host in the workspace agrees on the logical layout — refs in the four
//! shared namespaces, records at `<namespace>/<sha256hex>` under a `kv` root — and
//! each spells it in its own idiom. The `fs` and `s3` hosts have a key space, so a
//! record is a key. A forge that stores git objects has a tree and a ref, so:
//!
//! ```text
//! refs/gitiup/kv                 one append-only commit chain
//!   <namespace>/<sha256hex>      one file per record, content verbatim
//! refs/changes/<id>/head         pointer commit → gitiup-ref.json + record
//! refs/attestations/<subject>/<digest>  pointer commit → gitiup-ref.json + record
//! ```
//!
//! which is the same shape the plain-git host uses, so a repository can be moved
//! between them with a `git push` and nothing else.
//!
//! `refs/gitiup/**` is the store's own bookkeeping and is hidden from an ordinary
//! ref listing ([`is_internal_ref`]), exactly as on the other hosts: a listing is
//! for branches, changes and attestations, and a caller who wants the plumbing asks
//! for it by name.

use gitiup_host::{Namespace, Oid, RefName};

/// The ref holding the record chain.
pub fn kv_ref_name() -> RefName {
    // `refs/gitiup/kv` is a fixed, valid name.
    RefName::gitiup("kv").expect("refs/gitiup/kv is a valid ref name")
}

/// The path a record takes inside the chain's tree: `<namespace>/<sha256hex>`.
pub fn record_path(namespace: &Namespace, oid: &Oid) -> String {
    format!("{}/{}", namespace, oid.hex())
}

/// Whether a ref is the store's own machinery rather than something a listing
/// should show.
pub fn is_internal_ref(name: &str) -> bool {
    name == gitiup_host::refs::ns::GITIUP
        || name.starts_with(&format!("{}/", gitiup_host::refs::ns::GITIUP))
}

/// The namespace a chain path belongs to, or `None` if it is not a record path.
pub fn namespace_of(path: &str) -> Option<Namespace> {
    let (namespace, rest) = path.split_once('/')?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Namespace::new(namespace).ok()
}

/// The digest a chain path names.
pub fn oid_of(path: &str) -> Option<Oid> {
    let hex = path.rsplit('/').next()?;
    Oid::from_hex(hex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_paths_round_trip_through_their_parts() {
        let namespace = Namespace::ATTESTATION;
        let oid = Oid::hash_bytes(b"attested bytes");
        let path = record_path(&namespace, &oid);
        assert_eq!(path, format!("attestation/{}", oid.hex()));
        assert_eq!(namespace_of(&path).unwrap(), namespace);
        assert_eq!(oid_of(&path).unwrap(), oid);
        assert_eq!(namespace_of("README.md"), None);
        assert_eq!(namespace_of("attestation/a/b"), None);
        assert_eq!(oid_of("attestation/not-hex"), None);
    }

    #[test]
    fn the_stores_own_refs_are_hidden() {
        assert!(is_internal_ref("refs/gitiup/kv"));
        assert!(is_internal_ref("refs/gitiup/whatever/deeper"));
        assert!(is_internal_ref("refs/gitiup"));
        assert!(!is_internal_ref("refs/heads/main"));
        assert!(!is_internal_ref("refs/changes/c1/head"));
        assert!(!is_internal_ref("refs/gitiup-not-really"));
    }
}
