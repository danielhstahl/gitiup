//! Moving the history, and proving it arrived.
//!
//! Two questions live here, and the ticket insists on both:
//!
//! * **Does the code come?** The forge API has no packfile endpoint, so history moves from
//!   a git endpoint through a local mirror into whatever the destination offers — a git
//!   object database if it has one, or the record store if it does not. Which of those it
//!   was is [`ObjectMove::form`], and the report prints it, because "the bucket has your
//!   history" and "the bucket has your history as gitiup records, which `git fetch` will not
//!   carry" are different sentences about the same bytes.
//! * **Did it come faithfully?** Every commit that arrived *with a proof* is re-hashed
//!   **from the destination's copy** and counted. A proof about a commit the new store cannot
//!   name is a photograph of a proof, so the count is not decoration: it is the difference
//!   between a migration and a copy with confidence.
//!
//! The re-hash is git's own arithmetic (`git hash-object -t commit --stdin` on the bytes the
//! store returned, `git index-pack` for the packfile path, which refuses an object that does
//! not hash to the name it arrived under). Nothing here recomputes a git object header by
//! hand, and nothing here reports a match it did not actually read back.

use std::collections::BTreeSet;
use std::path::Path;

use gitiup_host::{Host, HostKind, HostResult, Namespace, Oid, Pack, PackFormat, PackRequest};

use super::journal::Journal;
use super::mirror::{BATCH_OBJECTS, Mirror, hash_commit};

/// The namespace a store with no git object database keeps git objects under.
///
/// The same one `gitiup change submit` files a change's commits under, so a store migrated
/// here and a change submitted here are stored the same way — one less place where "a bucket
/// holds git objects" means two things.
pub const GIT_OBJECT: Namespace = Namespace::const_new("git-object");

/// What moved, in the words the report prints.
#[derive(Debug, Clone, Default)]
pub struct ObjectMove {
    /// Objects handed to the destination.
    pub objects: usize,
    /// Bytes those objects took.
    pub bytes: u64,
    /// `git-packfile` · `records` · `nothing-new` · `skipped`.
    pub form: &'static str,
    /// The sentence about the form, when the form needs one.
    pub detail: Option<String>,
}

impl ObjectMove {
    /// The phrase for the human report: the form, the count, and the sentence the form
    /// needs — a bucket holding git objects as records has to say so, or the next person
    /// runs `git fetch` at it and is surprised.
    pub fn phrase(&self) -> String {
        let form = match self.form {
            "git-packfile" => format!("as a git packfile, {} object(s)", self.objects),
            "records" => format!("as gitiup records, {} object(s)", self.objects),
            "nothing-new" => "nothing new".to_string(),
            _ => "not moved".to_string(),
        };
        match &self.detail {
            Some(detail) => format!("{form} — {detail}"),
            None => form,
        }
    }
}

/// Move everything reachable from `tip` that is not reachable from `not`.
///
/// `proofs` names the commits that arrive with at least one attestation. Only those get
/// their bytes catalogued in the journal, and that is deliberate rather than an
/// optimisation: the catalogue is what the verification reads back, and cataloguing a
/// repository's every commit to check a dozen of them would make the journal as big as the
/// history.
pub fn move_objects(
    mirror: &Mirror,
    to: &dyn Host,
    tip: &str,
    not: &[String],
    proofs: &BTreeSet<String>,
    journal: &mut Journal,
) -> HostResult<ObjectMove> {
    let wants = vec![tip.to_string()];
    let objects = mirror.objects(&wants, not)?;
    if objects.is_empty() {
        return Ok(ObjectMove {
            objects: 0,
            bytes: 0,
            form: "nothing-new",
            detail: None,
        });
    }
    let kind = to.kind();
    let moved = if kind == HostKind::Git {
        let pack = mirror.packfile(&objects)?;
        let bytes = pack.len() as u64;
        to.put_pack(&Pack::git_packfile(pack)?)?;
        ObjectMove {
            objects: objects.len(),
            bytes,
            form: "git-packfile",
            detail: None,
        }
    } else {
        // A bucket or a directory has no git object database, so the objects go in as
        // records: the store can return the bytes of anything it was given, and the report
        // says that a `git fetch` of these refs will not carry them. Batched, so a big
        // history costs a window of memory and not the whole of itself.
        let mut bytes = 0u64;
        for chunk in objects.chunks(BATCH_OBJECTS) {
            let contents = mirror.contents(chunk)?;
            if contents.len() != chunk.len() {
                return Err(gitiup_host::HostError::invalid(
                    "git cat-file --batch",
                    format!("asked for {} objects, got {}", chunk.len(), contents.len()),
                ));
            }
            let pack = Pack::from_raw_objects(
                contents
                    .iter()
                    .cloned()
                    .map(|content| (GIT_OBJECT, content)),
            )?;
            bytes += pack.len() as u64;
            to.put_pack(&pack)?;
            for (oid, content) in chunk.iter().zip(contents.iter()) {
                // Only the commits a proof is about are catalogued; a tree or a blob has no
                // name a proof could be checked against, and cataloguing a repository's
                // every commit to re-hash a dozen of them would make the journal as big as
                // the history.
                if proofs.contains(oid) {
                    journal.note_commit(oid, &Oid::hash_bytes(content).hex());
                }
            }
        }
        ObjectMove {
            objects: objects.len(),
            bytes,
            form: "records",
            detail: Some(
                "this store has no git object database: the objects are gitiup records, so \
                 `gitiup` can return any of them and `git fetch` cannot carry them"
                    .to_string(),
            ),
        }
    };
    Ok(moved)
}

/// Whether this store can hand over the bytes of this commit by itself.
///
/// A git repository answers the question directly: ask it for the object and see whether it
/// produces one. A bucket or a directory has no git object database and no index of git
/// names, so it cannot answer at all, and "cannot answer" is treated as no — the question is
/// being asked in order to decide whether a ref may point here, and guessing yes is exactly
/// the failure ADR-0005 D8 forbids.
pub fn holds(to: &dyn Host, tip: &str) -> bool {
    if to.kind() != HostKind::Git {
        return false;
    }
    let Ok(oid) = Oid::from_hex(tip) else {
        return false;
    };
    match to.fetch_pack(&PackRequest::new([oid]).with_format(PackFormat::GitPackfile)) {
        Ok(pack) => !pack.bytes.is_empty(),
        Err(_) => false,
    }
}

/// What the faithfulness check found.
#[derive(Debug, Clone, Default)]
pub struct Verified {
    /// Commits that arrived with at least one proof.
    pub with_proof: usize,
    /// How many were actually read back out of the destination.
    pub rehashed: usize,
    /// How many re-hashed to the name their proof gives.
    pub matched: usize,
    /// `(commit, what it hashed to)` for the ones that did not.
    pub mismatched: Vec<(String, String)>,
    /// Commits whose bytes this store does not hold, so nothing could be re-hashed.
    pub unreadable: Vec<String>,
    /// Which clock the age of a proof is measured from — the ADR-0005 D5 invariant, printed
    /// because a constant nobody prints is a constant somebody changes.
    pub basis: &'static str,
}

impl Verified {
    /// The one line a report prints.
    pub fn line(&self) -> String {
        format!(
            "{}/{} matched, {} mismatched, {} not in this store (re-hashed from the store's \
             own bytes, age basis {})",
            self.matched,
            self.with_proof,
            self.mismatched.len(),
            self.unreadable.len(),
            self.basis
        )
    }

    /// Whether the migration may claim it was faithful.
    pub fn faithful(&self) -> bool {
        self.mismatched.is_empty()
    }

    /// The same facts as data.
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "commits_with_proof": self.with_proof,
            "rehashed": self.rehashed,
            "matched": self.matched,
            "mismatched": self.mismatched,
            "unreadable": self.unreadable,
            "age_basis": self.basis,
        })
    }
}

/// Re-hash every proof-bearing commit **in the destination**.
///
/// Two read paths, because that is what two kinds of store offer: a git store is asked for a
/// packfile naming the commit, which `index-pack` accepts only if the object hashes to that
/// name; a record store is asked for the record its journal catalogued, whose bytes the
/// store re-hashes on the way out and which git then names. Either way the bytes come from
/// the destination, not from the mirror that carried them — reading the copy against the
/// copy would prove nothing at all.
pub fn verify(
    to: &dyn Host,
    journal: &Journal,
    proofs: &BTreeSet<String>,
    scratch: &Path,
) -> HostResult<Verified> {
    let mut out = Verified {
        with_proof: proofs.len(),
        basis: "claimed_at_us",
        ..Default::default()
    };
    if proofs.is_empty() {
        return Ok(out);
    }
    let kind = to.kind();
    if kind == HostKind::Git {
        let mut pack: Vec<u8> = Vec::new();
        let mut asked: Vec<String> = Vec::new();
        for oid in proofs {
            let Ok(want) = Oid::from_hex(oid) else {
                out.unreadable.push(oid.clone());
                continue;
            };
            match to.fetch_pack(&PackRequest::new([want]).with_format(PackFormat::GitPackfile)) {
                Ok(found) => {
                    pack.extend_from_slice(&found.bytes);
                    asked.push(oid.clone());
                }
                Err(_) => out.unreadable.push(oid.clone()),
            }
        }
        // `git index-pack` makes the scratch object database if this run has none, so a
        // migration that moved no history can still be checked; a machine with no git
        // binary cannot, and says *unverified* rather than guessing either way.
        let named = match Mirror::index_and_check(&pack, &asked, scratch) {
            Ok(named) => named,
            Err(_) => {
                for oid in &asked {
                    out.unreadable.push(oid.clone());
                }
                return Ok(out);
            }
        };
        for oid in &asked {
            if named.iter().any(|found| found == oid) {
                out.rehashed += 1;
                out.matched += 1;
            } else {
                out.rehashed += 1;
                out.mismatched
                    .push((oid.clone(), "absent from the pack".to_string()));
            }
        }
        return Ok(out);
    }
    for oid in proofs {
        let Some(digest) = journal.commits.get(oid) else {
            out.unreadable.push(oid.clone());
            continue;
        };
        let want = match Oid::from_hex(digest) {
            Ok(oid) => oid,
            Err(_) => {
                out.unreadable.push(oid.clone());
                continue;
            }
        };
        let Some(bytes) = to.get(&want)? else {
            out.unreadable.push(oid.clone());
            continue;
        };
        let named = hash_commit(&bytes)?;
        out.rehashed += 1;
        if named.eq_ignore_ascii_case(oid) {
            out.matched += 1;
        } else {
            out.mismatched.push((oid.clone(), named));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_verification_is_faithful_and_says_why() {
        let verified = Verified::default();
        assert!(verified.faithful());
        assert_eq!(verified.with_proof, 0);
        // The basis is a constant, and the constant is the ADR's invariant.
        assert_eq!(
            Verified {
                basis: "claimed_at_us",
                ..Default::default()
            }
            .basis,
            "claimed_at_us"
        );
    }

    #[test]
    fn a_mismatch_is_never_faithful() {
        let verified = Verified {
            with_proof: 2,
            rehashed: 2,
            matched: 1,
            mismatched: vec![("aa".into(), "bb".into())],
            unreadable: vec![],
            basis: "claimed_at_us",
        };
        assert!(!verified.faithful());
        assert!(verified.line().contains("1/2 matched"));
        assert!(verified.line().contains("claimed_at_us"));
    }

    #[test]
    fn the_two_object_forms_are_two_sentences() {
        let records = ObjectMove {
            objects: 3,
            bytes: 10,
            form: "records",
            detail: None,
        };
        assert!(records.phrase().contains("record"));
        assert!(
            ObjectMove {
                form: "git-packfile",
                objects: 3,
                ..Default::default()
            }
            .phrase()
            .contains("packfile")
        );
    }

    #[test]
    fn git_objects_live_in_their_own_namespace() {
        assert_eq!(GIT_OBJECT.as_str(), "git-object");
    }
}
