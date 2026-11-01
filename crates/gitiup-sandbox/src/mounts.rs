//! Mount points: one destination, one mount.
//!
//! A container is addressed by *destination*. `-v /work:/work:ro` means "put this host
//! directory at that path in the job", and the runtime keeps its mounts keyed by that
//! destination. Ask for two mounts at one destination and it does not resolve the
//! conflict, does not keep the newer one, and does not name the two grants that
//! collided — it refuses the whole container:
//!
//! ```text
//! Error response from daemon: Duplicate mount point: '/work'
//! ```
//!
//! That is giti-0xi, and the clash was not exotic. The spec a workflow step runs under
//! is "the checkout **and** the scratch are writable", so the checkout is named twice:
//! once by [`Spec::read_paths`] (every backend mounts a workspace read-only) and once
//! by [`Spec::write_paths`] (a build writes where it is checked out). Two `-v`
//! arguments, one destination, one refused run — and the message named neither grant,
//! which is why it took a Mac user to file it as a mystery.
//!
//! So the mounts are worked out here, once, before any argv exists, under three rules:
//!
//! 1. **one destination, one mount.** A tree named twice is mounted once, and a
//!    writable grant wins over a read-only one: the only way the two meet is a spec
//!    that named the tree writable, and an explicit `with_writable` is what the
//!    read-only default is traded against. The collapse is *said*, in
//!    [`Plan::notes`] — "read-only workspace" just stopped being true, and a reviewer
//!    reading the plan is owed that sentence.
//! 2. **a destination a backend has already claimed for itself is refused, not
//!    overwritten.** The scratch cap is enforced by a size-capped tmpfs at `/tmp` on
//!    the container and `bwrap` rungs; a spec that mounts a tree *at* `/tmp` wants
//!    that address, and the runtime answers `Duplicate mount point: '/tmp'` without
//!    saying which half was the mistake. The refusal names the fix (a scratch *inside*
//!    `/tmp` keeps its cap) instead.
//! 3. **one host directory named two ways is said out loud when the two spellings get
//!    different grants.** On macOS `/tmp`, `/var` and `/etc` are symlinks into
//!    `/private`, and on a merged-usr Linux `/bin` *is* `/usr/bin`; a tree mounted
//!    read-only under one spelling is writable through the other. Nothing is guessed
//!    from the shape of the string — the host is asked, with `realpath`.
//!
//! Two paths count as the same *destination* when the runtime would say so: compared
//! after a lexical clean, because a runtime cleans the destination before keying it, so
//! `/work/` and `/work/x/../x` are one address whether or not they exist. Two paths
//! count as the same *directory* when the host says so.

use std::path::{Path, PathBuf};

use gitiup_attest::{Error, ErrorKind, Result};

use crate::spec::Spec;

/// The destination the container and `bwrap` rungs claim for themselves on every run:
/// the size-capped tmpfs that carries the scratch cap.
pub const TMPFS_DESTINATIONS: [&str; 1] = ["/tmp"];

/// The destinations `bwrap` claims besides the tmpfs: it builds `/proc` and `/dev`
/// itself, so a spec that also names them would be mounting over its own work.
pub const BWRAP_DESTINATIONS: [&str; 3] = ["/tmp", "/proc", "/dev"];

/// One mount the runtime will be asked to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The host directory, spelled as the spec spelled it.
    pub source: PathBuf,
    /// Where the job will see it: the same absolute path, so the paths in the job's own
    /// environment stay true inside it. A backend that relocated a mount would produce
    /// logs that match nothing on the host, which is why relocation is not offered.
    pub destination: PathBuf,
    /// Whether the job may write there.
    pub writable: bool,
}

impl Mount {
    /// `rw` or `ro`, in the runtime's own words.
    pub fn mode(&self) -> &'static str {
        if self.writable { "rw" } else { "ro" }
    }

    /// The `-v` form a container runtime takes: `source:destination:mode`.
    pub fn volume_arg(&self) -> String {
        format!(
            "{}:{}:{}",
            self.source.display(),
            self.destination.display(),
            self.mode()
        )
    }

    /// `` `/work` (read-only) `` — how the mount reads inside a sentence a reviewer
    /// has to parse rather than scan.
    pub fn describe(&self) -> String {
        format!(
            "`{}` ({})",
            self.source.display(),
            if self.writable {
                "writable"
            } else {
                "read-only"
            }
        )
    }
}

/// What [`plan`] decided: the mounts to make, and what had to be resolved to make them
/// distinct.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// The mounts to make, **shallowest destination first**: the order in which a nested
    /// mount has to be asked for, because `bwrap` applies its arguments in the order
    /// given and mounting a parent after its child hides the child. A container runtime
    /// sorts them itself; asking in the same order everywhere is what makes the printed
    /// command line readable as well as correct.
    pub mounts: Vec<Mount>,
    /// Every resolution that changed what a reviewer would have read out of the spec, in
    /// sentences. Printed in the plan notes and by `gitiup doctor`; never swallowed.
    pub notes: Vec<String>,
}

impl Plan {
    /// The writable mounts.
    pub fn writable(&self) -> Vec<&Mount> {
        self.mounts.iter().filter(|mount| mount.writable).collect()
    }

    /// The read-only mounts.
    pub fn read_only(&self) -> Vec<&Mount> {
        self.mounts.iter().filter(|mount| !mount.writable).collect()
    }

    /// The mounts as one comma-separated list, for a note.
    pub fn list(&self, writable: bool) -> String {
        let named: Vec<String> = self
            .mounts
            .iter()
            .filter(|mount| mount.writable == writable)
            .map(|mount| mount.source.display().to_string())
            .collect();
        if named.is_empty() {
            "(none)".to_string()
        } else {
            named.join(", ")
        }
    }
}

/// Work out the mounts for one spec.
///
/// `reserved` names destinations the backend has already claimed for itself —
/// [`TMPFS_DESTINATIONS`] for `docker` and `podman`, [`BWRAP_DESTINATIONS`] for
/// `bwrap`. A spec mount that lands on one is refused, with the fix.
pub fn plan(spec: &Spec, reserved: &[&str]) -> Result<Plan> {
    // Read-only asks first: the writable ones overwrite, and asking second is what
    // makes "writable wins" the observable order as well as the stated one.
    let mut asks: Vec<(PathBuf, bool)> = Vec::new();
    for path in spec.read_paths() {
        asks.push((path, false));
    }
    for path in spec.write_paths() {
        asks.push((path, true));
    }
    let reserved: Vec<String> = reserved.iter().map(|path| clean(Path::new(path))).collect();

    let mut plan = Plan::default();
    // The destination as the runtime keys it → index into `plan.mounts`.
    let mut at: Vec<(String, usize)> = Vec::new();

    for (source, writable) in asks {
        let destination = clean(&source);
        if reserved.iter().any(|claim| claim == &destination) {
            // Said two ways because there are two reasons a destination is claimed: the
            // scratch cap's tmpfs, and a namespace backend's own `/proc` and `/dev`.
            let why = if TMPFS_DESTINATIONS
                .iter()
                .any(|claim| clean(Path::new(claim)) == destination)
            {
                "gitiup mounts a size-capped tmpfs there on every run to carry the scratch \
                 cap"
            } else {
                "this backend builds that directory itself"
            };
            return Err(Error::new(
                ErrorKind::Invalid,
                "sandbox",
                format!(
                    "`{destination}` is named as a mount, and {why} — a runtime keeps one \
                     mount per destination and refuses the container with `Duplicate mount \
                     point: '{destination}'`"
                ),
            )
            .with_hint(
                "name a directory *inside* the one that is claimed rather than the claimed \
                 one itself (`/tmp/gitiup-scratch` is fine, and keeps its cap), or put the \
                 scratch somewhere else: the tmpfs is what makes the scratch size a limit \
                 rather than a request",
            ));
        }
        match at.iter().find(|(key, _)| *key == destination) {
            None => {
                plan.mounts.push(Mount {
                    source,
                    destination: PathBuf::from(&destination),
                    writable,
                });
                at.push((destination, plan.mounts.len() - 1));
            }
            Some((_, index)) => {
                // Same destination, so same path — every mount is at its own absolute
                // path, which is what makes a repeated destination a repeated *tree*
                // rather than two trees fighting over an address.
                let widened = writable && !plan.mounts[*index].writable;
                if widened {
                    plan.notes.push(format!(
                        "{} is named as a readable tree and as a writable one: it is mounted \
                         read-write, so the read-only promise does not cover it",
                        plan.mounts[*index].source.display()
                    ));
                    plan.mounts[*index].writable = true;
                }
                // The same grant at the same mode, asked for twice, is one mount and no
                // comment: `/usr` on the system list and `/usr` named by hand are the
                // same request.
            }
        }
    }
    alias_notes(&mut plan);
    // Shallowest destination first, so a parent is always mounted before something
    // inside it, whichever list the two grants came from.
    plan.mounts.sort_by_key(|mount| {
        (
            mount.destination.components().count(),
            mount.destination.display().to_string(),
        )
    });
    Ok(plan)
}

/// Rule 3: the same host directory mounted read-only at one path and writable at
/// another is a read-only grant that is not read-only.
///
/// Reachable on a Mac (`/private/var/folders/…/T` and `$TMPDIR`), and on a merged-usr
/// Linux where `/bin` and `/usr/bin` are one directory. Nothing is inferred from the
/// shape of the string; [`same_directory`] asks the host.
fn alias_notes(plan: &mut Plan) {
    for index in 0..plan.mounts.len() {
        for other in (index + 1)..plan.mounts.len() {
            let (a, b) = (&plan.mounts[index], &plan.mounts[other]);
            if a.writable == b.writable || !same_directory(&a.source, &b.source) {
                continue;
            }
            plan.notes.push(format!(
                "{} and {} are one directory under two names: the read-only grant is \
                 writable through the other path, so name the one the job actually uses",
                a.describe(),
                b.describe()
            ));
        }
    }
}

/// Whether two host paths are one directory: the same after the lexical clean, or the
/// same once the host has resolved the symlinks.
///
/// The lookup is the whole point on macOS, where `/tmp`, `/var` and `/etc` are symlinks
/// into `/private`, and it is a plain answer elsewhere. A path the host cannot resolve
/// is compared as spelled: "could not tell" is never allowed to become "they are the
/// same", because that would drop a mount.
fn same_directory(a: &Path, b: &Path) -> bool {
    if clean(a) == clean(b) {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// The destination as a runtime keys it: absolute, no `.` or `..`, no doubled or
/// trailing slash.
///
/// Lexical, on purpose: a runtime cleans the destination string before comparing it, and
/// a mount path means the same thing whether or not the directory exists yet — which is
/// the case for a scratch that `gitiup` has not created.
pub fn clean(path: &Path) -> String {
    let text = path.display().to_string();
    let absolute = text.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `gitiup run --execute` gives a step: checkout and scratch both writable.
    fn step(workspace: &str, scratch: &str) -> Spec {
        Spec::new(workspace, scratch).with_writable(workspace)
    }

    fn keys(plan: &Plan) -> Vec<String> {
        plan.mounts
            .iter()
            .map(|mount| mount.destination.display().to_string())
            .collect()
    }

    fn count(plan: &Plan, destination: &str) -> usize {
        at(plan, destination).len()
    }

    /// Every mount at one destination. Exactly one, in any plan this module returns —
    /// which is the whole point, and what `count` asserts.
    fn at<'a>(plan: &'a Plan, destination: &str) -> Vec<&'a Mount> {
        plan.mounts
            .iter()
            .filter(|mount| mount.destination == Path::new(destination))
            .collect()
    }

    #[test]
    fn a_checkout_named_twice_is_mounted_once() {
        // giti-0xi, exactly. Before this module these two grants became
        // `-v /work:/work:ro` and `-v /work:/work:rw`, and the runtime answered
        // `Duplicate mount point: '/work'` — naming neither grant.
        let plan = plan(&step("/work", "/work/.scratch"), &TMPFS_DESTINATIONS)
            .expect("the shape every workflow step uses must not clash");
        assert_eq!(count(&plan, "/work"), 1, "{:?}", keys(&plan));
        let work = at(&plan, "/work")[0];
        assert!(work.writable, "the explicit writable grant wins");
        assert!(
            plan.notes
                .iter()
                .any(|note| note.contains("read-write") && note.contains("read-only promise")),
            "a widened grant has to be said out loud: {:?}",
            plan.notes
        );
    }

    #[test]
    fn a_read_only_workspace_stays_read_only_and_says_nothing() {
        let plan = plan(&Spec::new("/work", "/work/.scratch"), &TMPFS_DESTINATIONS).unwrap();
        let work = at(&plan, "/work")[0];
        assert!(
            !work.writable,
            "nothing asked for the checkout to be writable"
        );
        assert!(plan.notes.is_empty(), "{:?}", plan.notes);
        assert!(
            at(&plan, "/work/.scratch")
                .iter()
                .any(|mount| mount.writable),
            "the scratch is writable at its own path: {:?}",
            keys(&plan)
        );
    }

    #[test]
    fn a_parent_is_mounted_before_anything_inside_it() {
        // The order is not cosmetic: `bwrap` applies its mount arguments in the order
        // given, so mounting `/work` after `/work/sub` buries `sub`. The grants come
        // from both lists here — the checkout writable, a tree inside it read-only — so
        // "reads first, writes second" is not an ordering at all.
        let spec = Spec::new("/work", "/work/.scratch")
            .with_writable("/work")
            .with_read_path("/work/sub");
        let plan = plan(&spec, &TMPFS_DESTINATIONS).unwrap();
        let keys = keys(&plan);
        let at = |want: &str| {
            keys.iter()
                .position(|key| key == want)
                .unwrap_or_else(|| panic!("{want} not mounted: {keys:?}"))
        };
        assert!(at("/work") < at("/work/sub"), "{keys:?}");
        assert!(at("/work") < at("/work/.scratch"), "{keys:?}");
        // And the writable flag survived the reordering, which is the whole point of
        // resolving before sorting.
        assert!(at_plan(&plan, "/work").writable);
        assert!(!at_plan(&plan, "/work/sub").writable);
    }

    fn at_plan<'a>(plan: &'a Plan, destination: &str) -> &'a Mount {
        at(plan, destination)[0]
    }

    #[test]
    fn no_destination_is_mounted_twice_in_any_plan() {
        // The invariant, stated the way the runtime states it: nothing may key twice,
        // however many ways the spec names the same tree.
        let spec = Spec::new("/work", "/tmp/s")
            .with_writable("/work")
            .with_writable("/tmp/s")
            .with_read_path("/work")
            .with_read_path("/work/")
            .with_read_path("/work/.");
        let plan = plan(&spec, &TMPFS_DESTINATIONS).unwrap();
        for destination in keys(&plan) {
            assert_eq!(count(&plan, &destination), 1, "{destination} mounted twice");
        }
        assert_eq!(count(&plan, "/work"), 1);
    }

    #[test]
    fn naming_tmp_itself_is_refused_because_the_scratch_cap_lives_there() {
        // `-v /tmp:/tmp:rw` beside `--tmpfs /tmp:…,size=…` is the other way to lose a
        // run to `Duplicate mount point`, and the scratch *being* /tmp is more common
        // than anyone admits — TMPDIR is /tmp in a great many containers.
        let err = plan(&Spec::new("/work", "/tmp"), &TMPFS_DESTINATIONS).unwrap_err();
        assert!(err.detail().contains("/tmp"), "{err}");
        assert!(err.detail().contains("scratch cap"), "{err}");
        assert!(err.hint().unwrap().contains("/tmp/gitiup-scratch"), "{err}");
        assert_eq!(err.kind(), ErrorKind::Invalid);
        // A scratch inside /tmp is the good case, and keeps its cap.
        plan(
            &Spec::new("/work", "/tmp/gitiup-scratch"),
            &TMPFS_DESTINATIONS,
        )
        .unwrap();
        // And a destination a backend builds itself is refused the same way.
        let err = plan(
            &Spec::new("/work", "/work/.scratch").with_read_path("/proc"),
            &BWRAP_DESTINATIONS,
        )
        .unwrap_err();
        assert!(err.detail().contains("/proc"), "{err}");
        // …but only for the backend that claims it.
        plan(
            &Spec::new("/work", "/work/.scratch").with_read_path("/proc"),
            &TMPFS_DESTINATIONS,
        )
        .unwrap();
    }

    #[test]
    fn destinations_are_compared_the_way_a_runtime_cleans_them() {
        assert_eq!(clean(Path::new("/work/")), "/work");
        assert_eq!(clean(Path::new("/work//./x/")), "/work/x");
        assert_eq!(clean(Path::new("/work/x/../y")), "/work/y");
        assert_eq!(clean(Path::new("/")), "/");
        assert_eq!(
            clean(Path::new("/tmp/gitiup-doctor-99/scratch")),
            "/tmp/gitiup-doctor-99/scratch"
        );
        // `/work/` and `/work` are one address, so they are one mount — not a runtime
        // error two seconds later.
        let plan = plan(
            &Spec::new("/work", "/work/.scratch").with_read_path("/work/"),
            &TMPFS_DESTINATIONS,
        )
        .unwrap();
        assert_eq!(count(&plan, "/work"), 1, "{:?}", keys(&plan));
    }

    #[test]
    fn one_directory_named_two_ways_is_said_loudly_when_the_grants_differ() {
        // The macOS habit: `/var/folders/…/T` and `/private/var/folders/…/T` are one
        // place, so a read-only grant spelled one way is writable spelled the other.
        // Built from a real symlink so the test runs anywhere.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let alias = dir.path().join("alias");
        if std::os::unix::fs::symlink(&real, &alias).is_err() {
            return; // no symlinks on this filesystem; nothing to demonstrate
        }
        let spec = Spec::new("/work", "/work/.scratch")
            .with_read_path(&alias)
            .with_writable(&real);
        let resolved = plan(&spec, &TMPFS_DESTINATIONS).unwrap();
        assert!(
            resolved
                .notes
                .iter()
                .any(|note| note.contains("one directory under two names")),
            "{:?}",
            resolved.notes
        );
        // Same grant on both spellings is not a finding, and is not mentioned.
        let resolved = plan(
            &Spec::new("/work", "/work/.scratch")
                .with_read_path(&alias)
                .with_read_path(&real),
            &TMPFS_DESTINATIONS,
        )
        .unwrap();
        assert!(resolved.notes.is_empty(), "{:?}", resolved.notes);
    }

    #[test]
    fn the_system_read_list_is_not_a_clash_waiting_to_happen() {
        // The list every build needs is mounted on every run, so a clash hiding in it
        // would be a clash on every machine. This is the check that says it is not, on
        // the machine that has the list.
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("checkout");
        std::fs::create_dir_all(&workspace).unwrap();
        let plan = plan(
            &step(
                &workspace.display().to_string(),
                &dir.path().join("scratch").display().to_string(),
            ),
            &TMPFS_DESTINATIONS,
        )
        .unwrap();
        let keys = keys(&plan);
        for key in &keys {
            assert_eq!(count(&plan, key), 1, "{key} mounted twice: {keys:?}");
        }
        assert!(!keys.iter().any(|key| key == "/tmp"), "{keys:?}");
        // Every directory a build needs is still there: de-duplicating mounts must not
        // quietly narrow what a job can read.
        for needed in crate::platform::system_read_only() {
            if std::path::Path::new(needed).exists() {
                assert!(keys.iter().any(|key| key == needed), "{needed} not mounted");
            }
        }
    }

    #[test]
    fn a_mount_is_the_runtime_shape() {
        let mount = Mount {
            source: PathBuf::from("/work"),
            destination: PathBuf::from("/work"),
            writable: false,
        };
        assert_eq!(mount.volume_arg(), "/work:/work:ro");
        assert_eq!(mount.mode(), "ro");
        assert!(
            mount.describe().contains("read-only"),
            "{}",
            mount.describe()
        );
        assert_eq!(
            Mount {
                source: PathBuf::from("/cache"),
                destination: PathBuf::from("/cache"),
                writable: true,
            }
            .volume_arg(),
            "/cache:/cache:rw"
        );
    }

    #[test]
    fn the_plan_lists_what_a_reviewer_is_owed() {
        let plan = plan(&step("/work", "/work/.scratch"), &TMPFS_DESTINATIONS).unwrap();
        let lists = |writable: bool| -> Vec<String> {
            plan.list(writable)
                .split(", ")
                .map(str::to_string)
                .collect()
        };
        assert!(
            lists(true).contains(&"/work/.scratch".to_string()),
            "{:?}",
            lists(true)
        );
        assert!(
            lists(true).contains(&"/work".to_string()),
            "the checkout is writable, and the lists are what a reviewer reads back: {:?}",
            lists(true)
        );
        assert!(
            !lists(false).contains(&"/work".to_string()),
            "…and it is no longer in the read-only one: {:?}",
            lists(false)
        );
        assert_eq!(Plan::default().list(true), "(none)");
    }
}
