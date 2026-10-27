//! The machine-identity passes: paths and identity.
//!
//! These are the two rules where "what differs between two machines" is not a
//! formatting accident but a *fact about the machine* — where the checkout landed,
//! what the host is called, which uid the runner account has. The placeholder
//! vocabulary says which kind of thing was hidden, so a normalised log still reads
//! as a description of a build rather than as noise.
//!
//! Paths are the subtle ones. The naive rule — "replace `/tmp` and the workspace
//! with a placeholder" — does not converge, because one machine's build directory
//! is another machine's temporary directory: GitHub puts a workspace under
//! `/home/runner/work/<repo>/<repo>`, a container runner puts it in
//! `/tmp/build-4f9c1a07`, and no placeholder chosen per-root can agree with the
//! other. So the rule anchors on the *project*, not the root: whichever absolute
//! path a log contains, the first recognised project directory (`target`, `build`,
//! `dist`, …) names the boundary, and everything before it is `<build>`.

use crate::grammar::{self as g, ph};
use crate::values::replace_all;

/// Directory names that mark "this is the project, this is what the build wrote".
///
/// Anything before one of these is root material — a workspace path, a temp dir, a
/// mount point — and is the part that legitimately differs between two machines
/// running the same workflow.
const ANCHORS: &[&str] = &[
    "target",
    "build",
    "dist",
    "out",
    "node_modules",
    "site-packages",
    "_site",
    "public",
    "vendor",
    ".cache",
];

/// Roots, each with the placeholder it maps to. Longest match wins.
const ROOTS: &[(&str, &str)] = &[
    ("/private/var/folders", ph::TMP),
    ("/var/folders", ph::TMP),
    ("/private/var/tmp", ph::TMP),
    ("/private/tmp", ph::TMP),
    ("/var/tmp", ph::TMP),
    ("/run/user", ph::TMP),
    ("/tmp", ph::TMP),
    ("$RUNNER_TEMP", ph::TMP),
    ("${RUNNER_TEMP}", ph::TMP),
    ("$TMPDIR", ph::TMP),
    ("${TMPDIR}", ph::TMP),
    ("$TMP", ph::TMP),
    ("${TMP}", ph::TMP),
    ("/home/runner/work", ph::BUILD),
    ("/github/workspace", ph::BUILD),
    ("/runner/workspace", ph::BUILD),
    ("$GITHUB_WORKSPACE", ph::BUILD),
    ("${GITHUB_WORKSPACE}", ph::BUILD),
    ("$WORKSPACE", ph::BUILD),
    ("${WORKSPACE}", ph::BUILD),
    ("/workspace", ph::BUILD),
    ("/build", ph::BUILD),
    ("/Users", ph::HOME),
    ("/home", ph::HOME),
    ("/root", ph::HOME),
    ("$HOME", ph::HOME),
    ("${HOME}", ph::HOME),
];

/// Bytes a path may contain.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'-' | b'.' | b'/' | b'$' | b'{' | b'}' | b'+' | b'~'
        )
}

/// Where a path run may start.
///
/// Stricter than [`g::token_start`]: a run must not begin straight after `<`, `>`,
/// `:` or `=`, which keeps a URL (`https://host/path`) and a `host:/path` scp
/// destination out of the rule, and — crucially for idempotence — keeps a path
/// already rewritten to `<build>/…` from being rewritten again.
fn path_start(bytes: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    !matches!(
        bytes[i - 1],
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'_'
            | b'.'
            | b'-'
            | b'/'
            | b'<'
            | b'>'
            | b':'
            | b'@'
            | b'#'
    )
}

/// `Path`: machine-specified roots and generated components.
pub(crate) fn paths(line: &str) -> Option<String> {
    replace_all(line, |bytes, i| {
        if !path_start(bytes, i) {
            return None;
        }
        let mut end = i;
        while bytes.get(end).is_some_and(|b| path_byte(*b)) {
            end += 1;
        }
        if end == i {
            return None;
        }
        let run = std::str::from_utf8(&bytes[i..end]).ok()?;
        // Trim trailing punctuation that was prose, not path: `see /tmp/x.`.
        let run = run.trim_end_matches(['.', ',', ':', ';', ')']);
        let rewritten = rewrite_path(run)?;
        (rewritten != run).then_some((rewritten, run.len()))
    })
}

/// One path, rewritten. `None` when there is nothing machine-specific in it.
fn rewrite_path(run: &str) -> Option<String> {
    let (root, placeholder, rest) = match_root(run)?;
    let mut components: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    // The project anchor wins over the root: `/tmp/build-x/target/debug/gitiup`
    // and `/home/runner/work/x/x/target/debug/gitiup` are the same artifact path
    // as far as a rerun is concerned.
    if let Some(index) = components.iter().position(|c| {
        ANCHORS
            .iter()
            .any(|anchor| anchor.eq_ignore_ascii_case(c.trim_end_matches('.')))
    }) {
        let tail = components[index..]
            .iter()
            .map(|c| collapse_component(c))
            .collect::<Vec<_>>()
            .join("/");
        return Some(format!("{}/{tail}", ph::BUILD));
    }
    // GitHub Actions checks a repository out at `<runner-root>/work/<repo>/<repo>`
    // — the repo name twice, a convention and not content. Dropping it is what makes
    // that layout say the same thing as any other checkout directory.
    if root == "/home/runner/work" {
        components = components.iter().skip(2).copied().collect();
    }
    // A path that says nothing beyond "where this machine put the checkout" is one
    // fact, whichever directory it was: GitHub's `…/work/<repo>/<repo>`, a
    // container's `/tmp/build0a9f`, a `$GITHUB_WORKSPACE` nobody expanded. Without
    // this two machines agree about every path *inside* the workspace and disagree
    // about the workspace itself, which is the worst of both.
    if placeholder == ph::TMP
        && !components.is_empty()
        && components
            .iter()
            .all(|component| g::looks_generated(component))
    {
        return Some(ph::BUILD.to_string());
    }
    let tail = components
        .iter()
        .map(|c| collapse_component(c))
        .collect::<Vec<_>>()
        .join("/");
    if tail.is_empty() {
        return Some(placeholder.to_string());
    }
    // Nothing to gain if nothing was rewritten.
    let rebuilt = format!("{placeholder}/{tail}");
    (rebuilt != run).then_some(rebuilt)
}

/// The longest matching root, as `(matched root, placeholder, remainder)`.
///
/// `("", placeholder, whole)` is the *variable* case, which only matches a
/// recognised `$NAME`. A run with no root at all (`./target/debug/x`,
/// `relative/path`) is `None` — relative paths carry no machine identity, and
/// rewriting them would only lose information.
fn match_root(run: &str) -> Option<(String, &'static str, String)> {
    let mut best: Option<(&str, &str)> = None;
    for (root, placeholder) in ROOTS {
        let matched = run == *root
            || run
                .strip_prefix(*root)
                .is_some_and(|rest| rest.starts_with('/'));
        if matched && best.is_none_or(|(previous, _)| root.len() > previous.len()) {
            best = Some((root, placeholder));
        }
    }
    if let Some((root, placeholder)) = best {
        return Some((
            root.to_string(),
            placeholder,
            run[root.len()..].trim_start_matches('/').to_string(),
        ));
    }
    // A variable this build does not know is left exactly as written: guessing
    // that `$SOME_DIR` is a temp dir would hide a real path.
    None
}

/// A generated-looking component becomes `<rand>`, so a random build directory
/// suffix cannot move a digest.
fn collapse_component(component: &str) -> String {
    // Keep an extension attached to a generated name, but only when the name part
    // is what looks generated: `foo-a1b2c3d4.log` → `<rand>.log` keeps the fact
    // that it is a log.
    if g::looks_generated(component) {
        return ph::RAND.to_string();
    }
    if let Some((stem, ext)) = component.split_once('.')
        && !ext.contains('.')
        && ext.len() <= 5
        && ext.bytes().all(|b| b.is_ascii_alphabetic())
        && g::looks_generated(stem)
    {
        return format!("{}.{}", ph::RAND, ext);
    }
    component.to_string()
}

// ------------------------------------------------------------- identity ---

/// `uid=`/`gid=`/`pid=`-style assignments, with the parenthesised name `id` prints.
const ID_LABELS: &[&str] = &[
    "uid",
    "gid",
    "euid",
    "egid",
    "groups",
    "pid",
    "ppid",
    "tid",
    "thread-id",
    "session-id",
];

/// Labels whose value is a user name.
const USER_LABELS: &[&str] = &["user", "username", "login", "account", "whoami"];

/// Labels whose value is a host name.
const HOST_LABELS: &[&str] = &[
    "host",
    "hostname",
    "runner",
    "node",
    "agent",
    "worker",
    "instance",
    "build-host",
];

/// Words that mean "this line is about which machine ran it".
///
/// A hostname is invisible without context — `build-03` and `main.rs` are the same
/// shape — so bare hostname rewriting only happens on a line that says what it is
/// labelling. Everything else about host identity is a labelled field, or `user@`
/// before an `@`, which need no context.
const HOST_HINTS: &[&str] = &[
    "host",
    "hostname",
    "runner",
    "node",
    "agent",
    "worker",
    "instance",
    "ssh",
    "connected",
    "login",
    "user",
    "uid",
    "gid",
    "id ",
    "whoami",
    "uname",
    "kubectl",
    "@",
];

/// `Identity`: hostnames, user names and numeric ids.
pub(crate) fn identity(line: &str, host_context: bool) -> Option<String> {
    let mut current = user_at_host_rule(line);
    current = id_assignments(&current);
    current = labelled(&current, USER_LABELS, ph::USER);
    current = labelled(&current, HOST_LABELS, ph::HOST);
    // An `ls -l` row is about files, not hosts: its mode column is a hostname
    // look-alike (`drwxr-xr-x`), so the columns get their own rule instead.
    if host_context && !g::ls_row(&current) {
        current = bare_hosts(&current);
    }
    current = ls_columns(&current);
    (current != line).then_some(current)
}

/// Whether the line is about machine identity (see [`HOST_HINTS`]).
pub(crate) fn host_context(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    HOST_HINTS.iter().any(|hint| lower.contains(hint))
}

/// `user@host` → `<user>@<host>`, on both sides of any separator.
fn user_at_host_rule(line: &str) -> String {
    replace_all(line, |bytes, i| {
        let (len, user_len) = g::user_at_host(bytes, i)?;
        let value = std::str::from_utf8(&bytes[i..i + len]).ok()?;
        // A `$HOSTNAME`-style value after the `@` is already a placeholder.
        if value[user_len + 1..].starts_with('$') {
            return None;
        }
        Some((format!("{}@{}", ph::USER, ph::HOST), len))
    })
    .unwrap_or_else(|| line.to_string())
}

/// `uid=1000(runner) gid=1000(runner) groups=1000(runner)` → placeholders.
fn id_assignments(line: &str) -> String {
    replace_all(line, |bytes, i| {
        for label in ID_LABELS {
            let len = label.len();
            if !g::starts_case_insensitive(bytes, i, label) {
                continue;
            }
            let mut p = i + len;
            if !matches!(bytes.get(p), Some(b'=') | Some(b':')) {
                continue;
            }
            p += 1;
            let Some((_, mut end)) = g::digit_run(bytes, p) else {
                continue;
            };
            // A list, with the names `id` prints: `1000(runner),27(sudo)`.
            loop {
                if bytes.get(end) == Some(&b'(')
                    && let Some(close) = bytes[end..].iter().position(|b| *b == b')')
                {
                    end += close + 1;
                }
                if bytes.get(end) != Some(&b',') {
                    break;
                }
                match g::digit_run(bytes, end + 1) {
                    Some((_, next)) => end = next,
                    None => break,
                }
            }
            if !g::unit_end(bytes, end) {
                continue;
            }
            let label = std::str::from_utf8(&bytes[i..i + len]).ok()?;
            return Some((format!("{label}={}", ph::ID), end - i));
        }
        None
    })
    .unwrap_or_else(|| line.to_string())
}

/// `label: value` / `label=value` where the value is a user or a host.
fn labelled(line: &str, labels: &[&str], placeholder: &str) -> String {
    replace_all(line, |bytes, i| {
        for label in labels {
            let len = label.len();
            if !g::starts_case_insensitive(bytes, i, label) {
                continue;
            }
            let mut p = i + len;
            if matches!(bytes.get(p), Some(b':') | Some(b'=')) {
                p += 1;
            } else if bytes.get(p) == Some(&b' ') {
                // `as root`, `user root` are worth taking, but only with a space
                // and only for the labels nobody overloads.
                if !matches!(*label, "user" | "login" | "as") {
                    continue;
                }
                p += 1;
            } else {
                continue;
            }
            while bytes.get(p) == Some(&b' ') {
                p += 1;
            }
            let start = p;
            while bytes.get(p).is_some_and(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'$')
            }) {
                p += 1;
            }
            if p == start {
                continue;
            }
            let value = std::str::from_utf8(&bytes[start..p]).ok()?;
            if value.starts_with('<') || value.starts_with('$') {
                // Already a placeholder or a variable reference.
                continue;
            }
            return Some((format!("{label}: {placeholder}"), p - i));
        }
        None
    })
    .unwrap_or_else(|| line.to_string())
}

/// Hostname-shaped tokens on a line that says it is about a host.
fn bare_hosts(line: &str) -> String {
    replace_all(line, |bytes, i| {
        let len = g::hostname_token(bytes, i)?;
        Some((ph::HOST.to_string(), len))
    })
    .unwrap_or_else(|| line.to_string())
}

/// The owner and group columns of an `ls -l` row.
///
/// `ls -l` is not reproducible — mtimes, block sizes and owner names differ — and
/// the contract says do not print it. When a build prints it anyway, placeholdering
/// the owner columns and sorting the block gets a rerun much closer to converging.
fn ls_columns(line: &str) -> String {
    if !g::ls_row(line) {
        return line.to_string();
    }
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return line.to_string();
    }
    let mut out = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        // Owner and group are columns 2 and 3 after the mode and link count, and
        // both are machine identity rather than output.
        out.push_str(if matches!(index, 2 | 3) {
            ph::USER
        } else {
            field
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_anchor_on_the_project_not_the_root() {
        assert_eq!(
            paths("built target/debug/gitiup"),
            None,
            "a relative path carries no machine identity"
        );
        let one = paths("Binary: /home/runner/work/gitiup/gitiup/target/debug/gitiup").unwrap();
        let two = paths("Binary: /tmp/build0a9f/target/debug/gitiup").unwrap();
        assert_eq!(one, two, "the acceptance criterion in one assertion");
        assert_eq!(
            one,
            format!("Binary: {0}/target/debug/gitiup", ph::BUILD),
            "{one}"
        );
    }

    #[test]
    fn temp_and_home_roots() {
        // The anchor wins even under a temp root: the same directory is often
        // printed once as `$RUNNER_TEMP/dist` and once as the expanded path, and
        // both have to land on one placeholder.
        assert_eq!(
            paths("$RUNNER_TEMP/dist").unwrap(),
            format!("{}/dist", ph::BUILD)
        );
        assert_eq!(
            paths("/var/tmp/xyz/out.log").unwrap(),
            format!("{}/xyz/out.log", ph::TMP)
        );
        assert_eq!(
            paths("/home/runner/.cargo/bin/cargo").unwrap(),
            format!("{}/runner/.cargo/bin/cargo", ph::HOME)
        );
        // Generated components collapse, and the project anchor wins over the root
        // that contains it.
        assert_eq!(
            paths("/tmp/tmp.Ab12Cd/target/x").unwrap(),
            format!("{0}/target/x", ph::BUILD)
        );
        assert_eq!(
            paths("/tmp/tmp.Ab12Cd/logs/x").unwrap(),
            format!("{0}/{1}/logs/x", ph::TMP, ph::RAND)
        );
    }

    #[test]
    fn paths_this_build_does_not_name_are_left_alone() {
        for line in [
            "https://example.test/x/y",
            "https://crates.io/api/v1/crates",
            "git@github.com:gitiup/gitiup.git",
            "$SOME_DIR/lib",
            "relative/path/main.rs",
            "/usr/bin/gcc",
        ] {
            assert_eq!(paths(line).as_deref(), None, "{line} should be untouched");
        }
    }

    #[test]
    fn id_and_user_assignment() {
        assert_eq!(
            identity("uid=1001(runner) gid=123(runner) groups=123(runner)", true).unwrap(),
            format!("uid={0} gid={0} groups={0}", ph::ID)
        );
        assert_eq!(
            identity("runner@a6f31c2d7e1f:~$ echo", false).unwrap(),
            format!("{}@{}:~$ echo", ph::USER, ph::HOST)
        );
        assert_eq!(
            identity("user: runner", false).unwrap(),
            format!("user: {}", ph::USER)
        );
        assert_eq!(
            identity("hostname: build-03.internal", false).unwrap(),
            format!("hostname: {}", ph::HOST)
        );
        assert_eq!(
            identity("host build-03.internal", true).unwrap(),
            format!("host {}", ph::HOST)
        );
    }

    #[test]
    fn ls_owner_columns_are_placeholders() {
        let row = "-rw-r--r--  1 alice wheel 1536 Jan  1  2020 README.md";
        assert_eq!(
            ls_columns(row),
            format!("-rw-r--r-- 1 {0} {0} 1536 Jan 1 2020 README.md", ph::USER)
        );
        assert_eq!(ls_columns("total 8"), "total 8");
    }
}
