//! The command line: `build`, `check`, `help`, `version`.
//!
//! Four commands and eight flags, parsed by hand. That is the same choice the CLI
//! crate makes and for the same reason (`crates/gitiup/Cargo.toml` says it): a
//! surface this small does not need an argument-parsing dependency, and hand-parsing
//! keeps the meaning of every flag in one readable file. The meanings worth stating:
//!
//! * **`build` writes, `check` decides.** `build` never refuses to write a site
//!   because a link is dead — the site is still more useful than nothing, and the
//!   warnings go to stderr. `check` writes nothing and exits non-zero on the same
//!   findings, which is the half that belongs in CI.
//! * **Nothing is fetched.** No flag pulls a theme, a font or a base URL from the
//!   network; `--source-url` only names a URL that appears in the output.
//! * **The exit codes are the interface**, as everywhere else here: `0` did the
//!   work, `1` found problems, `2` was asked for something impossible, `3` could
//!   not read or write a file.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

use crate::config::Config;
use crate::error::Error;

/// Everything worked.
pub const EXIT_OK: i32 = 0;
/// `check` found something wrong with the docs.
pub const EXIT_PROBLEM: i32 = 1;
/// Unknown flag, unknown command, or inputs that describe no site.
pub const EXIT_USAGE: i32 = 2;
/// A file could not be read or written.
pub const EXIT_IO: i32 = 3;

/// Flags that take a value.
const VALUED: &[&str] = &[
    "root",
    "out",
    "title",
    "tagline",
    "source-url",
    "source-ref",
    "base-path",
    "site-url",
];

/// Flags that do not.
const SWITCHES: &[&str] = &["help", "quiet", "version"];

const USAGE: &str = "\
gitiup-site — the repository's markdown, built into a static site

USAGE:
    gitiup-site <COMMAND> [FLAGS]

COMMANDS:
    build       Render docs/ into a directory of HTML (default: ./_site)
    check       Render everything and report broken links and anchors; write nothing
    help        Print this help
    version     Print the version

FLAGS:
    --root <dir>          The checkout to read (default: the nearest ancestor with a
                          Cargo.toml and a docs/)
    --out <dir>           Where to write the site (default: <root>/_site)
    --title <name>        The site name in the header and every <title> (default: gitiup)
    --tagline <line>      The line under the site name (default: README.md's first line)
    --source-url <url>    Repository to link for anything that is not a page
                          (default: the workspace Cargo.toml's `repository`)
    --source-ref <ref>    The ref those repository links name (default: main)
    --base-path <path>    Where the site is served from, / or /gitiup/ — used only by
                          404.html, which cannot know its own depth
    --site-url <url>      Absolute URL of the published site; when set, also writes
                          sitemap.xml and robots.txt
    --quiet               Say nothing on success
    --help                Print this help

EXIT CODES:
    0  built / nothing wrong
    1  `check` found problems
    2  usage, or a --root with no docs/
    3  a file could not be read or written

The build touches no network and needs no server: it reads a checkout and writes a
directory. Publish that directory anywhere static — Actions Pages, a bucket, a
`gh-pages` branch — with `.github/workflows/pages.yml` as one example.";

/// The parsed command line.
#[derive(Debug, Default)]
pub struct Flags {
    values: BTreeMap<String, String>,
    switches: BTreeSet<String>,
    positional: Vec<String>,
}

impl Flags {
    /// A valued flag, if given.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Whether a switch was given.
    pub fn switched(&self, name: &str) -> bool {
        self.switches.contains(name)
    }

    /// The positional arguments, in order.
    pub fn positionals(&self) -> &[String] {
        &self.positional
    }
}

/// Parse `args` (without the program name).
///
/// Errors are returned as a string rather than an error value because every parse
/// failure is the same thing: say the sentence, print the usage, exit 2.
pub fn parse(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;
        let Some(long) = arg.strip_prefix("--") else {
            flags.positional.push(arg.to_string());
            continue;
        };
        let (name, inline) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (long, None),
        };
        if SWITCHES.contains(&name) {
            if inline.is_some() {
                return Err(format!("--{name} takes no value"));
            }
            flags.switches.insert(name.to_string());
            continue;
        }
        if !VALUED.contains(&name) {
            return Err(format!("unknown flag --{name}"));
        }
        let value = match inline {
            Some(value) => value,
            None => {
                let Some(next) = args.get(index) else {
                    return Err(format!("--{name} needs a value"));
                };
                index += 1;
                next.clone()
            }
        };
        flags.values.insert(name.to_string(), value);
    }
    Ok(flags)
}

/// The config the flags describe, or the message saying why they describe none.
pub fn config(flags: &Flags) -> Result<Config, String> {
    let mut cfg = match flags.value("root") {
        Some(root) => Config::new(PathBuf::from(root)),
        None => Config::discover(&std::env::current_dir().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
    };
    if let Some(out) = flags.value("out") {
        cfg.out = PathBuf::from(out);
    }
    if let Some(title) = flags.value("title") {
        cfg.title = title.to_string();
    }
    if let Some(tagline) = flags.value("tagline") {
        cfg.tagline = tagline.to_string();
    }
    if let Some(url) = flags.value("source-url") {
        cfg.source_url = url.trim_end_matches('/').to_string();
    }
    if let Some(reference) = flags.value("source-ref") {
        cfg.source_ref = reference.to_string();
    }
    if let Some(path) = flags.value("base-path") {
        cfg.base_path = path.to_string();
    }
    if let Some(url) = flags.value("site-url") {
        cfg.site_url = Some(url.to_string());
    }
    Ok(cfg)
}

/// Run one invocation. Returns the process exit code.
///
/// Takes the two streams so the tests can assert on the report instead of on what
/// the test harness's stdout happens to capture.
pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let flags = match parse(args) {
        Ok(flags) => flags,
        Err(message) => {
            let _ = writeln!(stderr, "error: {message}");
            let _ = writeln!(stderr, "run `gitiup-site help` for the flags");
            return EXIT_USAGE;
        }
    };

    if flags.switched("help") || flags.positionals().is_empty() {
        let _ = writeln!(stdout, "{USAGE}");
        return EXIT_OK;
    }
    if flags.switched("version") {
        let _ = writeln!(stdout, "gitiup-site {}", env!("CARGO_PKG_VERSION"));
        return EXIT_OK;
    }

    let command = flags.positionals()[0].as_str();
    match command {
        "help" => {
            let _ = writeln!(stdout, "{USAGE}");
            EXIT_OK
        }
        "version" => {
            let _ = writeln!(stdout, "gitiup-site {}", env!("CARGO_PKG_VERSION"));
            EXIT_OK
        }
        "build" | "check" => match config(&flags) {
            Err(message) => {
                let _ = writeln!(stderr, "error: {message}");
                EXIT_USAGE
            }
            Ok(cfg) => match command {
                "build" => build(cfg, flags.switched("quiet"), stdout, stderr),
                _ => check(cfg, flags.switched("quiet"), stdout, stderr),
            },
        },
        other => {
            let _ = writeln!(stderr, "error: unknown command `{other}`");
            let _ = writeln!(stderr, "run `gitiup-site help` for the commands");
            EXIT_USAGE
        }
    }
}

fn build(cfg: Config, quiet: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match crate::build(&cfg) {
        Ok(summary) => {
            if !quiet {
                let _ = writeln!(
                    stdout,
                    "built {} pages ({} files, {} bytes) into {}",
                    summary.pages,
                    summary.files,
                    summary.bytes,
                    summary.out.display()
                );
            }
            report_warnings(&summary.problems, stderr);
            EXIT_OK
        }
        Err(error) => fail(error, stderr),
    }
}

fn check(cfg: Config, quiet: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match crate::check(&cfg) {
        Ok(problems) => {
            if problems.is_empty() {
                let _ = writeln!(
                    stdout,
                    "no problems: every internal link lands on a page and a heading that exist"
                );
                return EXIT_OK;
            }
            if !quiet {
                for problem in &problems {
                    let _ = writeln!(stdout, "{problem}");
                }
            }
            let _ = writeln!(
                stderr,
                "found {} problem{} in the docs",
                problems.len(),
                if problems.len() == 1 { "" } else { "s" }
            );
            EXIT_PROBLEM
        }
        Err(error) => fail(error, stderr),
    }
}

/// `build` does not refuse a site over a dead link, but it says so.
fn report_warnings(problems: &[crate::Problem], stderr: &mut dyn Write) {
    for problem in problems {
        let _ = writeln!(stderr, "warning: {problem}");
    }
}

fn fail(error: Error, stderr: &mut dyn Write) -> i32 {
    let code = match error {
        Error::Io { .. } => EXIT_IO,
        Error::Config(_) => EXIT_USAGE,
    };
    let _ = writeln!(stderr, "error: {error}");
    code
}
