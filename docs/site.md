# The docs site

Everything in `docs/` and [`docs/adr/`](adr/) is read in a browser far more
often than in an editor, so it is published as one: a directory of static HTML built
by [`gitiup-site`](../crates/gitiup-site/Cargo.toml). There is no site generator to
install, no theme to download, no server to run, and no network needed to build it —
the input is this checkout and the output is a directory.

Two things make this more than a markdown converter, and both are the reason it is a
crate in the workspace rather than a shell script in `ci/`:

* **The docs' own links are checked.** Every guide links every other guide by heading
  anchor, and an anchor whose heading has since been reworded is invisible in a diff —
  you only find it by following it and landing on nothing. `gitiup-site check` renders
  the whole tree in memory and refuses if any internal link misses, so that drift is a
  red build rather than a reader's dead end. It is run on every pull request by
  [`.github/workflows/pages.yml`](../.github/workflows/pages.yml).
* **The build is reproducible**, in the sense this repository uses everywhere else
  ([what a build has to promise](reproducibility.md)): sorted discovery, fixed key
  order, no clock, no absolute paths in the output. Two builds of one commit are
  byte-identical, which is what lets the deploy job publish the artifact of the build
  it just ran and say so.

## Build it, and read it

```sh
cargo build --release --locked -p gitiup-site
./target/release/gitiup-site build --out _site
python3 -m http.server -d _site
```

```console
$ gitiup-site build --out _site
built 29 pages (34 files, 1517544 bytes) into _site
```

The output is ordinary files: open `_site/index.html` in a browser and it works,
search included, without a web server in front of it. That is deliberate — the same
directory is what gets published to Pages, dropped into a bucket, or handed to a
colleague over a share, and it behaves the same in all four places.

The commands are `build` (write the site) and `check` (render everything, write
nothing, report). `build` never refuses to write a site because a link is dead — a
site with one dead link is still more useful than no site — but it prints a
`warning:` line for each one on stderr. `check` is the half that exits non-zero.

| exit | meaning |
|------|---------|
| **0** | built, or nothing wrong |
| 1 | `check` found problems: a dead link, a dead anchor, a page with no title, markup in a doc |
| 2 | usage, or a `--root` with no `docs/` in it |
| 3 | a file could not be read or written |

Those are this tool's own, not [the attestation verdict codes](verification.md#the-exit-codes-are-the-interface):
nothing here is a verdict about a proof.

| flag | what it does |
|------|--------------|
| `--root <dir>` | the checkout to read; defaults to the nearest ancestor with a `Cargo.toml` and a `docs/` |
| `--out <dir>` | where to write; defaults to `<root>/_site`, and is **removed** before each build |
| `--title`, `--tagline` | the name and the line in the header |
| `--source-url`, `--source-ref` | where links to files that are not pages point; default: the workspace manifest's `repository` |
| `--base-path <path>` | where the site is served from (`/gitiup/`); used by `404.html` alone |
| `--site-url <url>` | the published URL; when given, also writes `sitemap.xml` and `robots.txt` |
| `--quiet` | say nothing on success, for a CI job that reads the exit code |

## What becomes a page

One rule, too blunt to need a manifest: **every `*.md` under `docs/`, plus the
checkout's `README.md`, is a page**, with `README.md` becoming `index.html` in its own
directory so a directory URL serves it. Hidden directories and the fixture
generators' `__pycache__` are skipped. Nothing is listed in a config file, so a page
cannot be forgotten — the failure mode of a page list is a guide that quietly stops
being published.

Inside that rule:

| input | output |
|-------|--------|
| `README.md` | `index.html` — the front page |
| `docs/quickstart.md` | `docs/quickstart.html` |
| `docs/adr/README.md` | `docs/adr/index.html` |
| `docs/adr/fixtures/policy-v1/README.md` | `docs/adr/fixtures/policy-v1/index.html` |
| a link to `cases.json`, `../../crates/…`, or any file that is not a page | a link into the repository, at `--source-url`/`--source-ref` |
| a link to another page, `../quorum.md#the-ladder` | `../quorum.html#the-ladder` |

The **heading anchors are GitHub's**: lowercase, punctuation dropped, every whitespace
character turned into `-`, duplicate headings suffixed `-1`, `-2`. That is not a
stylistic choice — the existing docs were written against the ids GitHub gives a
heading when it renders a `.md`, including the double dash an em dash between two
spaces produces (`## D5 — Authority` becomes `d5--authority`). Diverging from it would
break the docs' own cross-links only in the built site, where nobody looks until a
reader does.

Raw HTML in a doc is **escaped, not passed through**, and `check` counts it. A docs
pull request is not a trusted input, and a site built from the repository should not be
a place where any contributor can execute script on it.

A link that goes nowhere is a finding, not a silent attribute: a missing file, a
heading that no longer has the anchor something else links to, a same-page anchor to a
section that was renamed. This page's own first run found three of them in `docs/` — a
`federation.md` link to a `D5` heading that lives in
[ADR-0005](adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md), a
`verification.md` anchor left behind when a heading's flag was rewritten from
`| attest` to `--attest`, and four fixture READMEs one directory short of the ADRs
they document.

## Order, and why it is written down

Which files exist is a rule; which order they are shown in is a judgement about the
reader, and it is written out as a list in
[`src/nav.rs`](../crates/gitiup-site/src/nav.rs): the quickstart first, then what a
machine can promise, then running and proving a job, then the trust questions, then
federation and quorum, then the decision records.

A hand-written list can rot quietly, so a test in
[`tests/navigation.rs`](../crates/gitiup-site/tests/navigation.rs) compares the list
against `docs/` in both directions: no guide missing from the list, and no name in the
list that `docs/` no longer has. A page that is not in the list is still built and
still linked — it just reads last — so the failure is a warning to whoever added it,
not a page nobody can find.

## Search

`search.html` reads `search-index.js`, written by the same build: one entry per
**section**, with the section's anchor in its URL, so a hit for "quorum verdict exit
codes" lands on the section that discusses them rather than the top of a 90 KB page.
The index is a script and not a `.json` because a page opened from a filesystem is not
allowed to fetch its neighbour, and this site is meant to be readable that way. Search
is the only page that loads JavaScript; every other page, the sidebar, the anchors and
the pager are server-rendered HTML, and `search.html` says what to do without it.

## Adding a page

1. Write the markdown under `docs/`. Link other pages by relative path and anchor the
   way the existing pages do — the anchors you write have to match the headings you
   link to, and that is checked.
2. Put its file stem (without `.md`) in `nav::GUIDES` in
   [`src/nav.rs`](../crates/gitiup-site/src/nav.rs), where it belongs in the reading
   order. Skip this and the page still works; the test says so.
3. Run it:

```sh
cargo run -p gitiup-site -- check
cargo run -p gitiup-site -- build --out _site
```

`check` printing `no problems` is the thing CI asserts. The rest — the builder's own
suite, the real docs built twice and compared byte for byte, every href in the built
output resolved against the files on disk — is
[`crates/gitiup-site/tests/`](../crates/gitiup-site/tests/build_site.rs).

## Publishing

[`.github/workflows/pages.yml`](../.github/workflows/pages.yml) runs `check` on every
pull request, builds the site on the default branch, and publishes the directory as a
GitHub Pages artifact. The same command publishes anywhere else static — the output of
`gitiup-site build --out site/` is what an `s3 sync` or a `gh-pages` branch push needs,
and nothing in the site assumes it was built by Actions.

That is the same shape as the rest of this project's story about forges: the
publishing target is a parameter, not a dependency.
