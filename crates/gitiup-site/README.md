# gitiup-site

The repository's markdown, built into a static site: `docs/` and `docs/adr/` in, a
directory of HTML out. No server, no JavaScript build step, no network at build time.

The user-facing write-up is [docs/site.md](../../docs/site.md) — what becomes a page,
the link and anchor rules, how to publish it, and why the heading anchors are GitHub's
rather than this crate's invention. This file is about why it is a crate.

## Why a crate, and not a script or a site generator

The docs here are not prose that happens to be in the repository; they are part of it.
[`docs/policy.md`](../../docs/policy.md) is executed line by line by
[`policy_doc_cli.rs`](../gitiup/tests/policy_doc_cli.rs), the quickstart by
[`quickstart_doc_cli.rs`](../gitiup/tests/quickstart_doc_cli.rs), and the guides link to
each other by heading anchor with the ids GitHub gives a heading. Publishing them
means keeping two promises:

* **every internal link lands.** An anchor whose heading has since been reworded is
  invisible in a diff and is only found by a reader following it into nothing.
  `gitiup-site check` renders the whole tree in memory and refuses on a dead link, a
  dead anchor, a page with no title, or markup smuggled into a doc. `build` warns;
  `check` is the CI half.
* **the output is a function of the tree.** Sorted discovery, fixed key order, no
  clock, no absolute paths in the output: two builds of one commit are byte-identical
  ([`tests/build_site.rs`](tests/build_site.rs) does exactly that diff).

Neither promise is portable to a generic site generator, and both are testable in
Rust alongside the code they describe. That is what a crate buys.

## The dependency, and its boundary

`pulldown-cmark` is the markdown parser, and it is the only external dependency: a
CommonMark parser plus the GFM tables these docs are full of is a specification, not a
decision this project should re-derive. What it is *not* is a trust boundary — nothing
here feeds a digest, a signature or a merge decision, so a wrong render can only print
a page badly. That is why the dependency lives in this crate and nowhere else: the CLI,
the host crates and the format crate keep their near-empty dependency lists
([`gitiup/tests/cli_hygiene.rs`](../gitiup/tests/cli_hygiene.rs),
[`gitiup-attest/tests/dependency_hygiene.rs`](../gitiup-attest/tests/dependency_hygiene.rs)),
and a docs builder does not get to make that promise for anyone else.

Everything else is written here, because each one is small and each one is the kind of
thing that goes wrong quietly: the GitHub-shaped heading slug (`md.rs`), the
source-tree-to-site link rewriting and its ledger of dead links (`links.rs`), the
reading order (`nav.rs`), the page shell (`template.rs`), the section search index
(`search.rs`).

## Running it

```sh
cargo run --locked --release -p gitiup-site -- build --out _site   # write the site
cargo run --locked --release -p gitiup-site -- check               # render, report, write nothing
cargo test --locked -p gitiup-site                                 # the rules above, as tests
```

`--help` is the whole flag list. Publishing is
[`.github/workflows/pages.yml`](../../.github/workflows/pages.yml): check on the pull
request, build and publish on the default branch.

## Modules

| file | what it owns |
|------|--------------|
| `tree.rs` | which files are pages, and what each is called in the output |
| `md.rs` | markdown → HTML, heading ids, the escaping that refuses raw HTML |
| `links.rs` | where each href goes — another page, the repository, or elsewhere — and the list of links that go nowhere |
| `nav.rs` | the reading order, and the sidebar built from it |
| `template.rs` | the one page shell: header, sidebar, article, "on this page", pager |
| `search.rs` | the section index `search.html` reads |
| `paths.rs` | site-relative `/`-separated paths: resolve, relativize, depth |
| `cli.rs` | `build`, `check`, `help`, `version`, and what each exit code means |
