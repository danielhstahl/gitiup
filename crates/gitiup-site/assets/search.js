/*
  gitiup docs — search, in one file, with no dependencies.

  Search on a site with no server is a list of strings and a loop over it. The list
  is `search-index.js`, written by `gitiup-site build`, which assigns one global;
  this file reads the `q` query parameter, scores every entry against it, and prints
  the best ones.

  Two choices worth stating:

  * **The index is a script, not `fetch("search-index.json")`.** A page opened from a
    filesystem cannot fetch a sibling file — the browser calls two files in one
    directory different origins — and this site is built to be readable that way
    (it is `gitiup-site build` output, not an Actions-only artifact). A `<script
    src>` has no such rule, so search works from `file://` and from Pages with the
    same bytes.
  * **Nothing here is required to read the docs.** Every page, the sidebar, the
    anchors and the pager are server-rendered HTML; this script only ever runs on
    search.html, and that page says in a `<noscript>` what to do without it.

  Text goes in through `textContent`, never `innerHTML`: the index is built from the
  repository's own markdown, but a search box that can be made to print markup is a
  search box that will eventually be made to.
*/

(function () {
  "use strict";

  var results = document.getElementById("search-results");
  var status = document.getElementById("search-status");
  var box = document.querySelector("input[name=q]");
  if (!results || !status || !box) {
    return;
  }

  var index = window.GITIUP_SEARCH_INDEX || [];
  var LIMIT = 30;

  function query() {
    var params = new URLSearchParams(window.location.search);
    return (params.get("q") || "").trim();
  }

  function tokens(q) {
    // Lowercased words, with the punctuation a docs reader types as part of the
    // word (`--store`, `refs/heads`) kept in: splitting on it would turn `--store`
    // into a search for "store", which matches every page and nothing useful.
    return q
      .toLowerCase()
      .split(/\s+/)
      .filter(function (t) {
        return t.length > 0;
      });
  }

  function count(haystack, needle) {
    var from = 0;
    var found = 0;
    while (true) {
      var at = haystack.indexOf(needle, from);
      if (at < 0) {
        break;
      }
      found += 1;
      from = at + needle.length;
      if (found > 5) {
        break;
      }
    }
    return found;
  }

  function score(entry, words) {
    var heading = entry.heading.toLowerCase();
    var page = entry.page.toLowerCase();
    var text = entry.text.toLowerCase();
    var total = 0;
    for (var i = 0; i < words.length; i++) {
      var word = words[i];
      var inHeading = count(heading, word);
      var inPage = count(page, word);
      var inText = count(text, word);
      if (inHeading === 0 && inPage === 0 && inText === 0) {
        // Every word has to appear somewhere: a five-word query that matches one
        // word is a list of every page that mentions that word.
        return 0;
      }
      // Exact heading equality is the strongest signal there is: someone searching
      // "exit codes" wants the page whose heading is "The exit codes are the
      // interface", not the page that says "exit" the most.
      if (heading === word || heading.indexOf(word) === 0) {
        total += 12;
      }
      total += inHeading * 6 + inPage * 4 + inText;
    }
    return total;
  }

  function snippet(entry, words) {
    var text = entry.text;
    if (text.length > 260) {
      // Centre the snippet on the first word that actually matched.
      var lower = text.toLowerCase();
      var at = -1;
      for (var i = 0; i < words.length; i++) {
        var found = lower.indexOf(words[i]);
        if (found >= 0 && (at < 0 || found < at)) {
          at = found;
        }
      }
      var start = at > 80 ? at - 60 : 0;
      text = (start > 0 ? "… " : "") + text.slice(start, start + 260) + "…";
    }
    return text;
  }

  function render(entries, words, q) {
    results.textContent = "";
    if (q === "") {
      status.textContent = "Type to search the documentation.";
      return;
    }
    if (entries.length === 0) {
      status.textContent = "Nothing matches “" + q + "”.";
      return;
    }
    status.textContent =
      entries.length === 1
        ? "1 result for “" + q + "”."
        : entries.length + " results for “" + q + "”.";

    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var li = document.createElement("li");

      var link = document.createElement("a");
      link.href = entry.url;
      link.textContent = entry.heading;
      li.appendChild(link);

      var where = document.createElement("span");
      where.className = "where";
      where.textContent = entry.page;
      li.appendChild(where);

      var bit = document.createElement("span");
      bit.className = "snippet";
      bit.textContent = snippet(entry, words);
      li.appendChild(bit);

      results.appendChild(li);
    }
  }

  function run() {
    var q = query();
    var words = tokens(q);
    var scored = [];
    for (var i = 0; i < index.length; i++) {
      var value = score(index[i], words);
      if (value > 0) {
        scored.push({ entry: index[i], value: value, order: i });
      }
    }
    scored.sort(function (a, b) {
      // Index order is the reading order the builder wrote it in, so it is the tie
      // break: quickstart beats an appendix that mentions the same word once.
      if (b.value !== a.value) {
        return b.value - a.value;
      }
      return a.order - b.order;
    });
    var shown = scored.slice(0, LIMIT).map(function (row) {
      return row.entry;
    });
    render(shown, words, q);
  }

  function submit() {
    var url = new URL(window.location.href);
    url.searchParams.set("q", box.value.trim());
    window.history.replaceState({}, "", url);
    run();
  }

  box.value = query();
  box.addEventListener("input", submit);
  var form = box.form;
  if (form) {
    form.addEventListener("submit", function (event) {
      // The form's own action would navigate; that is fine and correct, but typing
      // should search as it goes, so intercept the submit and update in place.
      event.preventDefault();
      submit();
    });
  }
  run();
})();
