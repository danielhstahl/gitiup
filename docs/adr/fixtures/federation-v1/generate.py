#!/usr/bin/env python3
"""Reference implementation of what a mirror may carry (ADR-0005).

Standard library only, and deliberately a *second* implementation: the two tickets
this feeds — `giti-g5c.2` (`gitiup fetch|push`) and `giti-g5c.3`
(`gitiup attest import`) — must agree on which namespaces travel, which never do, and
what "the closure of a proof" contains. Left to themselves they will not: one will copy
`refs/gitiup/**` because it is one prefix, the other will import an attestation without
its verdict because that is the ref it was asked for. Every rule implemented here is
quoted from
../0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md (D1, D2, D5, D7, D8, D9, D10).

There is **no crypto here on purpose**. Byte identity, signatures and digests are
already decided and already have vectors
([`../change-v1/`](../change-v1/), [`../selection-v1/`](../selection-v1/),
[`../policy-v1/`](../policy-v1/)); what this set checks is *scope*: which records a copy
must contain, which it must refuse, and with which token. Records are therefore
identified by a short name and their citations are given as fields — the same citations
the real records carry as signed members (`round_digest`, `roster_digest`,
`policy_digest`, `previous_digest`, `attempts.previous`).

    python3 generate.py            # print the tables, rewrite the vectors
    python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
    python3 generate.py --selftest # closure properties, budgets, the refusal table
    python3 generate.py --check-ad # fail if the ADR's tables and this data disagree

The last one is the point: a table in prose is a suggestion, and
`docs/adr/README.md` says so.
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADR = os.path.join(HERE, os.pardir, os.pardir,
                   "0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md")

GENESIS = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

# ---------------------------------------------------------------------------
# D10: the refusal table. Every token this file can emit, with the exit code the
# ADR assigns it. `--check-ad` proves the ADR's table says the same.
# ---------------------------------------------------------------------------
TOKEN_EXIT = {
    "not_portable": 6,
    "no_arbitration_here": 6,
    "read_only": 6,
    "diverged": 6,
    "digest_mismatch": 8,
    "not_canonical": 8,
    "same_ref": 6,
    "binding_mismatch": 8,
    "bad_signature": 7,
    "signer_untrusted": 6,
    "revoked_key": 6,
    "tier_not_allowed": 6,
    "policy_history_missing": 6,
    "expired": 6,
    "closure_incomplete": 6,
    "subject_missing": 6,
    "no_commitment": 6,
    "mirror_may_not_prune_by_age": 6,
    "eviction_needs_source": 6,
    "gc_record_not_instruction": 6,
    "origin_provenance_required": 6,
    "unlisted_mirror": 6,
    "closure_budget_records": 6,
    "closure_budget_depth": 6,
    "closure_budget_bytes": 6,
    "policy_chain_too_long": 6,
    "field_unknown": 6,
}

# D10 budgets. The vectors exercise these at a scaled-down value (see `--selftest`)
# so that a case does not need four thousand records to prove the bound works.
BUDGETS = {"records": 4096, "depth": 8, "policy_chain": 64, "bytes": 1 << 30}

# ---------------------------------------------------------------------------
# D1 / D2: the portability table.
#
# `display` is the first cell of the ADR's D1 table, verbatim, so `--check-ad` can
# prove the prose and this data are one fact and not two.
#
#   class    proof    a signed record: the unit of copying is record + advertisement
#            pointer  a store's live state; a reader may resolve one, never copy one
#            state    arbitration state, whose meaning is "as of now"
#            local    this store's own audit trail or furniture
#            code     a git object: a proof's subject, portable only with the code
#            foreign  out of this ADR's scope (git's own business)
# ---------------------------------------------------------------------------
ROWS = [
    {
        "display": "`refs/attestations/<subject>/<digest>` → `kv/attestation/<hex>`",
        "class": "proof", "portable": True, "kind": "attestation",
        "note": "the proof itself; its subject must be reachable or excused",
    },
    {
        "display": "`refs/changes/<id>/attempt/<n>` → `kv/change/<hex>`",
        "class": "proof", "portable": True, "kind": "change",
        "note": "immutable, create-only, and `chg-…` re-derives identically anywhere",
    },
    {
        "display": "`refs/changes/<id>/head`",
        "class": "pointer", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "the current attempt is an as-of-now fact; resolve it, do not copy it",
    },
    {
        "display": "`refs/changes/<id>/{merged,abandoned}` → `kv/merge\\|abandon/<hex>`",
        "class": "proof", "portable": True, "kind": "merge",
        "note": "a state that is a signed record plus one create-only ref",
    },
    {
        "display": "`refs/heads/**`",
        "class": "foreign", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "code travels by git; a merge is the base owner's CAS and cannot happen at a mirror",
    },
    {
        "display": "`refs/gitiup/roster/<epoch:08x>`",
        "class": "proof", "portable": True, "kind": "roster",
        "note": "immutable epoch; a round is auditable only against the epoch it pinned",
    },
    {
        "display": "`refs/gitiup/roster` (no epoch)",
        "class": "pointer", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "which epoch is live now is live state; the anti-rollback guard is a live-store rule",
    },
    {
        "display": "`refs/gitiup/signup/<slot>`",
        "class": "state", "portable": False, "kind": "signup",
        "token": "not_portable",
        "note": "a request awaiting a human; anyone approved is already inside an epoch",
    },
    {
        "display": "`refs/gitiup/withdrawal/<slot>`, `refs/gitiup/revocation/<slot>`",
        "class": "proof", "portable": True, "kind": "revocation",
        "note": "must travel with the epoch they affect, or the mirror serves an uncompromised-looking roster",
    },
    {
        "display": "`refs/gitiup/round/<change>/<job>/<attempt>`",
        "class": "proof", "portable": True, "kind": "round",
        "note": "evidence only: the record travels, the arbitration does not",
    },
    {
        "display": "`refs/gitiup/job/<change>/<job>`",
        "class": "state", "portable": False, "kind": "advertisement",
        "token": "not_portable",
        "note": "an invitation to arbitrate at a store that cannot seat anyone",
    },
    {
        "display": "`refs/gitiup/lease/<change>/<job>/<slot>`",
        "class": "state", "portable": False, "kind": "lease",
        "token": "not_portable",
        "note": "the purest as-of-now record in the system; there is no honest copy of it",
    },
    {
        "display": "`refs/gitiup/commit/…`, `refs/gitiup/reveal/…`",
        "class": "proof", "portable": True, "kind": "reveal",
        "note": "a reveal without its commitment is worth nothing, so both travel or neither",
    },
    {
        "display": "`refs/gitiup/verdict/<change>/<job>`",
        "class": "proof", "portable": True, "kind": "verdict",
        "note": "with the round, epoch, reveals, commitments and policy it cites",
    },
    {
        "display": "`refs/gitiup/policy/history/<rev>`",
        "class": "proof", "portable": True, "kind": "policy",
        "note": "the chain walk answers which rules were in force, from bytes in hand",
    },
    {
        "display": "`refs/gitiup/policy/current`",
        "class": "pointer", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "which rules are live now; D6 of ADR-0004 already refuses to guess a history",
    },
    {
        "display": "`refs/gitiup/kv/**` (the chain commits)",
        "class": "local", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "one store's private topology; the mirror appends the records to its own chain",
    },
    {
        "display": "`kv/import/<digest>`, `kv/gc/<digest>`",
        "class": "local", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "how *this* store got and dropped what it has; evidence to a human, never an instruction",
    },
    {
        "display": "ref caches, tombstones, pack layout, `host.json`, trust roots, `gitiup.toml`",
        "class": "local", "portable": False, "kind": None,
        "token": "not_portable",
        "note": "transport furniture and local authority; a trust root that arrives over a wire is an attack",
    },
]

# Every record kind the walk knows, and whether a copy may carry it.
KIND_CLASS = {r["kind"]: r["class"] for r in ROWS if r["kind"]}
KIND_CLASS.setdefault("withdrawal", "proof")
KIND_CLASS.setdefault("commitment", "proof")
KIND_CLASS.setdefault("abandon", "proof")
KIND_CLASS.setdefault("code", "code")

# D9: does a portable record ever require a non-portable class? `--selftest` proves
# this is empty, which is what makes D1's table a rule and not a coincidence.
NON_PORTABLE_CLASSES = {"pointer", "state", "local"}


def refusal(token, detail=""):
    """A named refusal carrying the exit code from the ADR's own table."""
    out = {"token": token, "exit": TOKEN_EXIT[token]}
    if detail:
        out["detail"] = detail
    return out


# ---------------------------------------------------------------------------
# D9: the closure edges, in a fixed order so a refusal is deterministic and a
# vector means one thing. Each edge names the signed field that cites it.
# ---------------------------------------------------------------------------
def edges(rec):
    t = rec["type"]
    if t == "attestation":
        yield ("subject", rec.get("subject"), "the object attested")
        yield ("policy_revision", rec.get("policy"), "claimed_at_us → the revision in force")
        if rec.get("tier") == "quorum":
            yield ("verdict", rec.get("verdict"), "the verdict its tier draws from")
    elif t == "verdict":
        yield ("round", rec.get("round"), "round_digest")
        yield ("roster_epoch", rec.get("roster"), "roster_digest")
        yield ("policy_revision", rec.get("policy"), "policy_digest")
        for slot in rec.get("reveals", []):
            yield ("reveal", slot, "counted[] through the round's seats")
    elif t == "round":
        yield ("roster_epoch", rec.get("roster"), "the pinned epoch")
        yield ("policy_revision", rec.get("policy"), "policy_digest")
        for slot in rec.get("seats", []):
            yield ("reveal", slot, "each filled seat")
            yield ("commitment", slot, "sealed rounds only")
        if rec.get("escalated_verdict"):
            yield ("verdict", rec["escalated_verdict"], "escalated_from.from_verdict_digest")
    elif t == "reveal":
        yield ("round", rec.get("round"), "the round it answers")
        if rec.get("sealed"):
            yield ("commitment", rec.get("commitment"), "the promise it must open")
    elif t == "commitment":
        yield ("round", rec.get("round"), "the round it promised into")
    elif t == "roster":
        for key in rec.get("revoked", []):
            yield ("revocation", key, "void at verdict time (ADR-0002 D9)")
        for key in rec.get("rotated", []):
            yield ("withdrawal", key, "the rotation the epoch depends on")
    elif t == "change":
        yield ("subject", rec.get("base"), "base")
        yield ("subject", rec.get("head"), "head")
        if rec.get("previous"):
            yield ("change", rec["previous"], "attempts.previous")
    elif t == "merge":
        yield ("change", rec.get("change"), "the change merged")
        if rec.get("attestation"):
            yield ("attestation", rec["attestation"], "the proof it says it believed")
    elif t == "abandon":
        yield ("change", rec.get("change"), "the change closed")
    # policy, code and every non-portable kind have no edges of this sort; a policy's
    # previous_digest chain is walked separately, under its own budget.


def closure(store, start, budgets=None, allow_missing_subject=False):
    """The verification closure of `start`, or the first refusal that stops it.

    Returns `(taken, refusal)`: `taken` is the ordered list of record ids the copy
    must contain (including `start` itself), `refusal` is `None` or the named refusal
    with the missing edge as its detail. D9: a record is imported with its closure or
    not at all, so a partial walk never becomes a partial copy.
    """
    b = dict(BUDGETS)
    if budgets:
        b.update(budgets)

    first = store.get(start)
    if first is None:
        return [], refusal("closure_incomplete", "start")
    kind = first["type"]
    if KIND_CLASS.get(kind) in NON_PORTABLE_CLASSES:
        return [], refusal("not_portable", kind)

    taken, seen = [], {start}

    def take(rid):
        if rid not in taken:
            taken.append(rid)

    queue = [(start, 0)]
    while queue:
        rid, depth = queue.pop(0)
        rec = store[rid]
        take(rid)
        if len(taken) > b["records"]:
            return [], refusal("closure_budget_records", str(len(taken)))
        if sum(r.get("bytes", 0) for r in (store[t_] for t_ in taken)) > b["bytes"]:
            return [], refusal("closure_budget_bytes", rid)

        # A policy's own chain: linear, its own budget, and a missing predecessor is
        # ADR-0004 D6's refusal, not a closure gap.
        if rec["type"] == "policy":
            chain, prev, seen_chain = 1, rec.get("previous"), {rid}
            while prev and prev != GENESIS:
                if prev not in store:
                    return [], refusal("policy_history_missing", prev)
                if prev in seen_chain:
                    return [], refusal("policy_history_missing", "cycle:" + prev)
                chain += 1
                if chain > b["policy_chain"]:
                    return [], refusal("policy_chain_too_long", str(chain))
                take(prev)
                seen.add(prev)
                seen_chain.add(prev)
                prev = store[prev].get("previous")

        for edge, target, why in edges(rec):
            if target is None:
                continue
            if edge == "subject":
                # A proof about an object that is not there is a proof about nothing.
                if target not in store:
                    if allow_missing_subject:
                        continue
                    return [], refusal("subject_missing", edge)
            elif target not in store:
                if edge == "commitment":
                    return [], refusal("no_commitment", why)
                return [], refusal("closure_incomplete", edge)
            if KIND_CLASS.get(store[target]["type"]) in NON_PORTABLE_CLASSES:
                return [], refusal("not_portable", store[target]["type"])
            if target not in seen:
                if depth + 1 > b["depth"]:
                    return [], refusal("closure_budget_depth", "%s\u2192%s" % (edge, target))
                seen.add(target)
                queue.append((target, depth + 1))
    return taken, None


# ---------------------------------------------------------------------------
# D5: freshness, and what a copy may not attest to.
# ---------------------------------------------------------------------------
CLOCK = 1793347200000000  # 2026-10-30T12:00:00Z, fixed: nothing here may read a clock


def age_us(rec, now=CLOCK):
    """The only age gitiup computes (D5 clause 1): from the signed claim."""
    return now - rec["claimed_at_us"]


def arrival_age_us(rec, now=CLOCK):
    """What a *wrong* implementation would use. Vectors show it differs, so that the
    trap is a fact and not a paragraph."""
    return now - rec["arrived_at_us"]


def provenance(store_kind, rec, policy=None, origin=None):
    """The report's `provenance` block, and any refusal it implies.

    `age_basis` is a literal field on purpose: the invariant "age comes from the
    claim" has to be assertable, not merely true.
    """
    policy = policy or {}
    origin = origin or "s3://gitiup-project/repo"
    prov = {
        "store": "origin" if store_kind == "origin" else "copy",
        "store_url": origin if store_kind == "origin" else rec["_from"],
        "read_at_us": CLOCK,
        "arrived_from": None if store_kind == "origin" else rec["_from"],
        "arrived_at_us": None if store_kind == "origin" else rec["arrived_at_us"],
        "origin_seen": store_kind == "origin",
        "age_us": age_us(rec),
        "age_basis": "claimed_at_us",
        "closure": "complete",
    }
    if store_kind != "origin":
        mirrors = policy.get("mirrors", [])
        if policy.get("require_origin_seen"):
            return prov, refusal("origin_provenance_required",
                                 "require_origin_seen is set and this is a copy")
        if mirrors and prov["arrived_from"] not in mirrors:
            return prov, refusal("unlisted_mirror", prov["arrived_from"])
    return prov, None


# ---------------------------------------------------------------------------
# D7: ref names, collisions, pointers, and the legacy spelling.
# ---------------------------------------------------------------------------
def advertise(subject, digest, legacy=False):
    """The ref a copy writes. Same digest, always; the legacy one-level spelling is
    re-spelled on import and never re-created."""
    if legacy:
        return "refs/attestations/%s/%s" % (subject, digest), "respelled"
    return "refs/attestations/%s/%s" % (subject, digest), None


def publish_collision(store, digest):
    """Create-only publish: a name collision in the portable set is a content match."""
    return "already" if digest in store else "written"


def resolve_head(source_attempts, target_attempts):
    """Resolve `refs/changes/<id>/head` on the reader's side and decide the move.

    A pointer is never copied; the reader resolves it to the attempts it names. A
    target holding an attempt the source does not have is not a fast-forward, and a
    mirror does not resolve divergences: it reports them (D6, D7).
    """
    if sorted(target_attempts) and max(target_attempts) > max(source_attempts):
        return "diverged", refusal("diverged", "target holds attempt %d, source's newest is %d"
                                   % (max(target_attempts), max(source_attempts)))
    return "resolved → attempt/%d" % max(source_attempts), None


# ---------------------------------------------------------------------------
# D8: retention authority, and eviction that needs a source.
# ---------------------------------------------------------------------------
def may_prune_by_age(import_records, read_only):
    """Retention authority follows write authority (D8 rule 2)."""
    if read_only or import_records:
        return refusal("mirror_may_not_prune_by_age",
                       "%d import records name an origin" % len(import_records)
                       if import_records else "store is read-only")
    return None


def evictable(digest, import_records):
    """A cache may evict only what it can go and get again."""
    if digest not in import_records:
        return refusal("eviction_needs_source", digest)
    return None


# ---------------------------------------------------------------------------
# The store used by the cases: one quorum proof and everything it leans on.
# ---------------------------------------------------------------------------
def build_store():
    """`sha256:` -prefixed short ids, not real digests: no crypto here on purpose."""
    s = {}

    def put(rid, **fields):
        fields.setdefault("bytes", 512)
        s[rid] = fields
        return rid

    put("code:C1", type="code", bytes=8192)
    put("pol:1", type="policy", previous=GENESIS, revision=1)
    put("pol:2", type="policy", previous="pol:1", revision=2)
    put("att:local", type="attestation", tier="local", subject="code:C1", policy="pol:1",
        claimed_at_us=CLOCK - 7200 * 10 ** 6, arrived_at_us=CLOCK - 3600 * 10 ** 6,
        _from="https://mirror.example.org/repo.git")

    for i in range(1, 5):
        put("rev:%d" % i, type="reveal", sealed=True, round="rnd:0",
            commitment="cmt:%d" % i, bytes=4096)
        put("cmt:%d" % i, type="commitment", round="rnd:0")
    put("ros:7", type="roster", epoch=7, revoked=["revo:key:dead"], rotated=[])
    put("revo:key:dead", type="revocation", key="key:dead")
    put("rnd:0", type="round", roster="ros:7", policy="pol:2", reveal_mode="sealed",
        seats=["rev:1", "rev:2", "rev:3", "rev:4"])
    put("ver:0", type="verdict", round="rnd:0", roster="ros:7", policy="pol:2",
        reveals=["rev:1", "rev:2", "rev:3", "rev:4"])
    put("att:quorum", type="attestation", tier="quorum", subject="code:C1", policy="pol:2",
        verdict="ver:0", claimed_at_us=CLOCK - 7200 * 10 ** 6,
        arrived_at_us=CLOCK - 3600 * 10 ** 6, _from="https://mirror.example.org/repo.git")
    put("chg:1", type="change", base="code:C1", head="code:C2", previous=None)
    put("code:C2", type="code", bytes=8192)
    put("mg:1", type="merge", change="chg:1", attestation="att:local")

    # The things a naive transport would happily copy.
    put("lease:1", type="lease", ttl_us=900)
    put("signup:1", type="signup", state="pending")
    put("job:1", type="advertisement", round="rnd:0")
    return s


def without(store, *names):
    out = dict(store)
    for n in names:
        out.pop(n, None)
    return out


# ---------------------------------------------------------------------------
# Cases: (source store, start refs, destination contents) → what a copy may be.
# ---------------------------------------------------------------------------
def cases():
    S = build_store()
    out = []

    def case(name, section, source, refs, target=(), **extra):
        taken, refused, already = [], [], []
        for ref in refs:
            if ref in target:
                refused_note = None
                already.append(ref)
                got = [ref]
            else:
                got, refused_note = closure(source, ref,
                                            extra.get("budgets"),
                                            extra.get("allow_missing_subject", False))
            if refused_note:
                refused.append({"ref": ref, **refused_note})
            else:
                taken.extend(g for g in got if g not in target and g not in taken)
        rec = {"case": name, "adr": section, "start": list(refs),
               "imported": sorted(taken), "already": sorted(already), "refused": refused}
        rec.update(extra.get("expect", {}))
        if "objects" in rec and rec["objects"] != len(taken):
            raise SystemExit("case %r: expected %r objects, the walk took %d (%s)"
                             % (name, rec["objects"], len(taken), " ".join(sorted(taken))))
        out.append(rec)
        return rec

    # D1: the closure of a local-tier proof is small, and it is still not one object.
    case("local-attestation", "D1", S, ["att:local"],
         expect={"note": "attestation + the policy revision in force + its subject"})

    # D1/D9: the closure of a quorum proof is where the work is.
    case("quorum-attestation-complete", "D1", S, ["att:quorum"],
         expect={"note": "the verdict, the round, the epoch, four reveals and their "
                         "commitments, both policy revisions and the revocation",
                 "objects": 16})

    # D9: every missing edge is a named refusal, per record.
    case("missing-policy-revision", "D9", without(S, "pol:2"), ["att:quorum"],
         expect={"note": "a cited revision absent at the source is a closure gap"})
    case("missing-subject", "D9", without(S, "code:C1"), ["att:local"],
         expect={"note": "`.3`'s --allow-missing-subject is the only excuse"})
    case("subject-excused", "D9", without(S, "code:C1"), ["att:local"],
         allow_missing_subject=True, expect={"note": "explicit, and reported"})
    case("verdict-only-rumour", "D9", without(S, "rnd:0"), ["att:quorum"],
         expect={"note": "a verdict without its round is the rumour `.3` names"})
    case("reveal-without-commitment", "D9", without(S, "cmt:3"), ["att:quorum"],
         expect={"note": "sealed: a reveal that cannot open its promise"})
    case("stale-roster-epoch", "D9", without(S, "ros:7"), ["att:quorum"],
         expect={"note": "the epoch the round pinned, or nothing was verified"})
    case("revocation-carried", "D9", without(S, "revo:key:dead"), ["att:quorum"],
         expect={"note": "a roster without the revocations naming its keys"})
    case("policy-chain-broken", "D9", without(S, "pol:1"), ["att:quorum"],
         expect={"note": "a present revision whose predecessor is missing is ADR-0004 "
                         "D6's refusal, reached through a copy"})

    # D2 / C11: what a listing offers that must be skipped.
    case("non-portable-in-listing", "D2", S, ["att:local", "lease:1", "signup:1", "job:1"],
         expect={"note": "leases, pending sign-ups and advertisements are skipped by name, "
                         "and the report says so"})

    # D7: collisions, pointers, the legacy spelling.
    case("already-imported", "D7", S, ["att:quorum"], target=("att:quorum",),
         expect={"note": "re-running a fetch writes nothing"})
    out[-1]["collision"] = publish_collision({"att:quorum": True}, "att:quorum")

    ptr, why = resolve_head([1, 2, 3], [2])
    out.append({"case": "head-resolves", "adr": "D7", "pointer": ptr,
                "refused": [], "imported": [],
                "note": "a fast-forward: the reader resolves head and moves it under CAS"})
    ptr, why = resolve_head([1, 2, 3], [4])
    out.append({"case": "head-diverged", "adr": "D7", "pointer": ptr,
                "imported": [],
                "refused": [{"ref": "refs/changes/chg-x/head", **why}],
                "note": "a mirror reports a divergence, it never resolves one"})
    ref_name, note = advertise("code:C1", "sha256:9f1c", legacy=True)
    out.append({"case": "legacy-ref-respelled", "adr": "D7", "imported": [],
                "refused": [], "written_ref": ref_name, "note": note,
                "expected_ref": "refs/attestations/code:C1/sha256:9f1c"})

    # D8: retention authority.
    out.append({"case": "age-gc-on-a-mirror", "adr": "D8", "imported": [],
                "refused": [{"ref": "--max-age 120d",
                             **may_prune_by_age(["kv/import/x"], False)}],
                "note": "`claimed_at_us` is identical on every copy, so age pruning in "
                        "lockstep is the real last-copy hazard"})
    out.append({"case": "age-gc-at-the-origin", "adr": "D8", "imported": [],
                "refused": [], "pruned": True,
                "note": "the vault prunes on policy",
                "allowed": may_prune_by_age([], False) is None})
    out.append({"case": "evict-without-source", "adr": "D8", "imported": [],
                "refused": [{"ref": "sha256:9f1c", **evictable("sha256:9f1c", [])}],
                "note": "no import record, so no re-fetch source, so this store is the "
                        "only copy and has not earned the decision"})
    out.append({"case": "evict-with-source", "adr": "D8", "imported": [], "refused": [],
                "evicted": True,
                "note": "a cache may forget what it can go and get again",
                "allowed": evictable("sha256:9f1c", {"sha256:9f1c": "s3://origin/repo"}) is None})

    # D5: freshness, and the trap.
    att = S["att:quorum"]
    prov, why = provenance("copy", att, {}, "https://mirror.example.org/repo.git")
    out.append({"case": "copy-is-fine-by-default", "adr": "D5", "provenance": prov,
                "refused": [], "imported": [],
                "age_from_claim_us": age_us(att),
                "age_from_arrival_us": arrival_age_us(att),
                "note": "age is 2 h from the claim and 1 h from arrival: measuring from "
                        "arrival is the freshness laundering D5 forbids"})
    prov, why = provenance("copy", att, {"require_origin_seen": True}, None)
    out.append({"case": "origin-provenance-required", "adr": "D5", "provenance": prov,
                "imported": [], "refused": [{"ref": "att:quorum", **why}]})
    prov, why = provenance("copy", att, {"mirrors": ["https://other.example/repo.git"]}, None)
    out.append({"case": "unlisted-mirror", "adr": "D5", "provenance": prov,
                "imported": [], "refused": [{"ref": "att:quorum", **why}]})
    prov, why = provenance("copy", att,
                           {"mirrors": ["https://mirror.example.org/repo.git"]}, None)
    out.append({"case": "listed-mirror", "adr": "D5", "provenance": prov,
                "refused": [], "imported": [],
                "note": "an allowlist is a staleness statement, never a trust statement"})

    for rec in out:
        rec.setdefault("already", [])
        rec.setdefault("refused", [])
        rec.setdefault("imported", [])

    return out


# ---------------------------------------------------------------------------
# `--check-ad`: the prose and the data are one fact.
# ---------------------------------------------------------------------------
def _cells(line):
    line = line.strip()
    if not line.startswith("|"):
        return None
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip("|"))]


def check_ad():
    text = open(ADR, encoding="utf-8").read()
    problems = []

    # D1's table must list exactly these rows, with the same portability verdict.
    section = text.split("## D1 —")[1].split("\n---")[0]
    prose = {}
    for line in section.splitlines():
        cells = _cells(line)
        if not cells or len(cells) < 2 or set("".join(cells)) <= set("-: "):
            continue
        if cells[1].startswith("**yes") or cells[1].startswith("**no") or \
           cells[1].startswith("**out"):
            prose[cells[0]] = cells[1]
    for row in ROWS:
        if row["display"] not in prose:
            problems.append("D1 table is missing the row %r" % row["display"])
            continue
        said = prose[row["display"]]
        if row["portable"] and not said.startswith("**yes"):
            problems.append("D1 says %r is %s, the data says portable" % (row["display"], said))
        if not row["portable"] and not (said.startswith("**no") or said.startswith("**out")):
            problems.append("D1 says %r is %s, the data says not portable" % (row["display"], said))
    extra = set(prose) - {r["display"] for r in ROWS}
    if extra:
        problems.append("D1 table has rows the data does not: %s" % sorted(extra))

    # D10's token table must carry every token this file can emit, with the same exit.
    table = text.split("## D10 —")[1]
    prose_tokens = {}
    for line in table.splitlines():
        cells = _cells(line)
        if not cells or len(cells) < 2:
            continue
        m = re.fullmatch(r"`([a-z_]+)`", cells[0])
        if m and re.fullmatch(r"[0-9]", cells[1]):
            prose_tokens[m.group(1)] = int(cells[1])
    for token, code in TOKEN_EXIT.items():
        if token not in prose_tokens:
            problems.append("D10 table is missing the token `%s`" % token)
        elif prose_tokens[token] != code:
            problems.append("`%s` is exit %d here, exit %d in the ADR"
                            % (token, code, prose_tokens[token]))
    for token in sorted(prose_tokens):
        if token not in TOKEN_EXIT:
            problems.append("D10 table lists `%s`, which this file does not know" % token)
    return problems


# ---------------------------------------------------------------------------
# `--selftest`: properties, not just golden output.
# ---------------------------------------------------------------------------
def selftest():
    S = build_store()
    checks = []

    def ok(name, cond):
        checks.append((name, bool(cond)))

    # Every portable record's closure exists in the full store and terminates.
    for rid in sorted(S):
        if KIND_CLASS.get(S[rid]["type"]) in NON_PORTABLE_CLASSES or S[rid]["type"] == "code":
            continue
        taken, why = closure(S, rid)
        ok("closure of %s is complete" % rid, why is None and taken)

    # No portable record's closure reaches a non-portable class: D1's table is a rule.
    leaks = []
    for rid in sorted(S):
        taken, _ = closure(S, rid)
        for t in taken:
            if KIND_CLASS.get(S[t]["type"]) in NON_PORTABLE_CLASSES:
                leaks.append("%s→%s" % (rid, t))
    ok("no portable closure reaches arbitration state", not leaks)

    # Deleting any single required edge turns the walk into a named refusal.
    for victim, token in [("pol:2", "closure_incomplete"), ("rnd:0", "closure_incomplete"),
                          ("ros:7", "closure_incomplete"), ("cmt:3", "no_commitment"),
                          ("code:C1", "subject_missing")]:
        _, why = closure(without(S, victim), "att:quorum" if victim != "code:C1" else "att:local")
        ok("deleting %s refuses with %s" % (victim, token), why and why["token"] == token)

    # Budgets, at a scaled value so the vectors stay human-sized.
    deep = dict(build_store())
    deep["att:deep"] = {"type": "attestation", "tier": "quorum", "subject": "code:C1",
                        "policy": "pol:2", "verdict": "ver:0", "bytes": 512}
    for i in range(12):
        deep["ver:%d" % i] = {"type": "verdict", "round": "rnd:%d" % i, "roster": "ros:7",
                              "policy": "pol:2", "reveals": [], "bytes": 128}
        deep["rnd:%d" % i] = {"type": "round", "roster": "ros:7", "policy": "pol:2",
                              "seats": [], "bytes": 128,
                              "escalated_verdict": "ver:%d" % (i + 1) if i < 11 else None}
    _, why = closure(deep, "att:deep")
    ok("an escalation chain past the hop budget refuses rather than wandering",
       why and why["token"] == "closure_budget_depth")
    _, why = closure(S, "att:quorum", budgets={"records": 4})
    ok("the record budget refuses instead of truncating",
       why and why["token"] == "closure_budget_records")
    _, why = closure(S, "att:quorum", budgets={"bytes": 1024})
    ok("the byte budget refuses instead of truncating",
       why and why["token"] == "closure_budget_bytes")
    long_chain = {"p0": {"type": "policy", "previous": GENESIS, "bytes": 8}}
    for i in range(1, 70):
        long_chain["p%d" % i] = {"type": "policy", "previous": "p%d" % (i - 1), "bytes": 8}
    long_chain["att"] = {"type": "attestation", "tier": "local", "policy": "p69",
                         "subject": None, "bytes": 8}
    _, why = closure(long_chain, "att")
    ok("a policy chain past 64 revisions refuses",
       why and why["token"] == "policy_chain_too_long")
    _, why = closure(long_chain, "att", budgets={"policy_chain": 96})
    ok("…and walks when the budget allows it", why is None)

    # Age never comes from arrival, and the two differ in the fixture.
    att = S["att:quorum"]
    ok("age is measured from the claim", age_us(att) == CLOCK - att["claimed_at_us"])
    ok("arrival age would be a different, larger-believing number",
       age_us(att) != arrival_age_us(att))
    prov, _ = provenance("copy", att, {}, None)
    ok("the report states its age basis", prov["age_basis"] == "claimed_at_us")
    ok("a copy is not origin_seen", prov["origin_seen"] is False)
    prov, why = provenance("copy", att, {"require_origin_seen": True}, None)
    ok("require_origin_seen refuses a copy", why["token"] == "origin_provenance_required")
    prov, why = provenance("origin", att, {"require_origin_seen": True}, None)
    ok("the origin satisfies it", why is None and prov["origin_seen"] is True)

    # D2: nothing in the register is portable, and the token is always named.
    for rid in sorted(S):
        if KIND_CLASS.get(S[rid]["type"]) in NON_PORTABLE_CLASSES:
            _, why = closure(S, rid)
            ok("%s is refused, by token" % rid, why and why["token"] == "not_portable")
    for row in ROWS:
        if not row["portable"]:
            ok("%s names its refusal" % row["display"], row.get("token"))

    # D10: every token in use is in the ADR's table.
    ok("every token emitted is in the refusal table",
       all(TOKEN_EXIT[w["token"]] for w in [refusal(t) for t in TOKEN_EXIT]))

    bad = [name for name, good in checks if not good]
    for name, good in checks:
        print("  %s %s" % ("ok " if good else "FAIL", name))
    print("%d checks, %d failed" % (len(checks), len(bad)))
    return 1 if bad else 0


# ---------------------------------------------------------------------------
# Emit.
# ---------------------------------------------------------------------------
def render():
    portable = {
        "adr": "ADR-0005",
        "unit": "record + advertisement, bytes first (D1, D8)",
        "principle": "the portable set is the verification closure; arbitration state "
                     "and anything whose meaning is 'as of now' never travels",
        "budgets": BUDGETS,
        "rows": ROWS,
        "kinds": KIND_CLASS,
    }
    return portable, {"clock_us": CLOCK, "genesis_previous": GENESIS,
                      "cases": cases(),
                      "refusals": [{"token": t, "exit": c}
                                   for t, c in sorted(TOKEN_EXIT.items(),
                                                      key=lambda kv: (kv[1], kv[0]))]}


def main():
    args = sys.argv[1:]
    if args == ["--check-ad"]:
        problems = check_ad()
        for p in problems:
            print("ADR disagrees with the vectors: %s" % p)
        print("%d problems" % len(problems))
        return 1 if problems else 0
    if args == ["--selftest"]:
        return selftest()

    portable, cases_doc = render()
    files = {"portable.json": portable, "cases.json": cases_doc}

    if args == ["--check"]:
        bad = 0
        for name, doc in files.items():
            want = json.dumps(doc, indent=2, sort_keys=True) + "\n"
            have = open(os.path.join(HERE, name), encoding="utf-8").read()
            if want != have:
                print("%s is stale" % name)
                bad += 1
            else:
                print("%s is current" % name)
        return 1 if bad else 0

    for name, doc in files.items():
        with open(os.path.join(HERE, name), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print("wrote %s" % ", ".join(sorted(files)))
    print("\nportability: %d rows, %d portable, %d refused"
          % (len(ROWS), sum(1 for r in ROWS if r["portable"]),
             sum(1 for r in ROWS if not r["portable"])))
    for row in ROWS:
        mark = "portable" if row["portable"] else "not      "
        print("  %s  %-64s %s" % (mark, row["display"], row.get("token") or row["note"][:44]))
    print("\ncases: %d" % len(cases_doc["cases"]))
    for case_doc in cases_doc["cases"]:
        refused = ", ".join("%s(%s)" % (r["token"], r.get("detail", ""))
                            for r in case_doc["refused"]) or "—"
        print("  %-28s %-5s %2d imported  %s"
              % (case_doc["case"], case_doc["adr"], len(case_doc["imported"]), refused))
    return 0


if __name__ == "__main__":
    sys.exit(main())
