#!/usr/bin/env python3
"""Reference implementation of gitiup verifier selection v1 (ADR-0002).

Standard library only, deliberately: this file is the byte-for-byte contract
that `gitiup select` (ticket giti-msi.3) must reproduce in Rust, and a second
implementation in a different language is the test of that. Everything the
algorithm touches is here and nothing else is: no network, no third-party
package, no clock (the epoch is an input, not `now()`).

    python3 generate.py            # print the worked-example table, rewrite the vectors
    python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
    python3 generate.py --uniform  # chi-square over 100000 rounds on a homogeneous roster

See ../0002-roster-verifier-selection-and-sybil-resistance.md for the prose spec; the
constants and the filter order below are what that document names.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Constants (ADR-0002 D2, D3, D10). Domain strings are ASCII, contain no NUL, and
# are part of every hash: changing one changes every derivation, so it is a new
# round kind, not a new field.
# ---------------------------------------------------------------------------
ROUND_KIND = "gitiup-round-1"
D_SEP = b"\x00"
D_SCORE = ROUND_KIND.encode() + b"/score"
D_HANDLE = ROUND_KIND.encode() + b"/handle"
D_SLOT = b"gitiup-keyslot-1"
D_SECRET = ROUND_KIND.encode() + b"/secret"
TEST_SECRET_LABEL = b"gitiup ADR-0002 test vector selection secret (never use)"
HANDLE_BYTES = 16


def canonical(obj) -> bytes:
    """Gitiup Canonical JSON (ADR-0001 D1) for the subset these fixtures use:
    keys ascending, no whitespace, integers only, no nulls, ASCII only here."""
    return json.dumps(
        obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def sha256(*parts) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def digest_str(raw: bytes) -> str:
    """The algorithm-tagged digest string form of ADR-0001 D2."""
    return "sha256:" + raw.hex()


def digest_of(obj) -> str:
    """`sha256:<hex>` over the canonical bytes of `obj` — the roster digest."""
    return digest_str(sha256(canonical(obj)))


def hex_body(digest: str) -> bytes:
    """The bare lower-case hex body of a tagged digest, as an ASCII byte string."""
    return digest.split(":", 1)[1].lower().encode()


def slot_of(key_id: str) -> str:
    """Public storage slot for a key: hex-safe, stable, one-way (ADR-0002 D10)."""
    return hashlib.sha256(D_SLOT + D_SEP + key_id.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Derivations (ADR-0002 D2, D3, D8)
# ---------------------------------------------------------------------------
def selection_secret(label: bytes = TEST_SECRET_LABEL) -> bytes:
    """HKDF-Extract(secret, label) — stands in for the selector's derivation
    `HKDF-Extract(salt=D_SECRET, ikm=<ed25519 seed>)`. Public here because a
    test vector must be recomputable by anyone; a real selector's secret never
    leaves its key store."""
    return hmac.new(D_SECRET, label, hashlib.sha256).digest()


def round_id_bytes(round_inputs: dict) -> bytes:
    """The exact seed message: seven NUL-separated fields, in this order."""
    fields = [
        ROUND_KIND,
        str(round_inputs["roster_epoch"]),
        hex_body(round_inputs["roster_digest"]).decode(),
        round_inputs["change_id"],
        round_inputs["head_oid"],
        round_inputs["job_id"],
        str(round_inputs["attempt"]),
    ]
    for f in fields:
        if not f or "\x00" in f:
            raise ValueError(f"round field is empty or contains NUL: {f!r}")
    return D_SEP.join(f.encode() for f in fields)


def seed_of(secret: bytes, round_inputs: dict) -> bytes:
    """The round seed: HMAC-SHA-256 keyed by the selector's secret. Deterministic
    in the round inputs, so nobody — not the proposer, not the selector — can
    re-roll it (ADR-0002 D2)."""
    return hmac.new(secret, round_id_bytes(round_inputs), hashlib.sha256).digest()


def score_of(seed: bytes, key_id: str) -> bytes:
    """Per-candidate score, compared as a big-endian 256-bit integer, ascending."""
    return sha256(D_SCORE, D_SEP, seed, D_SEP, key_id.encode())


def handle_of(seed: bytes, key_id: str) -> str:
    """Seed-derived pseudonym. Only computable with the seed, so it can address a
    commitment slot without naming a key while the selection is still closed."""
    raw = hmac.new(seed, D_HANDLE + D_SEP + key_id.encode(), hashlib.sha256).digest()
    return raw[:HANDLE_BYTES].hex()


# ---------------------------------------------------------------------------
# Eligibility (ADR-0002 D5): filters are ordered, and the first failure is the
# recorded reason, so `--explain` output is part of the contract.
# ---------------------------------------------------------------------------
FILTER_ORDER = (
    "window",
    "tier_floor",
    "excluded",
    "arch",
    "ram",
    "disk",
    "images",
    "sandboxes",
    "sandbox_level",
)


def why_excluded(entry: dict, round_inputs: dict) -> str | None:
    caps = entry["capabilities"]
    need = round_inputs["required_capabilities"]
    policy = round_inputs["policy"]
    epoch = round_inputs["roster_epoch"]
    window = entry["epochs_valid"]
    if not (window["from"] <= epoch <= window["to"]):
        return "window"
    order = {"anonymous": 0, "endorsed": 1, "trusted": 2}
    if order[entry["tier"]] < order[policy["tier_floor"]]:
        return "tier_floor"
    exclusions = set(round_inputs["exclusions"])
    if entry["key_id"] in exclusions or entry["identity"] in exclusions:
        return "excluded"
    if need["arch"] not in caps["arch"]:
        return "arch"
    if caps["ram_mb"] < need["ram_mb"]:
        return "ram"
    if caps["disk_mb"] < need["disk_mb"]:
        return "disk"
    if not caps["can_pull"]:
        missing = [d for d in need["image_digests"] if d not in caps["image_cache"]]
        if missing:
            return "images"
    if not set(need["sandboxes"]) & set(caps["sandboxes"]):
        return "sandboxes"
    if caps["sandbox_level"] < need["min_sandbox_level"]:
        return "sandbox_level"
    return None


# ---------------------------------------------------------------------------
# Selection (ADR-0002 D3): order by score, then fill greedily under caps.
# ---------------------------------------------------------------------------
def select(roster: dict, round_inputs: dict, secret: bytes) -> dict:
    policy = round_inputs["policy"]
    seed = seed_of(secret, round_inputs)
    order_rank = {"anonymous": 0, "endorsed": 1, "trusted": 2}

    rows = []
    for entry in roster["entries"]:
        rows.append(
            {
                "key_id": entry["key_id"],
                "identity": entry["identity"],
                "tier": entry["tier"],
                "arch": entry["capabilities"]["arch"],
                "ram_mb": entry["capabilities"]["ram_mb"],
                "slot": slot_of(entry["key_id"]),
                "score": score_of(seed, entry["key_id"]).hex(),
                "excluded_by": why_excluded(entry, round_inputs),
                "greedy": "n/a",
                "greedy_reason": "",
            }
        )
    # Total order: score ascending as a big-endian integer, then key_id by
    # ascending UTF-8 bytes. key_ids are unique inside a roster epoch, so the
    # tie-break is a total order and the sort is stable by construction.
    rows.sort(key=lambda r: (int.from_bytes(bytes.fromhex(r["score"]), "big"), r["key_id"].encode()))

    tier_caps = policy["tier_caps"]
    tier_used = {t: 0 for t in order_rank}
    identity_used: dict[str, int] = {}
    selected: list[dict] = []
    for row in rows:
        if row["excluded_by"] is not None:
            row["greedy"] = "ineligible"
            continue
        room_identity = identity_used.get(row["identity"], 0) < policy["max_per_identity"]
        room_tier = tier_used[row["tier"]] < tier_caps.get(row["tier"], 0)
        row["greedy"] = "take" if (room_identity and room_tier) else "skip"
        row["greedy_reason"] = (
            ""
            if row["greedy"] == "take"
            else ("identity" if not room_identity else "tier_cap")
        )
        if len(selected) < policy["n"] and row["greedy"] == "take":
            identity_used[row["identity"]] = identity_used.get(row["identity"], 0) + 1
            tier_used[row["tier"]] += 1
            selected.append(row)
    for row in rows:
        row["selected"] = row in selected
    reserves = [r for r in rows if r["excluded_by"] is None and not r["selected"]]
    eligible = [r for r in rows if r["excluded_by"] is None]
    return {
        "kind": "selection",
        "schema_version": 1,
        "round_kind": ROUND_KIND,
        "round_id": round_id_bytes(round_inputs).decode().replace("\x00", "/"),
        "seed": digest_str(seed),
        "policy_digest": digest_of(policy),
        "eligible": len(eligible),
        "sufficient": len(selected) == policy["n"],
        "selected": [
            {
                "rank": i + 1,
                "key_id": r["key_id"],
                "identity": r["identity"],
                "slot": r["slot"],
                "tier": r["tier"],
                "handle": handle_of(seed, r["key_id"]),
            }
            for i, r in enumerate(selected)
        ],
        "reserves": [
            {"rank": i + 1, "key_id": r["key_id"], "slot": r["slot"], "tier": r["tier"]}
            for i, r in enumerate(reserves)
        ],
        "candidates": [
            {
                "key_id": r["key_id"],
                "score": r["score"],
                "eligible": r["excluded_by"] is None,
                "excluded_by": r["excluded_by"],
                "greedy": r["greedy"],
                "greedy_reason": r["greedy_reason"],
                "selected": r["selected"],
            }
            for r in rows
        ],
    }


def promote(roster: dict, round_inputs: dict, secret: bytes, voided: list[str]) -> dict:
    """Reassignment is a re-run with a longer exclusion list, never a new seed
    (ADR-0002 D3): that is what stops the issuer from steering a promotion."""
    extended = dict(round_inputs)
    extended["exclusions"] = sorted(set(round_inputs["exclusions"]) | set(voided))
    return select(roster, extended, secret)


class Key:
    """A fixture key: real-shaped, consistent, and with no private half.

    `key_id` is derived from the SSH wire blob exactly the way ADR-0001 D3
    requires, so a test that re-derives the fingerprint from `public_key` gets
    the roster's `key_id` back — the vectors bind the identity presentation,
    not just an opaque string.
    """

    def __init__(self, label: str):
        blob_body = hashlib.sha256(("adr-0002:" + label).encode()).digest()
        blob = (
            len("ssh-ed25519").to_bytes(4, "big")
            + b"ssh-ed25519"
            + len(blob_body).to_bytes(4, "big")
            + blob_body
        )
        self.name = label
        self.ssh_blob = blob
        self.public_key = "ssh-ed25519 " + base64.b64encode(blob).decode().rstrip("=")
        self.key_id = (
            "SHA256:"
            + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        )


IMAGE = "sha256:" + hashlib.sha256(b"ghcr.io/example/rust:1.83").hexdigest()

# One human/organisation principal per Key here; two principals bring two boxes.
PRINCIPALS = {
    name: Key("principal:" + name)
    for name in ("ada", "brin", "chen", "dara", "evel", "fur", "gus", "halo", "ivy")
}
BOXES = {
    name: Key("box:" + name)
    for name in (
        "ada-primary",
        "ada-arm",
        "brin-ci",
        "chen-tower",
        "chen-rack",
        "dara-build",
        "evel-laptop",
        "evel-desktop",
        "fur-arm",
        "gus-pi",
        "halo-ci",
        "ivy-lap",
    )
}


def principal_of(box: str) -> Key:
    return PRINCIPALS[box.split("-")[0]]


def entry(box: str, tier, arch, ram, disk, sandboxes, level, cache=(), can_pull=False,
          frm=38, to=52):
    k = BOXES[box]
    return {
        "key_id": k.key_id,
        "public_key": k.public_key,
        "identity": principal_of(box).key_id,
        "tier": tier,
        "capabilities": {
            "arch": arch,
            "ram_mb": ram,
            "disk_mb": disk,
            "image_cache": list(cache),
            "can_pull": can_pull,
            "sandboxes": sandboxes,
            "sandbox_level": level,
        },
        "epochs_valid": {"from": frm, "to": to},
    }


def build_roster() -> dict:
    """Ten machines, seven principals, one epoch. Fixed numbers, no clock."""
    entries = [
        # ada is the owner: two boxes, one principal, one vote either way.
        entry("ada-primary", "trusted", ["x86_64"], 65536, 1048576, ["docker"], 2,
              (IMAGE,)),
        entry("ada-arm", "trusted", ["aarch64"], 32768, 524288,
              ["docker", "unshare"], 2, (), True),
        # brin proposed this change: every brin key is excluded, whichever one
        # the roster happens to hold.
        entry("brin-ci", "trusted", ["x86_64"], 32768, 524288, ["docker"], 2,
              (IMAGE,)),
        # chen runs two qualifying boxes: max_per_identity bites on the second.
        entry("chen-tower", "endorsed", ["x86_64"], 16384, 262144, ["docker"], 2,
              (), True),
        entry("chen-rack", "endorsed", ["x86_64"], 16384, 262144, ["unshare"], 1,
              (), True),
        # dara caches the base image; evel is anonymous and may hold at most one
        # seat per round under tier_caps.anonymous.
        entry("dara-build", "endorsed", ["x86_64"], 65536, 1048576,
              ["docker", "unshare"], 2, (IMAGE,)),
        entry("evel-laptop", "anonymous", ["x86_64"], 8192, 61440, ["unshare"], 1,
              (), True),
        entry("evel-desktop", "anonymous", ["x86_64"], 16384, 262144,
              ["unshare"], 1, (), True),
        # fur is arm-only and gus is short on ram: both are filtered out, and the
        # audit record has to name the filter that got them. gus is also
        # quarantined from a previous round, so two reasons apply and the first
        # one in FILTER_ORDER wins.
        entry("fur-arm", "endorsed", ["aarch64"], 32768, 262144, ["docker"], 2,
              (), True),
        entry("gus-pi", "endorsed", ["x86_64"], 4096, 61440, ["unshare"], 1, (),
              True),
        # halo and ivy are spare capacity: they make the round reach n=5 and
        # leave something behind in the reserve list.
        entry("halo-ci", "endorsed", ["x86_64"], 32768, 524288, ["docker"], 2, (),
              True),
        entry("ivy-lap", "anonymous", ["x86_64"], 16384, 262144, ["unshare"], 1,
              (), True),
    ]
    entries.sort(key=lambda e: e["key_id"])
    return {
        "schema_version": 1,
        "type": "gitiup-roster-1",
        "epoch": 41,
        "prev_roster_digest": digest_str(hashlib.sha256(b"gitiup roster epoch 40").digest()),
        "issued_at_us": 1792771200000000,
        "valid_until_us": 1793376000000000,
        "epoch_interval_us": 604800000000,
        "entries": entries,
        "signatures": [],
    }


def build_round(roster: dict) -> dict:
    return {
        "kind": "round",
        "schema_version": 1,
        "round_kind": ROUND_KIND,
        "roster_epoch": roster["epoch"],
        "roster_digest": digest_of(roster),
        "change_id": "chg-000000000000f00d",
        "head_oid": "sha1:" + hashlib.sha1(b"gitiup change head for ADR-0002").hexdigest(),
        "job_id": "build/matrix/linux-x86_64",
        "attempt": 0,
        "required_capabilities": {
            "arch": "x86_64",
            "ram_mb": 8192,
            "disk_mb": 51200,
            "image_digests": [IMAGE],
            "sandboxes": ["docker", "unshare"],
            "min_sandbox_level": 1,
        },
        # brin is the proposer: naming their principal key excludes the whole
        # family. gus-pi is quarantined after a divergent round (msi.8).
        "exclusions": sorted([PRINCIPALS["brin"].key_id, BOXES["gus-pi"].key_id]),
        "policy": {
            "n": 5,
            "reserves": 2,
            "required_agree": 4,
            "tier_floor": "anonymous",
            "tier_caps": {"trusted": 1, "endorsed": 4, "anonymous": 1},
            "max_per_identity": 1,
        },
    }


# ---------------------------------------------------------------------------
# Reporting and entry point
# ---------------------------------------------------------------------------
NAME = {}
for _box, _k in BOXES.items():
    NAME[_k.key_id] = _box


def labels(sel: dict) -> list:
    """Human rows for the ADR's worked-example table."""
    by_id = {e["key_id"]: e for e in build_roster()["entries"]}
    rows = []
    for cand in sel["candidates"]:
        e = by_id[cand["key_id"]]
        verdict = cand["excluded_by"] or (
            "selected" if cand["selected"] else "reserve (" + cand["greedy_reason"] + ")"
            if cand["greedy"] == "skip"
            else "reserve"
        )
        rank = ""
        for s in sel["selected"]:
            if s["key_id"] == cand["key_id"]:
                rank = str(s["rank"])
        rows.append(
            {
                "machine": NAME[cand["key_id"]],
                "principal": NAME[cand["key_id"]].split("-")[0],
                "tier": e["tier"],
                "arch": "/".join(e["capabilities"]["arch"]),
                "ram_mb": e["capabilities"]["ram_mb"],
                "disk_mb": e["capabilities"]["disk_mb"],
                "sandbox": "+".join(e["capabilities"]["sandboxes"]),
                "level": e["capabilities"]["sandbox_level"],
                "score": cand["score"],
                "eligible": cand["eligible"],
                "verdict": verdict,
                "rank": rank,
            }
        )
    return rows


def short(text: str, keep: int = 12) -> str:
    """Display-only: a 64-hex digest in a terminal line is noise, in a file it is
    the contract."""
    return re.sub(r"[0-9a-f]{%d}[0-9a-f]{8,}" % keep, lambda m: m.group(0)[:keep] + "\u2026", text)


def render_table(sel: dict) -> str:
    rows = labels(sel)
    head = (
        f"{'#':<3} {'machine':<13} {'principal':<11} {'tier':<10} {'arch':<9} "
        f"{'ram':>6} {'disk':>8} {'sandbox':<15} {'score':<20} {'verdict':<22}"
    )
    out = [head, "-" * len(head)]
    for i, r in enumerate(rows, 1):
        out.append(
            f"{(r['rank'] or chr(45)):<3} {r['machine']:<13} {r['principal']:<11} "
            f"{r['tier']:<10} {r['arch']:<9} {r['ram_mb']:>6} {r['disk_mb']:>8} "
            f"{r['sandbox']:<15} {r['score'][:16]:<20} {r['verdict']:<22}"
        )
    return "\n".join(out)


def uniformity(rounds: int) -> str:
    """Chi-square over `rounds` rounds on a homogeneous roster: evidence that the
    score ordering does not favour anyone (giti-msi.3's acceptance criterion)."""
    keys = [Key("uniform-%02d" % i) for i in range(12)]
    roster = {
        "entries": [
            {
                "key_id": k.key_id,
                "identity": k.key_id,
                "tier": "endorsed",
                "capabilities": {
                    "arch": ["x86_64"],
                    "ram_mb": 65536,
                    "disk_mb": 1048576,
                    "image_cache": [],
                    "can_pull": True,
                    "sandboxes": ["docker"],
                    "sandbox_level": 2,
                },
                "epochs_valid": {"from": 0, "to": 1 << 30},
            }
            for k in keys
        ]
    }
    base = build_round(build_roster())
    base = {k: v for k, v in base.items() if k != "exclusions"}
    base["exclusions"] = []
    base["policy"] = {
        "n": 5,
        "reserves": 0,
        "required_agree": 4,
        "tier_floor": "anonymous",
        "tier_caps": {"trusted": 99, "endorsed": 99, "anonymous": 99},
        "max_per_identity": 1,
    }
    secret = selection_secret()
    counts = {k.key_id: 0 for k in keys}
    first = {k.key_id: 0 for k in keys}
    for i in range(rounds):
        inputs = dict(base)
        inputs["change_id"] = "chg-%016x" % i
        sel = select(roster, inputs, secret)
        for s in sel["selected"]:
            counts[s["key_id"]] += 1
        first[sel["selected"][0]["key_id"]] += 1
    expect_any = rounds * 5 / len(keys)
    expect_first = rounds / len(keys)
    chi_any = sum((c - expect_any) ** 2 / expect_any for c in counts.values())
    chi_first = sum((c - expect_first) ** 2 / expect_first for c in first.values())
    df = len(keys) - 1
    return (
        f"{rounds} rounds over {len(keys)} identical candidates, n=5\n"
        f"  selected-count  chi2 = {chi_any:.3f}  (df {df}, p>0.01 below 24.725)\n"
        f"  rank-1-count    chi2 = {chi_first:.3f}  (df {df}, p>0.01 below 24.725)\n"
        f"  min/max selected-count = {min(counts.values())}/{max(counts.values())}"
        f" against expectation {expect_any:.1f}"
    )


def write(path, data, pretty=False):
    body = (
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode() if pretty else canonical(data)
    with open(path, "wb") as fh:
        fh.write(body)
    return body


def build_all():
    """The three fixture documents, exactly as they are committed."""
    roster = build_roster()
    round_inputs = build_round(roster)
    secret = selection_secret()
    sel = select(roster, round_inputs, secret)
    by_name = {NAME[e["key_id"]]: e["key_id"] for e in roster["entries"]}
    cases = []
    for label in ("ivy-lap", "ada-primary"):
        voided = [by_name[label]]
        nxt = promote(roster, round_inputs, secret, voided)
        chosen = {x["key_id"] for x in sel["selected"]}
        added = [x for x in nxt["selected"] if x["key_id"] not in chosen]
        cases.append(
            {
                "voided": voided,
                "voided_machine": label,
                "promoted": added[0] if added else None,
                "selected_after": len(nxt["selected"]),
                "sufficient": nxt["sufficient"],
            }
        )
    sel["promotion"] = {
        "rule": "re-run select with exclusions + voided, same seed and same epoch "
        "(ADR-0002 D3): the ordering does not change, only the pool does",
        "cases": cases,
        "note": "voiding a seat frees a slot for the highest-scoring eligible "
        "remainder; if caps leave no substitute the round is short, which is "
        "Insufficient (giti-msi.7) or an escalation (giti-msi.8), never a lower bar",
    }
    return roster, round_inputs, sel


def check() -> int:
    """Re-run and compare against the committed files: what a CI test does."""
    roster, round_inputs, sel = build_all()
    want = {
        "roster.json": canonical(roster),
        "round.json": canonical(round_inputs),
        "selection.json": (
            json.dumps(sel, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode(),
    }
    bad = []
    for name, body in want.items():
        path = os.path.join(HERE, name)
        with open(path, "rb") as fh:
            if fh.read() != body:
                bad.append(name)
    if bad:
        print("stale fixtures: " + ", ".join(sorted(bad)) + " (run generate.py)")
        return 1
    print("fixtures match: roster.json, round.json, selection.json")
    return 0


def main(argv):
    if "--check" in argv:
        return check()
    roster, round_inputs, sel = build_all()
    roster_bytes = write(os.path.join(HERE, "roster.json"), roster)
    assert round_inputs["roster_digest"] == digest_of(roster)
    write(os.path.join(HERE, "round.json"), round_inputs)
    write(os.path.join(HERE, "selection.json"), sel, pretty=True)

    if "--uniform" in argv:
        rounds = 100000
        if "--rounds" in argv:
            rounds = int(argv[argv.index("--rounds") + 1])
        print(uniformity(rounds))
        return 0
    print(render_table(sel))
    print()
    print(f"roster digest   {short(digest_of(roster))}")
    print(f"round id        {short(sel['round_id'], 12)}")
    print(f"seed (revealed) {sel['seed']}")
    print(f"eligible        {sel['eligible']} of {len(roster['entries'])}, sufficient={sel['sufficient']}")
    print("selected        " + ", ".join(
        f"{s['rank']}:{NAME[s['key_id']]}({s['handle'][:12]})" for s in sel["selected"]))
    print("reserves        " + ", ".join(NAME[r["key_id"]] for r in sel["reserves"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
