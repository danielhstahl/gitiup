#!/usr/bin/env python3
"""Reference implementation of the gitiup repository policy v1 (ADR-0004).

Standard library only, and deliberately a *second* implementation: the vectors
here are what `gitiup policy publish|show|explain` (`giti-91m.2`, `.3`),
`gitiup verify change` (`giti-91m.4`), the pre-receive hook (`giti-91m.5`) and the
quorum's round inputs (`giti-zp1.2`, `giti-msi.7`) all have to agree on. Every rule
implemented here is quoted from
../0004-published-policy-format-signing-and-resolution.md (D2, D3, D5, D6, D9).

The canonicaliser, the PAE framing, the Ed25519 code and the fixture keys are
imported from `../change-v1/generate.py` rather than copied: ADR-0003 D11's rule is
that there is **one** canonicaliser, and a fixture set that re-implemented it would
be a second one — the exact failure that rule exists to prevent.

    python3 generate.py            # print the table, rewrite the vectors
    python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
    python3 generate.py --selftest # primitives, the refusal table, the history walk
    python3 generate.py --verify   # re-derive every committed record from its bytes

The signatures here are real (RFC 8032, `verify_strict` semantics) and, when OpenSSL
is on `PATH`, cross-checked against it, so "signed by the owner" means the same thing
in Python, in Rust, and in somebody else's crypto library.
"""

import copy
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_SIBLING = os.path.join(os.path.dirname(HERE), "change-v1", "generate.py")


def _load_primitives():
    """Import the change-v1 generator as a module: one canonicaliser, one PAE,
    one Ed25519, one set of fixture keys, for all of gitiup's fixtures."""
    spec = importlib.util.spec_from_file_location("gitiup_change_vectors", _SIBLING)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


chg = _load_primitives()

canon = chg.canon
pae = chg.pae
sha256_hex = chg.sha256_hex
digest_str = chg.digest_str
ed25519_verify = chg.ed25519_verify
FixtureKey = chg.FixtureKey
openssl_verify = chg.verify_with_openssl

# ---------------------------------------------------------------------------
# Constants (ADR-0004 D2, D6)
# ---------------------------------------------------------------------------
POLICY_TYPE = "gitiup-policy-1"
POLICY_PAYLOAD_TYPE = "application/vnd.gitiup.policy+json"
SCHEMA_VERSION = 1

#: The `previous_digest` of the first policy a store ever advertised (D2). A zero
#: digest rather than an omitted field because the canonical form forbids `null`
#: (ADR-0001 D1 rule 5) and "there was no predecessor" is a fact, not an absence.
GENESIS_PREVIOUS = "sha256:" + ("00" * 32)

#: The clock the vectors are written against, so a regeneration is reproducible
#: (2026-10-25T12:00:00Z). D6 refuses a policy dated more than the skew allowance
#: into the future, so the fixture clock has to be fixed rather than `now`.
NOW_US = 1_793_092_800_000_000
MAX_CLOCK_SKEW_US = 300 * 1_000_000

MAX_POLICY_BYTES = 32 * 1024
MAX_ANNOTATIONS = 16
MAX_ANNOTATION_VALUE = 512
MAX_PROTECTS = 32
MAX_GLOB = 128
MAX_BY_JOB = 64
MAX_PRINCIPAL = 128
MAX_SANDBOXES = 32
MAX_IMAGE_DIGESTS = 32
MAX_CHAIN_WALK = 64

#: The rung a policy may not demand less of (D5). `0` is "nothing confined this",
#: which no repository gets to require of somebody else's machine.
MIN_SANDBOX_LEVEL = 1

RE_POLICY_TYPE = re.compile(r"^gitiup-policy-1$")
RE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RE_KEY_ID = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
RE_ANNOTATION_KEY = re.compile(r"^x_[a-z0-9]+(?:_[a-z0-9]+)+$")

#: The fields a `gitiup-policy-1` document may carry, in canonical (that is,
#: alphabetical) order — which is also the order a person reads one in: who set
#: these rules, when they started, what they cover, what they demand, who signed.
POLICY_FIELDS = [
    "annotations",
    "effective_from_us",
    "expires_at_us",
    "owner",
    "previous_digest",
    "protects",
    "quorum",
    "revision",
    "rules",
    "schema_version",
    "signatures",
    "type",
]

#: The rule body is `gitiup_attest::PolicyFile` verbatim (D2): one vocabulary for
#: "what a proof must satisfy", in the tree file and in the published record alike.
RULE_FIELDS = [
    "allow_simulated",
    "allowed_sandboxes",
    "allowed_tiers",
    "expected_commit",
    "expected_result_digest",
    "max_age_us",
    "max_clock_skew_us",
    "require_arch",
    "require_env_fingerprint",
    "require_env_match",
    "require_image_digest",
    "require_image_reference",
    "require_normalisation_version",
    "require_os",
    "require_os_version",
    "require_provider",
    "require_runner",
    "require_toolchain",
    "schema_version",
    "trust_key_ids",
    "min_signatures",
]

#: The quorum block: `gitiup_quorum::SelectionPolicy` verbatim, plus the per-job
#: overrides and the verifier-capability floor (D5).
SELECTION_FIELDS = [
    "max_per_identity",
    "n",
    "required_agree",
    "reserves",
    "tier_caps",
    "tier_floor",
]
REQUIREMENTS_FIELDS = [
    "arch",
    "disk_mb",
    "image_digests",
    "min_sandbox_level",
    "ram_mb",
    "sandboxes",
]

ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "x64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}
TIERS = ["simulated", "local", "quorum"]
ROSTER_TIERS = ["anonymous", "endorsed", "trusted"]
ENV_MATCH = ["strict", "major", "off"]

#: The trust roots a verifier is configured with (D3). Fixtures use the local
#: keystore of the upstream owner, so a policy signed by the fork's key is refused
#: rather than "used but distrusted" (D3's decision).
OWNER_ADA = FixtureKey("ada", "ada@example.com")
OWNER_SOFIA = FixtureKey("sofia", "sofia@example.org")
CI_KEY = FixtureKey("ci-runner", "ci@ci.example.com")
TRUST_ROOTS = {OWNER_ADA.key_id}


class Refuse(Exception):
    """A document a conforming reader must reject, carrying the reason token."""

    def __init__(self, token, detail=""):
        super().__init__("%s: %s" % (token, detail))
        self.token = token
        self.detail = detail


#: The exit code each refusal token maps to, through the taxonomy ADR-0001 D7 fixed
#: and ADR-0004 D9 re-quotes: 6 refused, 7 bad signature, 8 not-its-own-bytes.
TOKEN_EXIT = {
    # A key id that is not the fingerprint of the key offered is a signature-class
    # failure, exactly as ADR-0003 D11 treats it: the bytes are fine and the identity
    # claim is not.
    "bad_signature": 7,
    "key_id_derivation": 7,
    "not_canonical": 8,
    "digest_mismatch": 8,
}
DEFAULT_EXIT = 6


def exit_of(token):
    return TOKEN_EXIT.get(token, DEFAULT_EXIT)


def require(condition, token, detail=""):
    if not condition:
        raise Refuse(token, detail)


# ---------------------------------------------------------------------------
# The document (ADR-0004 D2)
# ---------------------------------------------------------------------------
def body_of(record):
    """The signed body: the record with its own signature list removed — the rule
    `gitiup_quorum::record::body_bytes` applies to rosters, rounds and verdicts."""
    return canon({k: v for k, v in record.items() if k != "signatures"})


def body_digest(record):
    return digest_str(body_of(record))


def record_digest(record):
    return digest_str(canon(record))


def sign(record, key):
    require(not record.get("signatures"), "signatures_already_present")
    record = copy.deepcopy(record)
    record["signatures"] = [key.sign(pae(POLICY_PAYLOAD_TYPE, body_of(record)))]
    return record


def resolve_shorthand(rules):
    """What `gitiup policy publish` does to a tree file before signing it (D2).

    `allow_simulated` is the one-line spelling a human writes in `gitiup-policy.json`;
    the signed document names its tiers once, in `allowed_tiers`. Lists are also
    sorted and deduplicated here, so two authors who wrote the same rules in a
    different order produce **byte-identical** bytes, and a re-publish that changed
    nothing cannot move the digest a verdict cites (D6).
    """
    out = dict(rules)
    shorthand = out.pop("allow_simulated", None)
    tiers = list(out.get("allowed_tiers") or ["local"])
    if shorthand is not None and "allowed_tiers" not in out and shorthand:
        tiers.append("simulated")
    out["allowed_tiers"] = sorted(set(tiers))
    for field in ("allowed_sandboxes",):
        if field in out:
            out[field] = sorted(set(out[field]))
    return out


def require_normalised(record):
    """The normalisation rule, checked on the way out as well as on the way in (D2).

    A reader is not obliged to re-normalise: the bytes signed are the bytes read, so
    the invariant lives on the publisher and on this check."""
    def check(values, where):
        require(values == sorted(set(values)), "not_normalised", where)

    rules = record["rules"]
    check(rules.get("allowed_tiers") or [], "rules.allowed_tiers")
    check(rules.get("allowed_sandboxes") or [], "rules.allowed_sandboxes")
    check(record["protects"], "protects")
    quorum = record.get("quorum") or {}
    requirements = quorum.get("requirements") or {}
    check(requirements.get("sandboxes") or [], "quorum.requirements.sandboxes")
    check(requirements.get("image_digests") or [], "quorum.requirements.image_digests")


def filed(record):
    """Where a published policy lives (D1, D7)."""
    digest = record_digest(record)
    return {
        "kv": "kv/policy/%s" % sha256_hex(canon(record)),
        "refs": ["refs/gitiup/policy/current"],
        "digest_hex": digest.split(":", 1)[1],
    }


# ---------------------------------------------------------------------------
# Validation (ADR-0004 D5, D6, D9) — the order D9 fixes
# ---------------------------------------------------------------------------
def check_bytes(record, raw):
    """Steps 1 and 2 of D9: is this what it says it is, byte for byte."""
    require(len(raw) <= MAX_POLICY_BYTES, "size_exceeded", "%d bytes" % len(raw))
    try:
        again = canon(json.loads(raw.decode("utf-8")))
    except Exception as exc:  # not even JSON: same class of refusal
        raise Refuse("not_canonical", str(exc))
    require(again == raw, "not_canonical", "the bytes are not their own canonical form")


def check_structure(record):
    """Steps 3 and 4: the fields, the derivations, the signature."""
    require(isinstance(record, dict), "invalid", "not an object")
    unknown = [key for key in record if key not in POLICY_FIELDS]
    require(not unknown, "field_unknown", ", ".join(sorted(unknown)))
    # The rule body's keys are schema too, so they are refused here (step 1) and not
    # after the signature: a typo in a policy must print the typo, not "bad signature".
    rules = record.get("rules") or {}
    require(isinstance(rules, dict), "rules_shape")
    unknown_rules = [key for key in rules if key not in RULE_FIELDS]
    require(not unknown_rules, "field_unknown", ", ".join(sorted(unknown_rules)))
    # `signatures` is absent rather than empty in a document nobody signed, and the
    # refusal that names it is `unsigned`, not "missing field" (D9).
    missing = [key for key in POLICY_FIELDS if key not in record and key
               not in ("annotations", "expires_at_us", "quorum", "signatures")]
    require(not missing, "field_missing", ", ".join(missing))
    require(record["type"] == POLICY_TYPE and record["schema_version"] == SCHEMA_VERSION,
            "unknown_schema", "%s / %s" % (record["type"], record["schema_version"]))
    require(isinstance(record["revision"], int) and record["revision"] >= 1,
            "revision_invalid")
    require(RE_DIGEST.match(record["previous_digest"]) is not None,
            "previous_digest_shape")
    require(isinstance(record["effective_from_us"], int), "effective_from_shape")
    if "expires_at_us" in record:
        require(record["expires_at_us"] > record["effective_from_us"],
                "expires_before_effective")
        require(record["expires_at_us"] > NOW_US, "expired",
                "expired %d us ago" % (NOW_US - record["expires_at_us"]))
    require(record["effective_from_us"] <= NOW_US + MAX_CLOCK_SKEW_US,
            "future_dated")

    owner = record["owner"]
    require(set(owner) == {"key_id", "principal"}, "owner_shape")
    require(RE_KEY_ID.match(owner["key_id"]) is not None, "owner_key_shape")
    require(0 < len(owner["principal"]) <= MAX_PRINCIPAL, "owner_principal_shape")

    protects = record["protects"]
    require(0 < len(protects) <= MAX_PROTECTS, "protects_shape")
    for glob in protects:
        require(len(glob) <= MAX_GLOB, "protects_shape", glob)
        # D5: a policy may gate what is trusted, never what is merely offered.
        require(glob.startswith("refs/heads/"), "protects_out_of_scope", glob)

    if "annotations" in record:
        notes = record["annotations"]
        require(len(notes) <= MAX_ANNOTATIONS, "annotations_shape")
        for key, value in notes.items():
            require(RE_ANNOTATION_KEY.match(key) is not None, "annotation_key_shape", key)
            require(0 < len(value) <= MAX_ANNOTATION_VALUE, "annotation_value_shape", key)

    signatures = record.get("signatures") or []
    require(len(signatures) == 1, "unsigned" if not signatures else "signature_count")
    entry = signatures[0]
    require(entry["key_id"] == owner["key_id"], "owner_mismatch")
    require(entry["key_id"] == key_id_from(entry["public_key"]),
            "key_id_derivation", "a key id is derived, never typed")
    require(ed25519_verify(_pub(entry), pae(POLICY_PAYLOAD_TYPE, body_of(record)),
                           _sig(entry)), "bad_signature")


def key_id_from(public_key_line):
    """`SHA256:<unpadded b64>` of the SSH wire blob: ADR-0001 D3, re-derived from the
    key offered rather than read from the document that claims it."""
    import base64
    import hashlib
    blob = base64.b64decode(public_key_line.split()[1])
    return "SHA256:" + chg.b64u(hashlib.sha256(blob).digest())


def check_trust(record, roots):
    """Step 5 of D9: the signature is valid *and* the signer is somebody.

    Note what is **not** checked here: the policy's own `trust_key_ids` are who may sign
    an *attestation*, and a repository whose owner publishes and whose CI runner signs
    is the normal case, not a mismatch. The verifier's trust roots decide who may set
    the rules; the anchors decide who may supply a proof."""
    signer = record["signatures"][0]["key_id"]
    require(signer in roots, "signer_untrusted", signer)
    rules = record["rules"]
    anchors = rules.get("trust_key_ids") or []
    require(anchors, "no_trust_anchors", "an empty anchor list trusts nobody")


def publish_warnings(record, roots, now_us=None):
    """Advice `gitiup policy publish` prints (D8) — loud, and never a refusal.

    Each one is a case that is legitimate but frequently a mistake, which is the only
    thing a warning is for."""
    now_us = NOW_US if now_us is None else now_us
    out = []
    anchors = set(record["rules"].get("trust_key_ids") or [])
    if not anchors & roots:
        out.append(
            "none of the trust anchors is a key this machine holds: correct when a CI "
            "runner signs and the owner publishes, a mistake if you meant to sign "
            "yourself"
        )
    if "expires_at_us" in record and record["expires_at_us"] - now_us < 7 * 86_400 * 10 ** 6:
        out.append("the policy expires within a week; a policy that expires silently "
                   "stops a merge gate the same day")
    quorum = record.get("quorum") or {}
    for where, selection in [("quorum.default", quorum.get("default"))] + [
        ("quorum.by_job[%s]" % glob, sel) for glob, sel in (quorum.get("by_job") or {}).items()
    ]:
        if selection and selection["required_agree"] == selection["n"]:
            out.append(
                "%s demands unanimity: one verifier that is offline is no verdict, and "
                "the escalation round asks for more" % where
            )
    if (record["rules"].get("max_age_us") or 0) > 7 * 86_400 * 10 ** 6:
        out.append(
            "the freshness window is over a week: how long a policy change can be dodged "
            "with an old proof (D6)"
        )
    return out


def check_rules(rules):
    """`PolicyFile`'s own rules, re-implemented so a *published* policy cannot say
    something the local file parser would refuse."""
    require(isinstance(rules, dict), "rules_shape")
    if "schema_version" in rules:
        require(rules["schema_version"] == SCHEMA_VERSION, "unknown_schema")
    tiers = rules.get("allowed_tiers")
    if tiers is None:
        tiers = ["local"]
    require(tiers, "empty_tiers", "a policy that accepts no tier accepts no proof")
    for tier in tiers:
        require(tier in TIERS, "tier_unknown", tier)
    # The same coherence rule `PolicyFile::from_json` already enforces (and which this
    # crate therefore does not re-invent): a policy that argues with itself is refused,
    # not resolved by a precedence nobody remembers. A reader accepts either spelling;
    # `gitiup policy publish` resolves the shorthand and writes only `allowed_tiers`.
    if "allow_simulated" in rules and "allowed_tiers" in rules:
        require(rules["allow_simulated"] == ("simulated" in tiers),
                "simulated_contradiction")
    require(rules.get("min_signatures", 1) >= 1, "min_signatures_zero")
    for anchor in rules.get("trust_key_ids") or []:
        require(RE_KEY_ID.match(anchor) is not None, "anchor_key_shape", anchor)
    match = rules.get("require_env_match", "strict")
    require(match in ENV_MATCH, "env_match_unknown", match)
    published = [key for key in rules if key.startswith("require_")
                 and key not in ("require_env_match", "require_normalisation_version")]
    require(not (match == "off" and published), "env_match_off",
            "a requirement is published while the comparison is off")
    for name in rules.get("allowed_sandboxes") or []:
        require(name not in ("", "none", "off", "no", "plain", "inprocess"),
                "sandbox_forbidden", name)
    require(len(rules.get("allowed_sandboxes") or []) <= MAX_SANDBOXES,
            "sandbox_shape")


def check_quorum(record):
    """The Epic 3 block: the numbers that decide a quorum, and what the repository
    may ask of a verifier (D5)."""
    quorum = record.get("quorum")
    rules = record["rules"]
    if quorum is None:
        return
    require(set(quorum) <= {"by_job", "default", "requirements"}, "quorum_shape",
            ", ".join(sorted(set(quorum) - {"by_job", "default", "requirements"})))
    if "default" in quorum:
        check_selection(quorum["default"])
    by_job = quorum.get("by_job") or {}
    require(len(by_job) <= MAX_BY_JOB, "by_job_shape")
    for glob, selection in by_job.items():
        require(0 < len(glob) <= MAX_GLOB, "by_job_shape", glob)
        check_selection(selection)
    tiers = rules.get("allowed_tiers") or ["local"]
    if "quorum" in tiers:
        require("default" in quorum or by_job, "quorum_without_rules",
                "the tier is allowed but no quorum rules decide it")
    if "quorum" not in tiers and "default" in quorum:
        raise Refuse("tier_not_allowed", "quorum rules with a tier that refuses quorum")
    requirements = quorum.get("requirements")
    if requirements is None:
        return
    unknown = [key for key in requirements if key not in REQUIREMENTS_FIELDS]
    require(not unknown, "field_unknown", ", ".join(sorted(unknown)))
    require(requirements.get("sandboxes"), "requirements_unsatisfiable",
            "no sandbox backend is acceptable, so no verifier can be seated")
    require(len(requirements.get("sandboxes") or []) <= MAX_SANDBOXES, "requirements_shape")
    for image in (requirements.get("image_digests") or [])[:MAX_IMAGE_DIGESTS + 1]:
        require(RE_DIGEST.match(image) is not None, "requirements_shape", image)
    require(len(requirements.get("image_digests") or []) <= MAX_IMAGE_DIGESTS,
            "requirements_shape")
    require(requirements.get("ram_mb", 1) > 0 and requirements.get("disk_mb", 1) > 0,
            "requirements_unsatisfiable", "a zero resource floor selects any box")
    level = requirements.get("min_sandbox_level", 0)
    require(isinstance(level, int) and level >= MIN_SANDBOX_LEVEL, "sandbox_floor",
            "a policy may not demand less confinement than the verifier's own floor")
    allowed = rules.get("allowed_sandboxes") or []
    if allowed:
        disjoint = [name for name in requirements["sandboxes"] if name not in allowed]
        require(not disjoint, "sandbox_disjoint", ", ".join(disjoint))
    if requirements.get("arch") and rules.get("require_arch"):
        require(ARCH_ALIASES.get(requirements["arch"], requirements["arch"])
                == ARCH_ALIASES.get(rules["require_arch"], rules["require_arch"]),
                "arch_conflict", "%s vs %s" % (requirements["arch"], rules["require_arch"]))
    require(requirements.get("arch") in ARCH_ALIASES.values(), "arch_not_canonical",
            "spell it the way Arch canonicalises it, once")


def check_selection(selection):
    unknown = [key for key in selection if key not in SELECTION_FIELDS]
    require(not unknown, "field_unknown", ", ".join(sorted(unknown)))
    require(selection.get("n", 1) >= 1, "n_zero")
    require(selection.get("required_agree", 1) >= 1, "required_agree_zero",
            "a threshold of 0 certifies anything, including nothing")
    require(selection["required_agree"] <= selection["n"], "required_agree_unreachable",
            "%d of %d seats" % (selection["required_agree"], selection["n"]))
    require(selection.get("max_per_identity", 1) >= 1, "max_per_identity_zero")
    floor = selection.get("tier_floor", "anonymous")
    require(floor in ROSTER_TIERS, "tier_floor_unknown", floor)
    for tier in (selection.get("tier_caps") or {}):
        require(tier in ROSTER_TIERS, "tier_caps_unknown", tier)


def check_chain(record, history):
    """Step 6 of D9 on the read path: the chain has to be *continuous*, or "which
    rules were in force then?" has no answer (D6)."""
    previous = record["previous_digest"]
    if previous == GENESIS_PREVIOUS:
        require(record["revision"] == 1, "revision_gap", "genesis must be revision 1")
        return
    if previous not in history:
        raise Refuse("chain_broken", previous)
    parent = history[previous]
    require(parent["revision"] == record["revision"] - 1, "revision_gap",
            "%d follows %d" % (record["revision"], parent["revision"]))
    require(parent["effective_from_us"] < record["effective_from_us"], "effective_from_backwards")


def validate(record, roots=None, history=None):
    """Every read path (`.2`, `.3`, `.4`, `.5`) runs this, in this order (D9)."""
    roots = TRUST_ROOTS if roots is None else roots
    history = {} if history is None else history
    check_structure(record)
    check_trust(record, roots)
    check_rules(record["rules"])
    check_quorum(record)
    check_chain(record, history)
    require_normalised(record)


# ---------------------------------------------------------------------------
# The history walk (ADR-0004 D6)
# ---------------------------------------------------------------------------
def in_force_at(chain, at_us):
    """The policy in force at `at_us`: the newest one that had taken effect.

    `chain` is the list of policies reachable by walking `previous_digest` from the
    advertised one, newest first. Nothing here consults a live service: the whole
    question is answerable from bytes already fetched, which is the point of D6."""
    for policy in sorted(chain, key=lambda p: p["effective_from_us"], reverse=True):
        if policy["effective_from_us"] <= at_us:
            if "expires_at_us" in policy and policy["expires_at_us"] < at_us:
                raise Refuse("expired_history", policy["type"])
            return policy
    raise Refuse("policy_history_missing", "nothing in the chain had taken effect")


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------
TIMESTAMP = {
    # When each policy took effect, and the two probe points the walk is tested at.
    "project_r1": 1_790_828_800_000_000,   # 2026-10-01T00:00:00Z
    "project_r2": 1_792_467_200_000_000,   # 2026-10-20T00:00:00Z
    "personal_r1": 1_790_828_800_000_000,
    "fork_r1": 1_791_433_600_000_000,      # 2026-10-08T00:00:00Z
    "probe_before": 1_791_350_400_000_000,  # 2026-10-07T00:00:00Z
    "probe_after": 1_792_985_000_000_000,   # 2026-10-25T12:03:20Z
    # A run made before the store had any policy at all: the walk must refuse rather
    # than fall back to the newest rules (D6).
    "probe_no_policy": 1_790_828_799_999_999,
}


def selection(n, agree, floor="endorsed", caps=None, reserves=2, per_identity=1):
    return {
        "max_per_identity": per_identity,
        "n": n,
        "required_agree": agree,
        "reserves": reserves,
        "tier_caps": caps or {"anonymous": 1, "endorsed": 4, "trusted": 1},
        "tier_floor": floor,
    }


def build():
    """Every case, in the order a reader would meet them."""
    records = {}

    # 1. The personal bucket repo: one owner, one machine, one local run.
    personal = {
        "effective_from_us": TIMESTAMP["personal_r1"],
        "owner": {"key_id": OWNER_ADA.key_id, "principal": "Ada Hale"},
        "previous_digest": GENESIS_PREVIOUS,
        "protects": ["refs/heads/**"],
        "revision": 1,
        "rules": {
            "allowed_sandboxes": ["docker", "landlock", "podman", "unshare"],
            "allowed_tiers": ["local"],
            "max_age_us": 86_400_000_000,
            "min_signatures": 1,
            "require_arch": "amd64",
            "require_env_match": "major",
            "require_toolchain": {"rustc": "1.99"},
            "schema_version": 1,
            "trust_key_ids": [CI_KEY.key_id],
        },
        "schema_version": SCHEMA_VERSION,
        "signatures": [],
        "type": POLICY_TYPE,
    }
    records["personal"] = sign(personal, OWNER_ADA)

    # 2. A project: nothing counts unless a quorum agrees.
    project = {
        "annotations": {"x_gitiup_policy_note": "quorum or nothing; see docs/policy.md"},
        "effective_from_us": TIMESTAMP["project_r1"],
        "owner": {"key_id": OWNER_ADA.key_id, "principal": "Ada Hale"},
        "previous_digest": GENESIS_PREVIOUS,
        "protects": ["refs/heads/**", "refs/heads/stable/**"],
        "quorum": {
            "by_job": {"arm-*": selection(3, 3, caps={"anonymous": 0, "endorsed": 3})},
            "default": selection(5, 4),
            "requirements": {
                "arch": "x86_64",
                "disk_mb": 51200,
                "image_digests": ["sha256:" + ("ab" * 32)],
                "min_sandbox_level": 2,
                "ram_mb": 8192,
                "sandboxes": ["docker", "podman"],
            },
        },
        "revision": 1,
        "rules": {
            "allowed_sandboxes": ["docker", "podman"],
            "allowed_tiers": ["quorum"],
            "max_age_us": 43_200_000_000,
            "min_signatures": 1,
            "require_arch": "amd64",
            "require_image_digest": "sha256:" + ("ab" * 32),
            "require_normalisation_version": 1,
            "schema_version": 1,
            "trust_key_ids": [OWNER_ADA.key_id, OWNER_SOFIA.key_id],
        },
        "schema_version": SCHEMA_VERSION,
        "signatures": [],
        "type": POLICY_TYPE,
    }
    records["project"] = sign(project, OWNER_ADA)

    # 3. The same project, a fortnight later, with the bar raised. The chain is the
    #    only thing that lets a gate judge a run made *before* this against the rules
    #    that were actually in force (D6).
    tightened = {
        "annotations": {"x_gitiup_policy_note": "four of five was not holding"},
        "effective_from_us": TIMESTAMP["project_r2"],
        "owner": {"key_id": OWNER_ADA.key_id, "principal": "Ada Hale"},
        "previous_digest": body_digest(records["project"]),
        "protects": ["refs/heads/**"],
        "quorum": {
            "by_job": {"arm-*": selection(3, 3, caps={"anonymous": 0, "endorsed": 3})},
            "default": selection(7, 5),
            "requirements": {
                "arch": "x86_64",
                "disk_mb": 51200,
                "image_digests": ["sha256:" + ("ab" * 32)],
                "min_sandbox_level": 3,
                "ram_mb": 8192,
                "sandboxes": ["docker", "podman"],
            },
        },
        "revision": 2,
        "rules": {
            "allowed_sandboxes": ["docker", "podman"],
            "allowed_tiers": ["quorum"],
            "max_age_us": 21_600_000_000,
            "min_signatures": 1,
            "require_arch": "amd64",
            "require_image_digest": "sha256:" + ("ab" * 32),
            "require_normalisation_version": 1,
            "schema_version": 1,
            "trust_key_ids": [OWNER_ADA.key_id, OWNER_SOFIA.key_id],
        },
        "schema_version": SCHEMA_VERSION,
        "signatures": [],
        "type": POLICY_TYPE,
    }
    records["project-tightened"] = sign(tightened, OWNER_ADA)

    # 4. A fork that inherits upstream's policy: the same bytes, the same digest, and
    #    nothing to explain — a policy a fork cannot weaken is the point of D1.
    records["fork-inherited"] = copy.deepcopy(records["project"])

    # 5. A fork that re-signs a weakened copy with its own key. Everything about it is
    #    well-formed; a verifier whose trust roots are upstream's refuses it (exit 6),
    #    which is D3's decision made checkable: unsigned-or-foreign is *refused*, never
    #    *untrusted-but-used*.
    weakened = copy.deepcopy(project)
    weakened = {k: v for k, v in weakened.items() if k != "annotations"}
    weakened["annotations"] = {"x_gitiup_policy_note": "my repo, my rules"}
    weakened["owner"] = {"key_id": OWNER_SOFIA.key_id, "principal": "Sofia Marin"}
    weakened["previous_digest"] = GENESIS_PREVIOUS
    weakened["quorum"] = {"default": selection(1, 1, floor="anonymous")}
    weakened["revision"] = 1
    weakened["rules"] = {
        "allowed_tiers": ["local", "quorum"],
        "max_age_us": 604_800_000_000,
        "min_signatures": 1,
        "schema_version": 1,
        "trust_key_ids": [OWNER_SOFIA.key_id],
    }
    weakened["signatures"] = []
    records["fork-weakened"] = sign(weakened, OWNER_SOFIA)
    return records


#: What each case teaches, for the README and the table.
NOTES = {
    "personal": "one owner, one runner: `local` from a named key, amd64, 24 h",
    "project": "nothing counts without a quorum: tier `quorum`, 5 seats 4 agree",
    "project-tightened": "revision 2, `previous_digest` names revision 1: the bar moved",
    "fork-inherited": "a fork that changes nothing: byte-identical, same digest",
    "fork-weakened": "a fork that re-signs a weaker policy: refused, not distrusted",
}


# ---------------------------------------------------------------------------
# The refusal table (ADR-0004 D9) — generated, mutated, and checked here
# ---------------------------------------------------------------------------
def refusals():
    """The refusal table: a defect, the token the reader must report, and the exit
    code it maps to. `.2`'s test list, as written.

    A defect is introduced *before signing* wherever it can be, because a mutation
    applied to a signed document is a broken signature and nothing else: the table
    would then teach "bad signature" thirty times. The three cases that are only
    defects after the fact — a body edited afterwards, a typed key id, an owner that
    does not match the signer — are applied afterwards on purpose."""
    unsigned = copy.deepcopy(build()["project"])
    unsigned.pop("signatures")

    def make(pre=(), signer="owner", post=()):
        victim = copy.deepcopy(unsigned)
        for mutation in pre:
            victim = apply_mutation(victim, mutation)
        if signer == "owner":
            victim = sign(victim, OWNER_ADA)
        elif signer is not None:
            victim = sign(victim, signer)
        for mutation in post:
            victim = apply_mutation(victim, mutation)
        return victim

    describe = describe_mutation
    cases = [
        # name, expected token, mutation (for the index), the defective document
        ("unknown field", "field_unknown",
         ("set", ("rules", "require_archh"), "x86_64"),
         make(pre=[("set", ("rules", "require_archh"), "x86_64")])),
        ("unsigned policy", "unsigned", ("drop", "signatures"), make(signer=None)),
        ("two signatures", "signature_count", ("dup-signature",),
         make(post=[("dup-signature",)])),
        ("signer is not the owner", "owner_mismatch", ("owner-key",),
         make(post=[("owner-key", OWNER_SOFIA.key_id)])),
        ("typed key id", "key_id_derivation", ("signer-key-id",),
         make(post=[("signer-key-id", OWNER_SOFIA.key_id)])),
        ("body edited after signing", "bad_signature", ("tamper",),
         make(post=[("set", ("rules", "min_signatures"), 9)])),
        ("signed by a stranger", "signer_untrusted", ("foreign-signer",),
         copy.deepcopy(build()["fork-weakened"])),
        ("no anchors at all", "no_trust_anchors", ("set", ("rules", "trust_key_ids"), []),
         make(pre=[("set", ("rules", "trust_key_ids"), [])])),
        ("unknown schema", "unknown_schema", ("set", ("schema_version",), 2),
         make(pre=[("set", ("schema_version",), 2)])),
        ("future-dated", "future_dated", ("set", ("effective_from_us",), NOW_US + 10 ** 9),
         make(pre=[("set", ("effective_from_us",), NOW_US + 10 ** 9)])),
        ("expired", "expired", ("set", ("expires_at_us",), NOW_US - 1),
         make(pre=[("set", ("expires_at_us",), NOW_US - 1)])),
        ("expiry before effect", "expires_before_effective",
         ("set", ("expires_at_us",), None),
         make(pre=[("set", ("expires_at_us",), unsigned["effective_from_us"])])),
        ("revision skips", "revision_gap", ("set", ("revision",), 9),
         make(pre=[("set", ("revision",), 9)])),
        ("previous_digest names nothing", "chain_broken",
         ("set", ("previous_digest",), "sha256:" + ("11" * 32)),
         make(pre=[("set", ("previous_digest",), "sha256:" + ("11" * 32))])),
        ("gates a contributor ref", "protects_out_of_scope",
         ("set", ("protects",), ["refs/changes/**"]),
         make(pre=[("set", ("protects",), ["refs/changes/**"])])),
        ("rules not in canonical order", "not_normalised",
         ("set", ("rules", "allowed_tiers"), ["quorum", "local"]),
         make(pre=[("set", ("rules", "allowed_tiers"), ["quorum", "local"])])),
        ("accepts no tier", "empty_tiers", ("set", ("rules", "allowed_tiers"), []),
         make(pre=[("set", ("rules", "allowed_tiers"), [])])),
        ("unknown tier", "tier_unknown", ("set", ("rules", "allowed_tiers"), ["cloud"]),
         make(pre=[("set", ("rules", "allowed_tiers"), ["cloud"])])),
        ("zero signatures required", "min_signatures_zero",
         ("set", ("rules", "min_signatures"), 0),
         make(pre=[("set", ("rules", "min_signatures"), 0)])),
        ("env match off with a requirement", "env_match_off",
         ("set", ("rules", "require_env_match"), "off"),
         make(pre=[("set", ("rules", "require_env_match"), "off")])),
        ("unconfined sandbox demanded", "sandbox_forbidden",
         ("add", ("rules", "allowed_sandboxes"), "none"),
         make(pre=[("add", ("rules", "allowed_sandboxes"), "none")])),
        ("threshold above seats", "required_agree_unreachable",
         ("set", ("quorum", "default", "required_agree"), 9),
         make(pre=[("set", ("quorum", "default", "required_agree"), 9)])),
        ("threshold of zero", "required_agree_zero",
         ("set", ("quorum", "default", "required_agree"), 0),
         make(pre=[("set", ("quorum", "default", "required_agree"), 0)])),
        ("unknown roster tier", "tier_floor_unknown",
         ("set", ("quorum", "default", "tier_floor"), "famous"),
         make(pre=[("set", ("quorum", "default", "tier_floor"), "famous")])),
        ("quorum rules, quorum refused", "tier_not_allowed",
         ("set", ("rules", "allowed_tiers"), ["local"]),
         make(pre=[("set", ("rules", "allowed_tiers"), ["local"])])),
        ("no sandbox can satisfy it", "requirements_unsatisfiable",
         ("set", ("quorum", "requirements", "sandboxes"), []),
         make(pre=[("set", ("quorum", "requirements", "sandboxes"), [])])),
        ("sandbox sets disjoint", "sandbox_disjoint",
         ("set", ("quorum", "requirements", "sandboxes"), ["landlock"]),
         make(pre=[("set", ("quorum", "requirements", "sandboxes"), ["landlock"])])),
        ("arch spelled two ways", "arch_conflict",
         ("set", ("quorum", "requirements", "arch"), "aarch64"),
         make(pre=[("set", ("quorum", "requirements", "arch"), "aarch64")])),
        ("zero resource floor", "requirements_unsatisfiable",
         ("set", ("quorum", "requirements", "ram_mb"), 0),
         make(pre=[("set", ("quorum", "requirements", "ram_mb"), 0)])),
        ("policy demands no confinement", "sandbox_floor",
         ("set", ("quorum", "requirements", "min_sandbox_level"), 0),
         make(pre=[("set", ("quorum", "requirements", "min_sandbox_level"), 0)])),
    ]

    out = []
    for name, token, mutation, victim in cases:
        raw = canon(victim)
        try:
            check_bytes(victim, raw)
            validate(victim)
            raise AssertionError("refusal %r (%s) was accepted" % (name, token))
        except Refuse as refusal:
            require(refusal.token == token, "wrong_token",
                    "%s: expected %s, got %s" % (name, token, refusal.token))
        out.append({"case": name, "token": token, "exit": exit_of(token),
                    "mutation": describe(mutation)})

    # Two refusals are about bytes rather than about a document, so they cannot be
    # mutations of one. Both are step 1 of D9, and both are the reader's first check
    # for the same reason: an oversized or non-canonical encoding is refused before
    # anything in it is believed.
    try:
        check_bytes(unsigned, b'{ "a": 1 }')
        raise AssertionError("a non-canonical encoding was accepted")
    except Refuse as refusal:
        require(refusal.token == "not_canonical", "wrong_token", refusal.token)
    out.append({"case": "not its own bytes", "token": "not_canonical",
                "exit": exit_of("not_canonical"), "mutation": "re-encode with whitespace"})
    flooded = apply_mutation(copy.deepcopy(unsigned), ("flood",))
    try:
        canon(flooded)
        raise AssertionError("an oversized policy was encoded")
    except chg.Refuse as refused:
        require("limit" in str(refused), "wrong_token", str(refused))
    out.append({"case": "over the size limit", "token": "size_exceeded",
                "exit": exit_of("size_exceeded"),
                "mutation": describe(("flood",)) + ", over the 32 KiB record limit"})
    return sorted(out, key=lambda entry: (entry["exit"], entry["token"]))


def apply_mutation(record, mutation):
    victim = copy.deepcopy(record)
    kind = mutation[0]
    if kind == "set":
        _, path, value = mutation
        node = victim
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
    elif kind == "add":
        _, path, value = mutation
        node = victim
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = list(node.get(path[-1]) or []) + [value]
    elif kind == "drop":
        victim.pop(mutation[1], None)
    elif kind == "dup-signature":
        victim["signatures"] = list(victim["signatures"]) * 2
    elif kind == "owner-key":
        victim["owner"]["key_id"] = mutation[1]
    elif kind == "signer-key-id":
        # A typed key id: the owner and the signature entry agree on one key, and the
        # public key offered is a different one.
        victim["owner"]["key_id"] = mutation[1]
        victim["signatures"][0]["key_id"] = mutation[1]
    elif kind == "flood":
        victim["annotations"] = {
            "x_gitiup_flood_%04d" % i: "y" * MAX_ANNOTATION_VALUE for i in range(64)
        }
    else:
        raise AssertionError("unknown mutation %r" % (kind,))
    return victim


def describe_mutation(mutation):
    kind = mutation[0]
    if kind in ("set", "add"):
        return "%s %s%s" % (kind, ".".join(mutation[1]),
                            "" if mutation[2] is None else " = %s" % json.dumps(mutation[2]))
    if kind == "drop":
        return "remove %s" % mutation[1]
    if kind == "flood":
        return "add 64 annotations of %d bytes" % MAX_ANNOTATION_VALUE
    return kind.replace("-", " ")

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def table(records, history):
    rows = ["| case | revision | signed by | body digest | record digest | filed under |",
            "|------|----------|-----------|-------------|---------------|-------------|"]
    for name in records:
        record = records[name]
        digest = record_digest(record)
        rows.append("| `%s` | %d | `%s…%s` | `%s…` | `%s…` | `%s` + `%s` |" % (
            name, record["revision"], record["owner"]["key_id"][:16], record["owner"]["key_id"][-4:],
            body_digest(record)[:20], digest[:20], filed(record)["kv"], filed(record)["refs"][0]))
    walk = ["", "| question asked | the policy in force | why |", "|---|---|---|"]
    chain = [records["project"], records["project-tightened"]]
    for label, at in (("run at %d (2026-10-07)" % TIMESTAMP["probe_before"], TIMESTAMP["probe_before"]),
                      ("run at %d (2026-10-25)" % TIMESTAMP["probe_after"], TIMESTAMP["probe_after"])):
        policy = in_force_at(chain, at)
        which = "revision %d" % policy["revision"]
        why = ("revision 2 had not taken effect yet, so the 4-of-5 rule applied"
               if policy["revision"] == 1 else "revision 2 took effect on 2026-10-20")
        walk.append("| %s | %s | %s |" % (label, which, why))
    return "\n".join(rows + walk)


def write(records):
    os.makedirs(os.path.join(HERE, "policies"), exist_ok=True)
    index = {"policies": {}, "history": [], "refusals": refusals(), "clock_us": NOW_US}
    history = {}
    for name in sorted(records):
        record = records[name]
        raw = canon(record)
        path = os.path.join(HERE, "policies", name + ".json")
        with open(path, "wb") as handle:
            handle.write(raw)
        where = filed(record)
        index["policies"][name] = {
            "body_digest": body_digest(record),
            "effective_from_us": record["effective_from_us"],
            "file": "policies/%s.json" % name,
            "kv": where["kv"],
            "note": NOTES[name],
            "protects": record["protects"],
            "previous_digest": record["previous_digest"],
            "record_digest": record_digest(record),
            "ref": "refs/gitiup/policy/current",
            "required_tiers": record["rules"].get("allowed_tiers"),
            "revision": record["revision"],
            "signed_by": record["signatures"][0]["key_id"],
            "size_bytes": len(raw),
            "warnings": publish_warnings(record, TRUST_ROOTS),
        }
        history[body_digest(record)] = record
    chain = [records["project"], records["project-tightened"]]
    for label, at in sorted(TIMESTAMP.items(), key=lambda item: item[1]):
        if not label.startswith("probe"):
            continue
        try:
            policy = in_force_at(chain, at)
            index["history"].append({
                "at_us": at,
                "chain": ["project", "project-tightened"],
                "in_force": "project-tightened" if policy["revision"] == 2 else "project",
                "revision": policy["revision"],
            })
        except Refuse as refusal:
            index["history"].append({"at_us": at, "chain": ["project", "project-tightened"],
                                     "refusal": refusal.token})
    index["normalisations"] = [
        {"from": {"allow_simulated": True},
         "to": resolve_shorthand({"allow_simulated": True}),
         "note": "the shorthand a human writes, as the signed document spells it"},
        {"from": {"allow_simulated": False},
         "to": resolve_shorthand({"allow_simulated": False}),
         "note": "`false` is the default, so the signed tier list says `local` and nothing else"},
        {"from": {"allowed_tiers": ["quorum", "local"], "allowed_sandboxes": ["podman", "docker"]},
         "to": resolve_shorthand({"allowed_tiers": ["quorum", "local"],
                                  "allowed_sandboxes": ["podman", "docker"]}),
         "note": "order is normalised away, so equivalent rules are one byte string (D2)"},
    ]
    keys = {"ada": OWNER_ADA.key_id, "ci-runner": CI_KEY.key_id, "sofia": OWNER_SOFIA.key_id}
    with open(os.path.join(HERE, "cases.json"), "w") as handle:
        json.dump({"clock_us": NOW_US, "keys": keys, "trust_roots": sorted(TRUST_ROOTS),
                   "genesis_previous": GENESIS_PREVIOUS, "payload_type": POLICY_PAYLOAD_TYPE,
                   "policies": index["policies"], "history": index["history"],
                   "normalisations": index["normalisations"],
                   "refusals": index["refusals"]},
                  handle, indent=2, sort_keys=True)
        handle.write("\n")
    return index


def check_signatures(records):
    """Every signature re-verified here, and by OpenSSL when it is installed, so the
    signing path is not checked only against the code that wrote it."""
    for name, record in records.items():
        entry = record["signatures"][0]
        message = pae(POLICY_PAYLOAD_TYPE, body_of(record))
        require(ed25519_verify(_pub(entry), message, _sig(entry)), "bad_signature", name)
        cross = openssl_verify(entry["public_key"], message, entry["sig"])
        if cross is not None:
            require(cross, "bad_signature", "%s under openssl" % name)


def _pub(entry):
    import base64
    return base64.b64decode(entry["public_key"].split()[1])[-32:]


def _sig(entry):
    import base64
    return base64.b64decode(entry["sig"])


def verify_committed():
    records = {}
    index = json.load(open(os.path.join(HERE, "cases.json")))
    for name, meta in index["policies"].items():
        raw = open(os.path.join(HERE, meta["file"]), "rb").read()
        record = json.loads(raw.decode("utf-8"))
        check_bytes(record, raw)
        require(body_digest(record) == meta["body_digest"], "body_digest", name)
        require(record_digest(record) == meta["record_digest"], "digest_mismatch", name)
        require(meta["kv"] == "kv/policy/" + meta["record_digest"].split(":")[1],
                "kv_key", name)
        require(meta["signed_by"] == record["signatures"][0]["key_id"], "signer", name)
        records[name] = record
    history = {body_digest(r): r for r in records.values()}
    # Well-formedness is checked with every fixture key trusted; the trust question is
    # asserted separately, because one vector exists precisely in order to be refused.
    roots = TRUST_ROOTS | {OWNER_SOFIA.key_id}
    for name, record in records.items():
        if name != "fork-weakened":
            validate(record, roots=roots, history=history)
        check_chain(record, history)
    try:
        validate(records["fork-weakened"])
        raise AssertionError("a policy signed outside the trust roots was accepted")
    except Refuse as refusal:
        require(refusal.token == "signer_untrusted", "fork_refusal", refusal.token)
    return records


def selftest():
    records = build()
    check_signatures(records)
    # The canonicaliser is the one ADR-0001 D1 specifies, imported not copied.
    require(canon({"b": 1, "a": [1, {"k": "é"}]}) == b'{"a":[1,{"k":"\xc3\xa9"}],"b":1}',
            "canon")
    require(pae(POLICY_PAYLOAD_TYPE, b"{}").startswith(b"DSSEv1 34 "), "pae")
    refusals()
    # publish's normalisation: one spelling per fact, so equivalent rules are one
    # byte string and a re-publish that changed nothing cannot move a cited digest.
    require(resolve_shorthand({"allow_simulated": True})["allowed_tiers"]
            == ["local", "simulated"], "normalise_shorthand")
    require(resolve_shorthand({"allow_simulated": False})["allowed_tiers"] == ["local"],
            "normalise_default")
    require(resolve_shorthand({"allowed_tiers": ["quorum", "local"],
                              "allowed_sandboxes": ["podman", "docker"]})
            == {"allowed_tiers": ["local", "quorum"],
                "allowed_sandboxes": ["docker", "podman"]}, "normalise_order")
    # The walk, both ways, and its refusal.
    chain = [records["project"], records["project-tightened"]]
    require(in_force_at(chain, TIMESTAMP["probe_before"])["revision"] == 1, "walk_before")
    require(in_force_at(chain, TIMESTAMP["probe_after"])["revision"] == 2, "walk_after")
    try:
        in_force_at(chain, TIMESTAMP["project_r1"] - 1)
        raise AssertionError("a run before every policy was accepted")
    except Refuse as refusal:
        require(refusal.token == "policy_history_missing", "walk_refusal")
    # A fork's inherited copy is the same document; its weakened copy is not accepted
    # by upstream's trust roots.
    require(body_digest(records["fork-inherited"]) == body_digest(records["project"]),
            "inherited_digest")
    try:
        validate(records["fork-weakened"])
        raise AssertionError("a foreign-signed policy was trusted")
    except Refuse as refusal:
        require(refusal.token == "signer_untrusted", "fork_refusal")
    print("selftest: ok (%d vectors, %d refusals)" % (len(records), len(refusals())))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--selftest":
        selftest()
        return 0
    records = build()
    check_signatures(records)
    if mode in ("", "--write"):
        write(records)
        print(table(records, {}))
        return 0
    if mode == "--check":
        before = {}
        for name in sorted(records):
            before[name] = canon(records[name])
        on_disk = {}
        index = json.load(open(os.path.join(HERE, "cases.json")))
        for name, meta in index["policies"].items():
            on_disk[name] = open(os.path.join(HERE, meta["file"]), "rb").read()
        if set(before) != set(on_disk) or any(before[k] != on_disk[k] for k in before):
            print("stale vectors: regenerate with `python3 generate.py`", file=sys.stderr)
            return 1
        verify_committed()
        print("check: ok")
        return 0
    if mode == "--verify":
        verify_committed()
        check_signatures(verify_committed())
        print("verify: ok")
        return 0
    print("usage: generate.py [--check|--selftest|--verify]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
