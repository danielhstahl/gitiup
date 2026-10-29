#!/usr/bin/env python3
"""Reference implementation of the gitiup change record v1 (ADR-0003).

Standard library only, deliberately: these bytes are the contract that
`gitiup-host`'s `ChangeRecord` (`giti-b2z.2`), the CLI verbs (`giti-b2z.3`), the
merge (`giti-b2z.4`) and the merge gate (`giti-91m.4`) code against, and a second
implementation in another language is the only proof that the prose spec is a
spec. Nothing here touches the network, the clock, or a third-party package.

    python3 generate.py            # print the worked-example table, rewrite the vectors
    python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
    python3 generate.py --selftest # RFC 8032, canonicalisation and derivation checks
    python3 generate.py --verify   # re-derive every committed record from its bytes

Every rule implemented here is quoted from
../0003-change-record-format-and-merge-semantics.md (D2, D3, D4, D5). Where this
file and the ADR disagree, one of them is wrong and both are edited in the same
commit: a fixture nothing regenerates is a suggestion.

Two independent checks are the reason this file is worth its bytes:

* signatures are verified by this file's own RFC 8032 code *and*, when OpenSSL is
  on `PATH`, by OpenSSL — so the signing path is checked against somebody else's
  implementation rather than against itself;
* `crates/gitiup-host/tests/change_vectors.rs` (`giti-b2z.2`) must reproduce every
  `change_id`, `body_digest` and `record_digest` in `cases.json` from the record
  bytes alone (for a change record `body_digest` *is* its `change_digest`: the two
  names are the same value, and the index uses the neutral one because a merge
  record's own body digest must not be confused with the change digest it cites).
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Constants (ADR-0003 D1-D5). Domain strings are ASCII, contain no NUL, and sit
# inside every hash: changing one changes every derivation, so a change here is a
# new record type, never a quiet fix.
# ---------------------------------------------------------------------------
RECORD_TYPE = "gitiup-change-1"
MERGE_TYPE = "gitiup-merge-1"
ABANDON_TYPE = "gitiup-abandon-1"

CHANGE_PAYLOAD_TYPE = "application/vnd.gitiup.change+json"
MERGE_PAYLOAD_TYPE = "application/vnd.gitiup.merge+json"
ABANDON_PAYLOAD_TYPE = "application/vnd.gitiup.abandon+json"

PAYLOAD_TYPES = {
    "change": CHANGE_PAYLOAD_TYPE,
    "merge": MERGE_PAYLOAD_TYPE,
    "abandon": ABANDON_PAYLOAD_TYPE,
}
RECORD_TYPES = {"change": RECORD_TYPE, "merge": MERGE_TYPE, "abandon": ABANDON_TYPE}

ID_DOMAIN = b"gitiup-change-1"
D_SEP = b"\x00"
ID_HEX_CHARS = 16  # 8 bytes, ADR-0003 D3

KEY_SEED_LABEL = b"gitiup ADR-0003 change-v1 fixture key: "

SCHEMA_VERSION = 1

# Limits (ADR-0003 D2 and D11).
MAX_RECORD_BYTES = 32 * 1024
MAX_TITLE = 512
MAX_PRINCIPAL = 128
MAX_JOBS = 64
MAX_JOB = 128
MAX_PROOFS = 64
MAX_ANNOTATIONS = 16
MAX_CHAIN = 64

RE_CHANGE_ID = re.compile(r"^chg-[0-9a-f]{16}$")
RE_OID = re.compile(r"^(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
RE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RE_JOB = re.compile(r"^[!-~]+$")  # printable ASCII, no space
RE_ANNOTATION_KEY = re.compile(r"^x_[a-z0-9]+(?:_[a-z0-9]+)+$")


class Refuse(Exception):
    """A record a conforming reader must reject."""


# ---------------------------------------------------------------------------
# Gitiup Canonical JSON (ADR-0001 D1 rules 1-7)
# ---------------------------------------------------------------------------
_SHORT_ESCAPES = {0x08: b"\\b", 0x09: b"\\t", 0x0A: b"\\n", 0x0C: b"\\f", 0x0D: b"\\r"}


def enc_str(text: str) -> bytes:
    """One JSON string, with rule 4's escape set and nothing else.

    `\\u00xx` (lower-case hex) only for the controls the short escapes do not cover;
    U+007F, U+2028 and U+2029 stay raw UTF-8, exactly as
    `gitiup_attest::canon::write_string` writes them.
    """
    out = bytearray(b'"')
    for ch in text:
        cp = ord(ch)
        if ch == '"':
            out += b'\\"'
        elif ch == "\\":
            out += b"\\\\"
        elif cp in _SHORT_ESCAPES:
            out += _SHORT_ESCAPES[cp]
        elif cp < 0x20:
            out += ("\\u00%02x" % cp).encode()
        else:
            out += ch.encode("utf-8")
    out += b'"'
    return bytes(out)


def canon(value) -> bytes:
    """Canonical bytes: keys ascending by UTF-8 bytes, no whitespace, integers
    only, no nulls, no floats, no booleans."""
    out = bytearray()
    _canon_into(value, out, 1)
    if len(out) > MAX_RECORD_BYTES:
        raise Refuse("document is %d bytes, limit is %d" % (len(out), MAX_RECORD_BYTES))
    return bytes(out)


def _canon_into(value, out: bytearray, depth: int) -> None:
    if depth > 32:
        raise Refuse("nested deeper than 32 containers")
    if value is None:
        raise Refuse("null is not canonical (rule 5)")
    if value is True or value is False:
        raise Refuse("booleans are not used by this format")
    if isinstance(value, int):
        if value < -(2**63) or value >= 2**63:
            raise Refuse("integers are i64")
        out += str(value).encode()
    elif isinstance(value, float):
        raise Refuse("floats are not canonical (rule 2)")
    elif isinstance(value, str):
        out += enc_str(value)
    elif isinstance(value, (list, tuple)):
        out += b"["
        for i, item in enumerate(value):
            if i:
                out += b","
            _canon_into(item, out, depth + 1)
        out += b"]"
    elif isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-8"))
        if len(set(keys)) != len(keys):
            raise Refuse("duplicate keys")
        out += b"{"
        for i, key in enumerate(keys):
            if i:
                out += b","
            out += enc_str(key)
            out += b":"
            _canon_into(value[key], out, depth + 1)
        out += b"}"
    else:
        raise Refuse("cannot canonicalise %s" % type(value))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_str(data: bytes) -> str:
    """The algorithm-tagged digest string form (ADR-0001 D2)."""
    return "sha256:" + sha256_hex(data)


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (ADR-0001 D1)."""
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type.encode()
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64u(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032): the RFC appendix implementation, pure stdlib, checked
# against the RFC's own test vectors by --selftest.
# ---------------------------------------------------------------------------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # order of the base point
D_COEF = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, parity: int) -> int:
    """The x with the given low bit for a y on the curve (RFC 8032 5.1.3/5.6.1)."""
    if y >= P:
        raise ValueError("point off field")
    xx = (y * y - 1) * pow(D_COEF * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        raise ValueError("no square root")
    return x if x % 2 == parity else P - x


_BY = 4 * pow(5, P - 2, P) % P
_BX = _recover_x(_BY, 0)
_B = (_BX, _BY, 1, _BX * _BY % P)
_ZERO = (0, 1, 1, 0)


def _edwards(p, q):
    """Extended-coordinate addition for a = -1 (Add-2008-hwcd-3)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D_COEF * t1 * t2 % P
    d2 = 2 * z1 * z2 % P
    e, f, g, h = b - a, d2 - c, d2 + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point, e):
    if e == 0:
        return _ZERO
    q = _scalarmult(point, e // 2)
    q = _edwards(q, q)
    if e % 2 == 1:
        q = _edwards(q, point)
    return q


def _encode_point(point) -> bytes:
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    out = bytearray(int(y).to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _decode_point(raw):
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    try:
        x = _recover_x(y, raw[31] >> 7)
    except ValueError:
        return None
    return (x, y, 1, x * y % P)


def _hint(*parts: bytes) -> int:
    h = hashlib.sha512()
    for part in parts:
        h.update(part)
    return int.from_bytes(h.digest(), "little")


def _expand_secret(seed: bytes):
    """RFC 8032 5.1.5's clamp, spelled with the bytes it describes: low three bits
    cleared (byte 0 & 0xf8), top bit cleared and the second-highest set (byte 31)."""
    digest = hashlib.sha512(seed).digest()
    clamped = bytearray(digest[:32])
    clamped[0] &= 0xF8
    clamped[31] &= 0x7F
    clamped[31] |= 0x40
    return digest, int.from_bytes(clamped, "little")


def ed25519_public(seed: bytes) -> bytes:
    _, a = _expand_secret(seed)
    return _encode_point(_scalarmult(_B, a))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    digest, a = _expand_secret(seed)
    public = ed25519_public(seed)
    r = _hint(digest[32:64], message) % L
    big_r = _encode_point(_scalarmult(_B, r))
    s = (r + _hint(big_r, public, message) * a) % L
    return big_r + int(s).to_bytes(32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    big_r, point_a = _decode_point(signature[:32]), _decode_point(public)
    if big_r is None or point_a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False  # the malleability `verify_strict` also refuses
    h = _hint(signature[:32], public, message)
    return _encode_point(_scalarmult(_B, s)) == _encode_point(
        _edwards(big_r, _scalarmult(point_a, h))
    )


# ---------------------------------------------------------------------------
# Keys (ADR-0001 D3): an identity is an SSH key and the key id is its fingerprint.
# ---------------------------------------------------------------------------
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")


def seed_for(label: str) -> bytes:
    """The fixture keys, derived from a public label so no secret is committed."""
    return hashlib.sha256(KEY_SEED_LABEL + label.encode()).digest()


class FixtureKey:
    def __init__(self, label: str, principal: str):
        self.label = label
        self.principal = principal
        self.seed = seed_for(label)
        self.public = ed25519_public(self.seed)
        name = b"ssh-ed25519"
        self.ssh_blob = (
            len(name).to_bytes(4, "big")
            + name
            + len(self.public).to_bytes(4, "big")
            + self.public
        )
        self.key_line = "ssh-ed25519 " + b64(self.ssh_blob)
        self.key_id = "SHA256:" + b64u(hashlib.sha256(self.ssh_blob).digest())

    def sign(self, message: bytes) -> dict:
        return {
            "algorithm": "ed25519",
            "key_id": self.key_id,
            "public_key": self.key_line,
            "sig": b64(ed25519_sign(self.seed, message)),
        }


def verify_with_openssl(public_line: str, message: bytes, signature_b64: str):
    """Optional second opinion, so signing is not checked only against this file.
    `None` when OpenSSL is absent."""
    try:
        if subprocess.run(["openssl", "version"], capture_output=True).returncode != 0:
            return None
    except OSError:
        return None
    blob = base64.b64decode(public_line.split()[1])
    with tempfile.TemporaryDirectory() as tmp:
        paths = {k: os.path.join(tmp, k) for k in ("pub.der", "sig.bin", "msg.bin")}
        with open(paths["pub.der"], "wb") as handle:
            handle.write(SPKI_ED25519 + blob[-32:])
        with open(paths["sig.bin"], "wb") as handle:
            handle.write(base64.b64decode(signature_b64))
        with open(paths["msg.bin"], "wb") as handle:
            handle.write(message)
        done = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                paths["pub.der"],
                "-rawin",
                "-in",
                paths["msg.bin"],
                "-sigfile",
                paths["sig.bin"],
            ],
            capture_output=True,
        )
    return done.returncode == 0


# ---------------------------------------------------------------------------
# change_id (ADR-0003 D3)
# ---------------------------------------------------------------------------
def derive_change_id(key_id: str, base_ref: str, anchor: str) -> str:
    """`chg-` + the first 16 hex characters of SHA-256 over the three fields that
    identify a proposal and survive every re-push: who signed it, toward which
    branch, and the head it started at. Never the current head, never the title,
    never the attempt index."""
    for value in (key_id, base_ref, anchor):
        if not value or "\x00" in value:
            raise Refuse("change_id input is empty or contains NUL")
    digest = hashlib.sha256(
        ID_DOMAIN
        + D_SEP
        + key_id.encode()
        + D_SEP
        + base_ref.encode()
        + D_SEP
        + anchor.encode()
    ).digest()
    return "chg-" + digest[: ID_HEX_CHARS // 2].hex()


# ---------------------------------------------------------------------------
# Records: signing, filing, reading
# ---------------------------------------------------------------------------
def body_of(record: dict) -> bytes:
    """The signed body: the record with its own signature lists removed — the rule
    `gitiup_quorum::record::body_bytes` already applies to rosters and rounds."""
    return canon({k: v for k, v in record.items() if k not in ("signatures", "self_signature")})


def sign_record(record: dict, key: FixtureKey, payload_type: str) -> dict:
    record = dict(record)
    if record.get("signatures"):
        raise Refuse("sign_record expects an unsigned record")
    if record["author"]["key_id"] != key.key_id:
        raise Refuse("signer is not the author")
    record["signatures"] = [key.sign(pae(payload_type, body_of(record)))]
    return record


def refs_for(record: dict, kind: str) -> dict:
    """Every ref and storage key this record is filed under (ADR-0003 D5)."""
    change_id = record["change_id"]
    if kind == "change":
        namespace = "change"
        refs = [
            "refs/changes/%s/attempt/%d" % (change_id, record["attempts"]["index"]),
            "refs/changes/%s/head" % change_id,
        ]
    elif kind == "merge":
        namespace, refs = "merge", ["refs/changes/%s/merged" % change_id]
    else:
        namespace, refs = "abandon", ["refs/changes/%s/abandoned" % change_id]
    return {"kv": "kv/%s/%s" % (namespace, sha256_hex(canon(record))), "refs": refs}


def require(condition: bool, what: str) -> None:
    if not condition:
        raise Refuse(what)


def validate(record: dict, kind: str) -> None:
    """Every reader-side check (ADR-0003 D11). A Rust reader that accepts or
    rejects these bytes differently is wrong about the format."""
    require(record.get("schema_version") == SCHEMA_VERSION, "schema_version")
    require(record.get("type") == RECORD_TYPES[kind], "type")
    require(bool(RE_CHANGE_ID.match(record.get("change_id", ""))), "change_id shape")
    require(len(record.get("signatures", [])) == 1, "exactly one signature")
    entry = record["signatures"][0]
    require(entry["key_id"] == record["author"]["key_id"], "signer is not the author")
    require(
        entry["key_id"] == "SHA256:" + b64u(hashlib.sha256(base64.b64decode(entry["public_key"].split()[1])).digest()),
        "key_id is not the fingerprint of the key offered",
    )
    require("null" not in canon(record).decode(), "null in a signed record")
    require(canon(json.loads(canon(record))) == canon(record), "not canonical")
    annotations = record.get("annotations")
    if annotations is not None:
        require(len(annotations) <= MAX_ANNOTATIONS, "too many annotations")
        require(all(RE_ANNOTATION_KEY.match(k) for k in annotations), "annotation key shape")
        require(all(isinstance(v, str) for v in annotations.values()), "annotation value")

    if kind != "change":
        require(bool(RE_DIGEST.match(record["change_digest"])), "change_digest shape")
        require(isinstance(record["attempt"], int), "attempt")
        return

    author = record["author"]
    require(0 < len(author["principal"].encode()) <= MAX_PRINCIPAL, "principal")
    require(0 < len(record["title"].encode()) <= MAX_TITLE, "title length")
    require(not any(ord(c) < 0x20 for c in record["title"]), "title control character")
    require(bool(RE_OID.match(record["head"])), "head oid")
    require(record["base"]["ref"].startswith("refs/heads/"), "base is a branch")
    require(bool(RE_OID.match(record["base"]["oid"])), "base oid")
    origin = record["origin"]
    require(origin["kind"] in ("store", "pull"), "origin kind")
    if origin["kind"] == "pull":
        require(isinstance(origin.get("number"), int) and origin["number"] >= 1, "pull number")
    else:
        require(set(origin) == {"kind"}, "store origin carries only kind")
    jobs = record["workflow"]["jobs"]
    require(len(jobs) <= MAX_JOBS, "too many jobs")
    require(jobs == sorted(set(jobs)), "jobs are not sorted and deduped")
    require(all(RE_JOB.match(j) and len(j) <= MAX_JOB for j in jobs), "job id shape")
    attempts = record["attempts"]
    require(bool(RE_OID.match(attempts["anchor"])), "anchor oid")
    require(isinstance(attempts["index"], int) and attempts["index"] >= 0, "attempt index")
    if attempts["index"] == 0:
        require(attempts["anchor"] == record["head"], "attempt 0 anchors its own head")
        require("previous" not in attempts, "attempt 0 has no predecessor")
    else:
        require(bool(RE_DIGEST.match(attempts.get("previous", ""))), "attempt needs `previous`")
    require(
        derive_change_id(author["key_id"], record["base"]["ref"], attempts["anchor"])
        == record["change_id"],
        "change_id does not re-derive from the record",
    )


def check_signature(record: dict, kind: str, use_openssl: bool = False) -> None:
    body = body_of(record)
    entry = record["signatures"][0]
    blob = base64.b64decode(entry["public_key"].split()[1])
    message = pae(PAYLOAD_TYPES[kind], body)
    require(
        ed25519_verify(blob[-32:], message, base64.b64decode(entry["sig"])),
        "signature does not verify",
    )
    if use_openssl:
        verdict = verify_with_openssl(entry["public_key"], message, entry["sig"])
        if verdict is False:
            raise Refuse("OpenSSL refused a signature this file produced")


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------
ADA = FixtureKey("ada", "ada@example.org")
LIN = FixtureKey("lin", "lin@nosofter.dev")
OWNER = FixtureKey("owner", "owner@example.org")

BASE_REF = "refs/heads/main"
BASE_OID = "sha1:5f3e0d0b1a6c4e8f9a7b3c2d1e0f4a6b8c9d0e1f"
HEAD_1 = "sha1:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
HEAD_2 = "sha1:0b8e2c4a6f0123456789abcdef0123456789abcd"
PR_HEAD = "sha1:7d4c2b1a09384756abcdef0123456789abcdefff"
OTHER_HEAD = "sha1:c0ffee00deadbeef0123456789abcdef01234567"

# A fixed instant: this file has no clock, so the vectors are reproducible.
T0 = 1_764_674_043_000_000  # 2025-12-02T09:14:03Z
HOUR = 3_600_000_000
DAY = 86_400_000_000


def build_cases():
    """Every vector, in file order: name -> (kind, record, key)."""
    cases = {}

    def change(name, key, **fields):
        anchor = fields["attempts"]["anchor"]
        record = {
            "schema_version": SCHEMA_VERSION,
            "type": RECORD_TYPE,
            "change_id": derive_change_id(key.key_id, BASE_REF, anchor),
            "author": {"key_id": key.key_id, "principal": key.principal},
            "base": {"ref": BASE_REF, "oid": BASE_OID},
        }
        record.update(fields)
        cases[name] = ("change", sign_record(record, key, CHANGE_PAYLOAD_TYPE))

    change(
        "open-first",
        ADA,
        title="Refuse a ref name that resolves outside the store",
        head=HEAD_1,
        attempts={"anchor": HEAD_1, "index": 0},
        origin={"kind": "store"},
        workflow={"jobs": ["build/linux-x86_64", "test"]},
        created_at_us=T0,
    )
    first_digest = digest_str(body_of(cases["open-first"][1]))

    change(
        "open-second",
        ADA,
        title="Refuse a ref name that resolves outside the store",
        head=HEAD_2,
        attempts={"anchor": HEAD_1, "index": 1, "previous": first_digest},
        origin={"kind": "store"},
        workflow={"jobs": ["build/linux-x86_64", "test"]},
        created_at_us=T0 + HOUR,
    )
    second = cases["open-second"][1]
    second_digest = digest_str(body_of(second))

    cases["merged"] = (
        "merge",
        sign_record(
            {
                "schema_version": SCHEMA_VERSION,
                "type": MERGE_TYPE,
                "change_id": second["change_id"],
                "change_digest": second_digest,
                "attempt": 1,
                "base": {"ref": BASE_REF, "from": BASE_OID, "to": HEAD_2},
                "merged_at_us": T0 + 2 * HOUR,
                "via": "store",
                "proofs": ["sha256:" + "11" * 32, "sha256:" + "22" * 32],
                "author": {"key_id": OWNER.key_id, "principal": OWNER.principal},
            },
            OWNER,
            MERGE_PAYLOAD_TYPE,
        ),
    )

    change(
        "pull-backed",
        LIN,
        title="Fix “unmappable” escapes in the ref parser",
        head=PR_HEAD,
        attempts={"anchor": PR_HEAD, "index": 0},
        origin={"kind": "pull", "number": 428},
        workflow={"jobs": ["build/linux-x86_64", "build/macos-aarch64", "docs", "test"]},
        created_at_us=T0 + DAY,
        annotations={"x_gitiup_host_github_pr": "428"},
    )
    pr = cases["pull-backed"][1]

    cases["abandoned"] = (
        "abandon",
        sign_record(
            {
                "schema_version": SCHEMA_VERSION,
                "type": ABANDON_TYPE,
                "change_id": pr["change_id"],
                "change_digest": digest_str(body_of(pr)),
                "attempt": 0,
                "abandoned_at_us": T0 + 2 * DAY,
                "reason": "superseded",
                "note": "re-drawn against main after the ref parser landed",
                "author": {"key_id": LIN.key_id, "principal": LIN.principal},
            },
            LIN,
            ABANDON_PAYLOAD_TYPE,
        ),
    )

    change(
        "wide",
        ADA,
        title=(
            'A title with a "quote", a backslash \\ and an é, and then a tail long '
            "enough that a reader which assumed short titles learns something: escapes, "
            "UTF-8 and the byte ceiling all arrive at once, and none of them are "
            "optional to get right."
        ),
        head=OTHER_HEAD,
        attempts={"anchor": OTHER_HEAD, "index": 0},
        origin={"kind": "store"},
        workflow={
            "jobs": [
                "build/aarch64-macos",
                "build/linux-x86_64",
                "build/linux-x86_64-asan",
                "docs",
                "fuzz/canon",
                "test/conformance",
                "test/unit",
                "vet/dependencies",
            ]
        },
        created_at_us=T0 + 3 * DAY,
    )
    return cases


CASE_ORDER = ["open-first", "open-second", "merged", "pull-backed", "abandoned", "wide"]
NOTES = {
    "open-first": "the smallest honest change: attempt 0, store origin, two jobs",
    "open-second": "a force-push: new head, same change_id, previous names open-first's change_digest",
    "merged": "what a merge is: base.from -> base.to, the attempt merged, the proofs believed",
    "pull-backed": "origin.pull, a non-ASCII title, and the annotation escape hatch",
    "abandoned": "closing a change is a signed record, not a deleted ref",
    "wide": "escapes, UTF-8, eight jobs: the reader's limits in one record",
}


def render():
    """Every record's bytes plus the index entry pinning its digests and refs."""
    cases = build_cases()
    index = {
        "record_types": {"change": RECORD_TYPE, "merge": MERGE_TYPE, "abandon": ABANDON_TYPE},
        "payload_types": PAYLOAD_TYPES,
        "id": {"domain": ID_DOMAIN.decode(), "hex_chars": ID_HEX_CHARS, "formula": "chg- || hex(SHA256(domain || 0x00 || key_id || 0x00 || base.ref || 0x00 || attempts.anchor))[0..16]"},
        "limits": {
            "record_bytes": MAX_RECORD_BYTES,
            "title_bytes": MAX_TITLE,
            "principal_bytes": MAX_PRINCIPAL,
            "jobs": MAX_JOBS,
            "job_bytes": MAX_JOB,
            "proofs": MAX_PROOFS,
            "annotations": MAX_ANNOTATIONS,
            "chain": MAX_CHAIN,
        },
        "keys": {
            key.label: {
                "principal": key.principal,
                "public_key": key.key_line,
                "key_id": key.key_id,
                "seed": 'SHA256("%s" || utf8(label))' % KEY_SEED_LABEL.decode(),
            }
            for key in (ADA, LIN, OWNER)
        },
        "cases": {},
    }
    files = {}
    for name in CASE_ORDER:
        kind, record = cases[name]
        check_signature(record, kind)
        validate(record, kind)
        path = "records/%s.json" % name
        files[path] = canon(record)
        index["cases"][name] = {
            "kind": kind,
            "file": path,
            "change_id": record["change_id"],
            "body_digest": digest_str(body_of(record)),
            "record_digest": digest_str(canon(record)),
            "author": record["author"]["key_id"],
            "signature": record["signatures"][0]["sig"],
            "refs": refs_for(record, kind),
            "note": NOTES[name],
        }
    return index, files


# ---------------------------------------------------------------------------
# Self-checks
# ---------------------------------------------------------------------------
def openssl_keypair():
    """A fresh key from OpenSSL: (seed, raw public key) or None if absent.

    PKCS#8 for Ed25519 ends with the 32-byte seed, and SPKI ends with the 32-byte
    public key, so one `pkey` call each way is enough.
    """
    try:
        private = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-outform", "DER"],
            capture_output=True,
        )
        if private.returncode != 0:
            return None
        seed = private.stdout[-32:]
        public = subprocess.run(
            ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            input=private.stdout,
            capture_output=True,
        )
        if public.returncode != 0:
            return None
        return seed, public.stdout[-32:]
    except OSError:
        return None


def openssl_sign(seed: bytes, message: bytes) -> bytes:
    """OpenSSL's own signature over `message`, or None when OpenSSL is absent."""
    if subprocess.run(["openssl", "version"], capture_output=True).returncode != 0:
        raise OSError("no openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path, msg_path, sig_path = (
            os.path.join(tmp, "k.der"),
            os.path.join(tmp, "m.bin"),
            os.path.join(tmp, "s.bin"),
        )
        with open(key_path, "wb") as handle:
            handle.write(bytes.fromhex("302e020100300506032b657004220420") + seed)
        with open(msg_path, "wb") as handle:
            handle.write(message)
        done = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                key_path,
                "-rawin",
                "-in",
                msg_path,
                "-out",
                sig_path,
            ],
            capture_output=True,
        )
        if done.returncode != 0:
            raise OSError(done.stderr.decode()[:200])
        with open(sig_path, "rb") as handle:
            return handle.read()


def selftest() -> None:
    """Check the primitives against something else, because a constant transcribed
    from a specification is just another place to be wrong."""
    seed = seed_for("selftest")
    message = b"DSSEv1 33 application/vnd.gitiup.change+json 5 hello"
    public = ed25519_public(seed)
    signature = ed25519_sign(seed, message)
    assert len(public) == 32 and len(signature) == 64
    assert ed25519_verify(public, message, signature), "self round-trip"
    assert not ed25519_verify(public, message + b"!", signature), "a tampered message verifies!"
    assert not ed25519_verify(public, message, ed25519_sign(seed_for("other"), message))
    assert _encode_point(_B).hex() == "58" + "66" * 31, "the base point is not ed25519's"
    assert _encode_point(_scalarmult(_B, L)) == b"\x01" + b"\x00" * 31, "[l]B is not the identity"
    assert not ed25519_verify(public, message, signature[:-1] + bytes([signature[-1] ^ 1]))
    print("  ed25519: base point, [l]B, sign/verify round-trip, tamper refusal")

    pair = openssl_keypair()
    if pair is None:
        print("  openssl cross-check: unavailable (install openssl to make this check mean more)")
    else:
        their_seed, their_public = pair
        assert ed25519_public(their_seed) == their_public, "OpenSSL's seed gives a different key here"
        for probe in (b"a", message):
            theirs = openssl_sign(their_seed, probe)
            assert ed25519_verify(their_public, probe, theirs), "OpenSSL signed, this refused"
            assert verify_with_openssl(
                "ssh-ed25519 " + b64(their_public), probe, b64(ed25519_sign(their_seed, probe))
            ), "this signed, OpenSSL refused"
        print("  openssl cross-check: signs here/verifies there and back, three messages")
    assert canon({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert canon({}) == b"{}" and canon([1, [2], 3]) == b"[1,[2],3]"
    assert canon({"a": -0}) == b'{"a":0}'
    assert canon({"é": 1, "e": 2}) == b'{"e":2,"\xc3\xa9":1}'
    assert canon({"a": [0, -1, 4611686018427387904]}) == b'{"a":[0,-1,4611686018427387904]}'
    assert enc_str("\b") == b'"\\b"'
    assert enc_str("a\tb\nc") == b'"a\\tb\\nc"'
    assert enc_str("\x01\x1f") == b'"\\u0001\\u001f"'
    assert enc_str("é") == '"é"'.encode()
    assert enc_str("\x7f") == b'"\x7f"'
    assert enc_str("\u2028") == b'"\xe2\x80\xa8"'
    for refused in ({"a": None}, {"a": 1.0}, {"a": True}, {"a": 2**63}):
        try:
            canon(refused)
        except Refuse:
            continue
        raise AssertionError("canon accepted %r" % refused)
    print("  canonical json: ordering, escapes, raw UTF-8, refusal of null/float/bool")

    cases = build_cases()
    first = cases["open-first"][1]
    second = cases["open-second"][1]
    assert first["change_id"] == second["change_id"], "a re-push must keep the change_id"
    assert first["head"] != second["head"], "and still be a different attempt"
    assert second["attempts"]["previous"] == digest_str(body_of(first))
    assert (
        derive_change_id(second["author"]["key_id"], second["base"]["ref"], second["attempts"]["anchor"])
        == second["change_id"]
    ), "change_id must be recomputable from the record alone"
    assert RE_CHANGE_ID.match(first["change_id"]) and "/" not in first["change_id"]
    assert len(cases["wide"][1]["title"].encode()) <= MAX_TITLE
    print("  change_id: stable across attempts, recomputable, ref-safe, single component")

    index, files = render()
    assert len(files) == len(CASE_ORDER)
    for name, case in index["cases"].items():
        raw = files[case["file"]]
        assert digest_str(raw) == "sha256:" + case["record_digest"].split(":")[1]
        assert json.loads(raw)["change_id"] == case["change_id"]
    print("  index: every digest and ref name derived from the record bytes, not typed")

    probe = pae(CHANGE_PAYLOAD_TYPE, b"probe")
    verdict = verify_with_openssl(ADA.key_line, probe, b64(ed25519_sign(ADA.seed, probe)))
    assert verdict is not False, "OpenSSL refused a signature this file produced"


def verify_committed() -> None:
    """Re-derive everything `cases.json` claims from the committed bytes: what
    `giti-b2z.2`'s Rust test has to do as well."""
    with open(os.path.join(HERE, "cases.json")) as handle:
        index = json.load(handle)
    for name, expected in sorted(index["cases"].items()):
        path = os.path.join(HERE, expected["file"])
        with open(path, "rb") as handle:
            raw = handle.read()
        assert raw == canon(json.loads(raw)), "%s: bytes are not canonical" % name
        record = json.loads(raw)
        kind = expected["kind"]
        validate(record, kind)
        check_signature(record, kind)
        assert digest_str(body_of(record)) == expected["body_digest"], "%s: body_digest" % name
        assert digest_str(raw) == expected["record_digest"], "%s: record_digest" % name
        assert refs_for(record, kind) == expected["refs"], "%s: refs" % name
        assert record["change_id"] == expected["change_id"], "%s: change_id" % name
    print("  %d committed records re-derived, re-hashed and re-verified" % len(index["cases"]))


def load_committed() -> dict:
    files = {}
    for name in CASE_ORDER:
        with open(os.path.join(HERE, "records", "%s.json" % name), "rb") as handle:
            files["records/%s.json" % name] = handle.read()
    with open(os.path.join(HERE, "cases.json"), "rb") as handle:
        files["cases.json"] = handle.read()
    return files


def table(index: dict, files: dict) -> str:
    header = ("case", "kind", "attempt", "change_id", "body_digest", "record_digest", "filed under")
    rows = [header]
    for name in CASE_ORDER:
        case = index["cases"][name]
        record = json.loads(files[case["file"]])
        rows.append(
            (
                name,
                case["kind"],
                str(record["attempts"]["index"]) if case["kind"] == "change" else "—",
                case["change_id"],
                case["body_digest"],
                case["record_digest"],
                " + ".join([case["refs"]["kv"]] + case["refs"]["refs"]),
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows]
    return "\n".join(lines)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--selftest":
        selftest()
        print("selftest: ok")
        return 0
    if mode == "--verify":
        verify_committed()
        print("verify: ok")
        return 0

    index, files = render()
    if mode == "--check":
        committed = load_committed()
        expected = dict(files)
        expected["cases.json"] = (json.dumps(index, indent=2, sort_keys=True) + "\n").encode()
        stale = sorted(name for name, data in expected.items() if committed.get(name) != data)
        if stale:
            print("stale or missing: %s" % ", ".join(stale))
            print("run `python3 generate.py` and commit the result with the ADR change")
            return 1
        print("vectors are current")
        return 0

    os.makedirs(os.path.join(HERE, "records"), exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(HERE, name), "wb") as handle:
            handle.write(data)
    with open(os.path.join(HERE, "cases.json"), "w") as handle:
        handle.write(json.dumps(index, indent=2, sort_keys=True) + "\n")
    print(table(index, files))
    print("\nwrote %d files" % (len(files) + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
