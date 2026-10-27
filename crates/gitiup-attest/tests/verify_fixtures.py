#!/usr/bin/env python3
"""Verify the committed golden vectors with nothing but Python and OpenSSL.

    python3 tests/verify_fixtures.py [fixtures/v1]

This exists for two reasons. First, it is the argument ADR-0001 makes in
practice: a stranger can check an attestation with tools they already have —
`sha256` for the digest, RFC 8032 ed25519 over the PAE bytes for the signature,
no gitiup required. Second, it checks the format against *other people's*
implementations of those primitives, so the Rust code cannot be merely
self-consistent.

Exits non-zero on the first mismatch. Requires `openssl` on PATH.
"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# SubjectPublicKeyInfo prefix for an Ed25519 public key (DER):
# SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING ... }
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def ssh_blob(public_key_line: str) -> bytes:
    """`ssh-ed25519 AAAA…` (optionally with a comment) as its wire blob."""
    fields = public_key_line.split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise AssertionError(f"unsupported key line: {public_key_line!r}")
    blob = base64.b64decode(fields[1])
    name_len = int.from_bytes(blob[:4], "big")
    assert blob[4 : 4 + name_len] == b"ssh-ed25519", "not an ssh-ed25519 blob"
    key_len = int.from_bytes(blob[4 + name_len : 8 + name_len], "big")
    assert 8 + name_len + key_len == len(blob), "trailing bytes in the ssh blob"
    return blob


def pae(payload_type: bytes, payload: bytes) -> bytes:
    """in-toto DSSE Pre-Authentication Encoding."""
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type, len(payload), payload)


def verify_signature(pubkey_line: str, message: bytes, signature_b64: str) -> None:
    blob = ssh_blob(pubkey_line)
    with tempfile.TemporaryDirectory() as tmp:
        pub = Path(tmp) / "pub.der"
        msg = Path(tmp) / "msg.bin"
        sig = Path(tmp) / "sig.bin"
        pub.write_bytes(ED25519_SPKI_PREFIX + blob[-32:])
        msg.write_bytes(message)
        sig.write_bytes(base64.b64decode(signature_b64))
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(pub),
                "-rawin",
                "-in",
                str(msg),
                "-sigfile",
                str(sig),
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr.decode().strip() or "verification failed")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "fixtures/v1")
    cases = json.loads((root / "cases.json").read_text())
    trusted_key_id = cases["signing_key"]["key_id"]

    for case in cases["cases"]:
        name = case["name"]
        payload = (root / name / "manifest.json").read_bytes()
        doc = json.loads((root / name / "doc.json").read_text())

        # 1. the payload is canonical: re-serializing compactly must change nothing
        assert payload == json.dumps(
            json.loads(payload), separators=(",", ":"), ensure_ascii=False, sort_keys=True
        ).encode(), f"{name}: manifest.json is not canonical"

        # 2. both digests
        assert "sha256:" + hashlib.sha256(payload).hexdigest() == case["run_digest"], name
        result_core = json.dumps(
            json.loads(payload)["result"], separators=(",", ":"), ensure_ascii=False, sort_keys=True
        ).encode()
        assert (
            "sha256:" + hashlib.sha256(result_core).hexdigest() == case["result_digest"]
        ), f"{name}: result_digest"
        doc_bytes = (root / name / "doc.json").read_bytes()
        assert (
            "sha256:" + hashlib.sha256(doc_bytes).hexdigest() == case["record_digest"]
        ), f"{name}: record_digest"

        # 3. signatures, over the PAE bytes, against an independent ed25519
        assert len(doc["signatures"]) == len(case["signatures"]) == 1
        for entry, expected in zip(doc["signatures"], case["signatures"]):
            assert entry["key_id"] == expected["key_id"] == trusted_key_id, name
            assert entry["sig"] == expected["sig"], name
            assert "SHA256:" + base64.b64encode(
                hashlib.sha256(ssh_blob(entry["public_key"])).digest()
            ).decode().rstrip("=") == entry["key_id"], f"{name}: key id is not the fingerprint"
            verify_signature(
                entry["public_key"],
                pae(doc["payload_type"].encode(), payload),
                entry["sig"],
            )
        print(f"{name:14s} digest ✓  result digest ✓  key id ✓  signature ✓")

    print(f"all {len(cases['cases'])} cases verified against openssl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
