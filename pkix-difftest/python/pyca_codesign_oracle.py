#!/usr/bin/env python3
# pkix-difftest pyca/cryptography composed oracle for code-signing chains.
#
# Companion to pyca_oracle.py / pyca_verify_oracle.py. Those wrap pyca's
# PolicyBuilder (TLS-bound) or its purpose-driven ServerVerifier /
# ClientVerifier. THIS script answers a different question:
#
#     "Does this chain validate as a code-signing chain?"
#
# OpenSSL's `verify` tool has no -purpose codesign (verified empirically
# against OpenSSL 3.0.13; see baseline-verify-openssl.md PKIX-fmtv.18.5
# section), and pyca's PolicyBuilder.build_*_verifier surface is
# TLS-shaped — neither speaks code-signing directly. PKIX-fmtv.24's
# resolution: decompose the wrapper's job into two independent checks
# that DON'T touch the workspace's code under test.
#
# # Composed oracle
#
# 1. Chain walk via pyca primitives (not PolicyBuilder):
#    - For each adjacent cert pair (chain[i], chain[i+1]):
#      chain[i].verify_directly_issued_by(chain[i+1])
#      — pyca public API since cryptography 40.0.0. Checks issuer DN
#      match + signature verification against the issuer's public key.
#    - The top-of-chain cert (chain[-1]) must be a root or have an
#      issuer DN that matches one of the supplied trust anchor subjects.
#      The signature from that root must also verify (handled via
#      verify_directly_issued_by against the anchor).
#    - Every cert's validity period MUST cover validation_time.
#
# 2. EKU check (hand-rolled, separate ~5-line OID-match implementation):
#    - chain[0].extensions.get_extension_for_class(ExtendedKeyUsage)
#      .value contains ObjectIdentifier("1.3.6.1.5.5.7.3.3")
#      (id-kp-codeSigning).
#
# Combined verdict: chain_ok AND eku_ok.
#
# This is independent cross-validation per AGENTS.md test discipline.
# The EKU check is a separate OID-match implementation; the chain walk
# uses pyca's own primitive. Neither path uses workspace code.
#
# # Input / output
#
# Reads a JSON spec on stdin:
#
#     {
#       "leaf": "<PEM string>",
#       "intermediates": ["<PEM>", ...],
#       "roots": ["<PEM>", ...],
#       "validation_time_unix": <int>
#     }
#
# Writes a verdict on stdout as JSON:
#
#     {"verdict": "pass", "reason": null}
#     {"verdict": "fail", "reason": "<class-name>: <message>"}
#
# Exits 0 on a successful verdict (pass or fail). Exits non-zero only
# on harness errors:
#   exit 1 — bad input JSON, malformed cert, missing fields
#   exit 2 — cryptography too old (no verify_directly_issued_by)

from __future__ import annotations

import datetime
import json
import sys

# id-kp-codeSigning per RFC 5280 §4.2.1.12.
ID_KP_CODE_SIGNING_DOTTED = "1.3.6.1.5.5.7.3.3"


def fail(exit_code: int, message: str) -> None:
    sys.stderr.write(f"pyca_codesign_oracle.py: {message}\n")
    sys.exit(exit_code)


def main() -> None:
    try:
        from cryptography import x509
        from cryptography.x509 import ExtendedKeyUsage
        from cryptography.x509.oid import ObjectIdentifier
    except ImportError as e:
        fail(2, f"cryptography import failed: {e}")

    if not hasattr(x509.Certificate, "verify_directly_issued_by"):
        fail(
            2,
            "Certificate.verify_directly_issued_by missing — install "
            "cryptography>=40.0.0.",
        )

    try:
        spec = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        fail(1, f"stdin is not valid JSON: {e}")
    if not isinstance(spec, dict):
        fail(1, "stdin JSON must be an object")

    leaf_pem = spec.get("leaf")
    intermediates_pem = spec.get("intermediates", [])
    roots_pem = spec.get("roots", [])
    validation_time_unix = spec.get("validation_time_unix")

    if (
        not isinstance(leaf_pem, str)
        or not isinstance(intermediates_pem, list)
        or not isinstance(roots_pem, list)
    ):
        fail(1, "shape: {leaf:str, intermediates:[str], roots:[str], ...}")
    if not isinstance(validation_time_unix, int):
        fail(1, "validation_time_unix must be an integer (unix seconds)")

    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"))
        intermediates = [
            x509.load_pem_x509_certificate(p.encode("utf-8"))
            for p in intermediates_pem
        ]
        roots = [
            x509.load_pem_x509_certificate(p.encode("utf-8"))
            for p in roots_pem
        ]
    except Exception as e:  # noqa: BLE001 — pyca raises a tree of exception types
        fail(1, f"cert parsing failed: {type(e).__name__}: {e}")
    if not roots:
        fail(1, "no roots provided")

    pinned_time = datetime.datetime.fromtimestamp(
        validation_time_unix, datetime.timezone.utc
    )

    # Build the candidate signed chain: leaf, intermediates (issuer order),
    # then a matching root. The Rust wrapper test currently uses
    # single-cert chains (leaf only, root in anchors), but the oracle
    # supports multi-cert chains for future fixtures.
    chain = [leaf] + intermediates

    # --- check 1: chain walk via pyca primitive ---
    chain_ok, chain_reason = walk_chain(chain, roots, pinned_time, x509)
    if not chain_ok:
        emit({"verdict": "fail", "reason": chain_reason})
        return

    # --- check 2: standalone EKU check (independent of chain walk) ---
    eku_ok, eku_reason = check_eku(leaf, ExtendedKeyUsage, ObjectIdentifier)
    if not eku_ok:
        emit({"verdict": "fail", "reason": eku_reason})
        return

    emit({"verdict": "pass", "reason": None})


def walk_chain(chain, roots, pinned_time, x509_mod):
    """Walk chain leaf->top, verify each (child, issuer) pair, validity.

    Returns (ok, reason). Reason is None on ok=True.
    """
    # Validity-period check on every cert (including the root, after the
    # walk binds it).
    for idx, cert in enumerate(chain):
        ok, reason = check_validity(cert, pinned_time, f"chain[{idx}]")
        if not ok:
            return False, reason

    # Adjacent-pair verification within the chain.
    for i in range(len(chain) - 1):
        try:
            chain[i].verify_directly_issued_by(chain[i + 1])
        except Exception as e:  # noqa: BLE001 — pyca's API raises a tree
            return False, (
                f"chain[{i}] not directly issued by chain[{i + 1}]: "
                f"{type(e).__name__}: {e}"
            )

    # Top-of-chain must be issued by one of the trust anchors.
    top = chain[-1]
    matched = False
    for root in roots:
        try:
            top.verify_directly_issued_by(root)
            ok, reason = check_validity(
                root, pinned_time, "trust-anchor"
            )
            if not ok:
                return False, reason
            matched = True
            break
        except Exception:  # noqa: BLE001
            continue
    if not matched:
        return False, (
            "top-of-chain not verifiably issued by any supplied trust anchor"
        )
    return True, None


def check_validity(cert, pinned_time, label):
    """Verify pinned_time is within cert's validity period.

    pyca exposes `not_valid_before_utc` / `not_valid_after_utc` (datetime
    objects) on Certificate since cryptography 42; for earlier versions
    the names are `not_valid_before` / `not_valid_after` (naive UTC).
    Use the *_utc accessors where available.
    """
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    # Coerce naive datetimes to UTC for the comparison.
    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=datetime.timezone.utc)
    if na.tzinfo is None:
        na = na.replace(tzinfo=datetime.timezone.utc)
    if pinned_time < nb:
        return False, (
            f"{label}: validation_time {pinned_time.isoformat()} precedes "
            f"notBefore {nb.isoformat()}"
        )
    if pinned_time > na:
        return False, (
            f"{label}: validation_time {pinned_time.isoformat()} exceeds "
            f"notAfter {na.isoformat()}"
        )
    return True, None


def check_eku(leaf, ExtendedKeyUsage, ObjectIdentifier):
    """Standalone EKU check: leaf MUST assert id-kp-codeSigning.

    Independent of the chain walk above. Raises no pyca chain-validation
    code paths — pure extension lookup + OID comparison.
    """
    try:
        eku_ext = leaf.extensions.get_extension_for_class(ExtendedKeyUsage)
    except x509_exceptions_extension_not_found():
        return False, "leaf: ExtendedKeyUsage extension absent"
    usages = list(eku_ext.value)
    target_oid = ObjectIdentifier(ID_KP_CODE_SIGNING_DOTTED)
    if target_oid not in usages:
        listed = ", ".join(u.dotted_string for u in usages)
        return False, (
            f"leaf: ExtendedKeyUsage missing id-kp-codeSigning "
            f"(1.3.6.1.5.5.7.3.3); present: [{listed}]"
        )
    return True, None


def x509_exceptions_extension_not_found():
    """Resolve cryptography.x509.ExtensionNotFound at call time.

    Done as a function so the top-of-file ImportError handling stays
    minimal and we don't import the symbol unless the EKU check fires.
    """
    from cryptography.x509 import ExtensionNotFound

    return ExtensionNotFound


def emit(verdict):
    json.dump(verdict, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
