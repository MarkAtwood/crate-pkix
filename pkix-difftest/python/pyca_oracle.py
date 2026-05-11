#!/usr/bin/env python3
# pkix-difftest pyca/cryptography oracle sidecar.
#
# Reads a chain spec on stdin as JSON:
#   {
#     "leaf": "<PEM string>",                      # one cert
#     "intermediates": ["<PEM>", "<PEM>", ...],    # zero or more
#     "roots": ["<PEM>", ...],                     # one or more trust anchors
#     "validation_time_unix": <int>                # optional; unix seconds
#   }
#
# Writes a verdict on stdout as JSON:
#   {"verdict": "pass", "reason": null}
#   or
#   {"verdict": "fail", "reason": "<exception message>"}
#
# Exits 0 if it produced a verdict (pass or fail). Exits non-zero only on
# *harness* errors:
#   exit 1 — bad input JSON or malformed cert (cannot ask the question)
#   exit 2 — pyca cryptography too old (no verification module)
#
# Stays self-contained (only depends on cryptography).
#
# # Why ClientVerifier and not ServerVerifier?
#
# ServerVerifier requires a subject (DNSName or IPAddress) and validates
# Subject Alternative Name extensions against it. PKITS test chains and
# pyca-test-corpus chains do not have a fixed subject we could pass. The
# closest fit is ClientVerifier, which does not take a subject argument.
#
# # Why permit_all for EE but webpki_defaults_ca for CA?
#
# The default EE ExtensionPolicy (webpki_defaults_ee) enforces CA/B Forum
# strictures like "SAN must be present, must contain a DNSName matching the
# verifier's subject". PKITS test chains do not have a fixed subject and
# many lack SAN entirely, so these strictures would reject almost every
# PKITS chain for reasons unrelated to RFC 5280 §6.1 path walking. We pass
# permit_all() for the EE policy to cut through that noise.
#
# For CA we are forced to keep the webpki_defaults_ca policy, because pyca's
# PolicyBuilder enforces an invariant "all CA extension policies must
# require basicConstraints to be present" (raised as ValueError at
# build_client_verifier() time, not at verify() time). That requirement
# coincidentally aligns with RFC 5280 §6.1.4(k) ("the certificate is a
# version 3 certificate and the basic constraints extension is present and
# the cA boolean is asserted"), which pkix-path also enforces. So sticking
# with webpki_defaults_ca for CA is RFC-consistent.
#
# extension_policies() and ExtensionPolicy.permit_all() were added in
# cryptography 45.0. On 43.0–44.x we fall back to default policies on both
# sides; the report will then have lots of EE-stricture-driven
# StricterThanWild entries, which IS what the harness exists to surface,
# just noisier than necessary.

from __future__ import annotations

import datetime
import json
import sys


def fail(exit_code: int, message: str) -> None:
    sys.stderr.write(f"pyca_oracle.py: {message}\n")
    sys.exit(exit_code)


def main() -> None:
    # 1. Validate cryptography is new enough (>=43.0 for build_client_verifier).
    try:
        import cryptography  # noqa: F401
        from cryptography import x509
        from cryptography.x509.verification import PolicyBuilder, Store
    except ImportError as e:
        fail(
            2,
            f"cryptography.x509.verification not importable: {e}. "
            f"Install cryptography>=43 (45+ recommended for permit_all "
            f"extension policy) — see pkix-difftest/python/setup-venv.sh.",
        )

    # build_client_verifier was added in 43.0; check that explicitly so
    # pinning to 42.x produces a clear message rather than a confusing
    # AttributeError.
    if not hasattr(PolicyBuilder, "build_client_verifier"):
        fail(
            2,
            "PolicyBuilder.build_client_verifier missing — install "
            "cryptography>=43.",
        )

    # 2. Read input.
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
        fail(
            1,
            "stdin JSON shape: {leaf:str, intermediates:[str], roots:[str]}",
        )
    if validation_time_unix is not None and not isinstance(
        validation_time_unix, int
    ):
        fail(
            1,
            "validation_time_unix must be an integer (unix seconds) or omitted",
        )

    # 3. Parse certs. Failures here are harness errors (exit 1), not Verdicts.
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

    # 4. Build verifier. Use permit_all extension policies when available
    # (cryptography>=45) so divergences reflect RFC 5280 path-walk semantics
    # only.
    builder = PolicyBuilder().store(Store(roots))

    # Pin verification time. PolicyBuilder.time defaults to "now" but only
    # at build_*_verifier() call time (per pyca docs); pinning explicitly
    # makes the report reproducible across runs (the bead PKIX-7nsf.2 also
    # forbids non-deterministic reason strings). When the caller supplies
    # `validation_time_unix` (limbo testcases per PKIX-g9vc.1), use it; else
    # fall back to current wall clock (PKITS / PEM-tree behaviour).
    if validation_time_unix is not None:
        pinned_time = datetime.datetime.fromtimestamp(
            validation_time_unix, datetime.timezone.utc
        )
    else:
        pinned_time = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.time(pinned_time)

    try:
        from cryptography.x509.verification import ExtensionPolicy

        # extension_policies() and ExtensionPolicy.permit_all() arrived in 45.0.
        # webpki_defaults_ca() also exists in 45.0+. We need ALL of these to
        # build a "permissive EE / required-basicConstraints CA" policy pair.
        if (
            hasattr(builder, "extension_policies")
            and hasattr(ExtensionPolicy, "permit_all")
            and hasattr(ExtensionPolicy, "webpki_defaults_ca")
        ):
            builder = builder.extension_policies(
                ee_policy=ExtensionPolicy.permit_all(),
                ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            )
    except ImportError:
        # ExtensionPolicy itself is 45.0+. On 43.0–44.x, fall through with
        # default policies on both sides (CA/B Forum strictures will apply).
        pass

    try:
        verifier = builder.build_client_verifier()
        verifier.verify(leaf, intermediates)
        verdict = {"verdict": "pass", "reason": None}
    except Exception as e:  # noqa: BLE001
        verdict = {
            "verdict": "fail",
            "reason": f"{type(e).__name__}: {e}",
        }
    json.dump(verdict, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
