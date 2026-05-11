#!/usr/bin/env python3
# pkix-difftest pyca/cryptography oracle sidecar.
#
# Reads a chain spec on stdin as JSON:
#   {
#     "leaf": "<PEM string>",                      # one cert
#     "intermediates": ["<PEM>", "<PEM>", ...],    # zero or more
#     "roots": ["<PEM>", ...],                     # one or more trust anchors
#     "validation_time_unix": <int>,               # optional; unix seconds
#     "crls": ["<base64 DER>", ...]                # optional; zero or more
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
# # CRL revocation (PKIX-emf1.4)
#
# pyca's PolicyBuilder does NOT support CRL-aware verification as of
# cryptography 48.0.0 — there is no .crls() method on PolicyBuilder and no
# integrated revocation check on the verifier. To keep pyca an independent
# CRL oracle alongside OpenSSL and pkix-path, we hand-roll a minimal
# RFC 5280 §6.3 baseline check using cryptography's CRL parser:
#
#   1. Parse each base64-DER CRL via x509.load_der_x509_crl.
#   2. Drop CRLs whose next_update is in the past (validity window check).
#   3. For each cert in the chain except the trust anchor (matches the
#      pkix-path oracle's iteration over validation_chain), find CRLs whose
#      `issuer` equals the cert's `issuer`. For each match, look up the
#      cert's serial number in the CRL's revoked list.
#   4. If found in any matching CRL: verdict = fail, reason =
#      'pyca: certificate <serial> revoked by CRL'.
#
# Scope: matches RFC 5280 §6.3 baseline only. Indirect / delta / scoped
# CRLs are NOT handled here — they require RFC 5280 §6.3.3 machinery
# (issuingDistributionPoint, freshestCRL chase, distribution-point
# matching) that pkix-revocation implements in Rust but is out of scope
# for the diff oracle. The classifier will surface any divergence between
# pyca's baseline check and pkix-path's full CRL implementation as
# DiagnosticDivergence (verdicts agree on Pass/Fail but reason strings
# differ) or as Stricter/Looser (verdicts disagree) — which is the signal
# the harness exists to surface.
#
# CRL signature verification: NOT performed. The harness assumes the CRL
# was supplied as a trusted input. pkix-revocation's CrlChecker performs
# full signature verification; if a chain's CRL has a bad signature,
# pkix-path will Fail and the pyca oracle will Pass, and the classifier
# will flag the divergence. Adding pyca-side CRL signature verification
# would require running cryptography's hazmat backend to verify against
# the issuer cert's public key — straightforward but not needed for the
# §6.3 baseline test surface today.
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

import base64
import binascii
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
    crls_b64 = spec.get("crls", [])
    if (
        not isinstance(leaf_pem, str)
        or not isinstance(intermediates_pem, list)
        or not isinstance(roots_pem, list)
        or not isinstance(crls_b64, list)
    ):
        fail(
            1,
            "stdin JSON shape: {leaf:str, intermediates:[str], roots:[str], "
            "crls:[str]}",
        )
    if validation_time_unix is not None and not isinstance(
        validation_time_unix, int
    ):
        fail(
            1,
            "validation_time_unix must be an integer (unix seconds) or omitted",
        )
    for entry in crls_b64:
        if not isinstance(entry, str):
            fail(1, "every entry of crls must be a base64-encoded DER string")

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

    # 5. RFC 5280 §6.3 baseline CRL check. Only applied when the path-walk
    # verdict was Pass — a chain that failed path validation does not also
    # get a revocation reason layered on top (matches the pkix-path oracle's
    # behaviour in src/oracles/pkix_path.rs, which short-circuits revocation
    # on path-validation failure).
    if verdict["verdict"] == "pass" and crls_b64:
        rev_reason = _crl_revocation_reason(
            x509,
            crls_b64,
            leaf,
            intermediates,
            pinned_time,
        )
        if rev_reason is not None:
            verdict = {"verdict": "fail", "reason": rev_reason}

    json.dump(verdict, sys.stdout)
    sys.stdout.write("\n")


def _crl_revocation_reason(
    x509_mod,
    crls_b64,
    leaf,
    intermediates,
    pinned_time,
):
    """RFC 5280 §6.3 baseline CRL check.

    Returns a string reason if any cert in (leaf + intermediates) is revoked
    by a matching, in-window CRL. Returns None otherwise.

    Independence note: this is a hand-rolled check that uses pyca's CRL DER
    parser (x509.load_der_x509_crl) and CRL field accessors (issuer,
    next_update_utc, get_revoked_certificate_by_serial_number) but does NOT
    use any pyca verification module — those don't support CRLs. The lookup
    logic (issuer DN equality, serial match, validity window) is implemented
    here, parallel to the equivalent Rust logic in pkix_revocation::CrlChecker
    but with an independent code path so the two can act as differential
    oracles for each other.

    Scope: RFC 5280 §6.3 baseline only. No indirect/delta/scoped CRLs, no
    CRL signature verification (see module-level rustdoc for rationale).
    """
    # Parse CRLs, dropping malformed ones with a soft skip rather than
    # exiting the harness. A malformed CRL is data the diff classifier
    # should surface as a divergence (some oracles would accept it, others
    # not). We treat "could not parse" as "this CRL doesn't apply" to keep
    # the verdict semantics aligned with pkix-revocation's
    # CrlChecker::new failure → "ignore this CRL" treatment in
    # pkix_path.rs::check_revocation.
    crls = []
    for entry in crls_b64:
        try:
            der = base64.b64decode(entry, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            crl = x509_mod.load_der_x509_crl(der)
        except Exception:  # noqa: BLE001
            continue
        # Validity window: drop CRLs whose nextUpdate is in the past.
        # x509.CertificateRevocationList exposes next_update_utc (aware UTC)
        # in cryptography 42+; older releases exposed only `next_update`
        # (naive UTC). We try aware first and fall back to naive-as-UTC.
        next_update = getattr(crl, "next_update_utc", None)
        if next_update is None:
            naive = getattr(crl, "next_update", None)
            if naive is not None:
                next_update = naive.replace(tzinfo=datetime.timezone.utc)
        if next_update is not None and next_update < pinned_time:
            continue
        crls.append(crl)

    if not crls:
        return None

    # Walk every cert except the trust anchor. The trust anchor is not in
    # `intermediates` (PolicyBuilder consumes it from Store(roots)) and is
    # by definition not subject to revocation by RFC 5280 §6.1 — anchors
    # are trusted by deployment, not by certificate-status check.
    chain_to_check = [leaf] + list(intermediates)
    for cert in chain_to_check:
        for crl in crls:
            # Issuer DN equality. cryptography's Name.__eq__ implements
            # byte-for-byte equality on the underlying DER RDN sequence,
            # which matches RFC 5280's name-matching baseline at the §6.3
            # layer (full RFC 4518 string prep is overkill here — the test
            # surface compares Name objects from the same parser).
            if crl.issuer != cert.issuer:
                continue
            revoked = crl.get_revoked_certificate_by_serial_number(
                cert.serial_number
            )
            if revoked is not None:
                # Format the serial as hex to match the way OpenSSL and
                # pkix-revocation render it in their reason strings; the
                # classifier compares verdicts not reason strings, but a
                # consistent format keeps the diff easier to scan.
                return (
                    f"pyca: certificate 0x{cert.serial_number:x} "
                    f"revoked by CRL"
                )
    return None


if __name__ == "__main__":
    main()
