#!/usr/bin/env python3
# pkix-difftest pyca/cryptography wrapper-level oracle sidecar.
#
# Companion to pyca_oracle.py. The sibling script answers "does this chain
# validate as an RFC 5280 path?" using ClientVerifier + permit_all extension
# policies. THIS script answers a different question: "does this chain
# validate under pyca's purpose-built TLS verifiers, which enforce RFC 6125
# identity binding (server) or clientAuth EKU + chain semantics (client)?"
#
# The output of this oracle is the comparison target for
# pkix_chain::verify_tls_server and pkix_chain::verify_tls_client_dns.
#
# Reads a JSON spec on stdin:
#   {
#     "leaf": "<PEM string>",
#     "intermediates": ["<PEM>", ...],
#     "roots": ["<PEM>", ...],
#     "validation_time_unix": <int>,
#     "mode": "server" | "client",
#     // mode=="server": exactly one of {dns, ipv4, ipv6} must be set.
#     "dns": "host.example.com",     // optional
#     "ipv4": "192.0.2.5",           // optional
#     "ipv6": "2001:db8::1",         // optional
#   }
#
# Writes a verdict on stdout as JSON:
#   {"verdict": "pass", "reason": null}
#   {"verdict": "fail", "reason": "<exception type>: <message>"}
#
# Exits 0 on a successful verdict. Exits non-zero only on harness errors:
#   exit 1 — bad input JSON, malformed cert, missing fields
#   exit 2 — cryptography too old (no PolicyBuilder / ServerVerifier)
#
# # Mode semantics
#
# ## server
# Calls PolicyBuilder.build_server_verifier(subject) with subject as one of:
#   - x509.DNSName(dns)       — matches RFC 6125 §6.4 dNSName SAN binding
#   - x509.IPAddress(...)     — matches RFC 5280 §4.2.1.6 iPAddress SAN
#
# pyca ships webpki-CA-Browser-Forum-flavored CA and EE extension policies on
# ServerVerifier — these enforce id-kp-serverAuth EKU and SAN presence. That
# matches what pkix-chain::verify_tls_server enforces (via BasicTlsProfile),
# so a side-by-side diff is meaningful.
#
# ## client
# Calls PolicyBuilder.build_client_verifier() — pyca's client verifier does
# NOT bind a subject (no hostname or mailbox argument). It validates the
# chain and enforces id-kp-clientAuth via its default CA/EE extension
# policies.
#
# This is a WEAKER oracle than pkix-chain::verify_tls_client_dns, which
# additionally binds a SAN. The sidecar therefore returns pass whenever
# the chain validates + EKU matches, regardless of SAN. The Rust side of
# the diff harness compensates by only treating chain-level outcomes as
# directly comparable; SAN-binding divergences are flagged but not as
# bugs.
#
# # Extension policy choice
#
# pkix-chain's `verify_tls_server` enforces a small, RFC 6125-focused
# policy: under `BasicTlsProfile`, the leaf must have id-kp-serverAuth EKU
# and a SAN extension; the SAN must match the supplied hostname/IP. It does
# NOT require AKI, SKI, AIA, CRLDP, or any of the CA/B Forum BR-flavored
# extensions that pyca's webpki_defaults_ee policy enforces.
#
# To get a meaningful side-by-side diff (rather than every chain failing
# pyca for missing-AKI reasons orthogonal to the actual RFC 6125 binding
# we want to test), this sidecar installs a custom EE policy:
#
#   ExtensionPolicy.permit_all().require_present(SubjectAlternativeName, ...)
#
# That keeps the two semantics that matter for a verify_tls_server diff:
#   1. SAN must be present (enforced via require_present)
#   2. SAN must match the subject (enforced by ServerVerifier itself —
#      build_server_verifier(DNSName/IPAddress) refuses to construct without
#      SAN-in-policy, and verify() applies the binding regardless of EE
#      policy permissiveness)
#
# This matches the surface `verify_tls_server` exercises. For
# mode=="client", pyca's build_client_verifier does NOT take a subject;
# permit_all alone is acceptable there (id-kp-clientAuth is still
# enforced by ServerVerifier-internal logic, not by EE extension policy).
#
# # ca_policy
#
# Left at webpki_defaults_ca() because PolicyBuilder requires CA EE policy
# to include basicConstraints — that requirement coincidentally aligns
# with RFC 5280 §6.1.4(k), which pkix-path also enforces.

from __future__ import annotations

import datetime
import ipaddress
import json
import sys


def fail(exit_code: int, message: str) -> None:
    sys.stderr.write(f"pyca_verify_oracle.py: {message}\n")
    sys.exit(exit_code)


def main() -> None:
    try:
        from cryptography import x509
        from cryptography.x509.verification import (
            PolicyBuilder,
            Store,
            ExtensionPolicy,
            Criticality,
        )
    except ImportError as e:
        fail(
            2,
            f"cryptography.x509.verification not importable: {e}. "
            f"Install cryptography>=45 — see pkix-difftest/python/setup-venv.sh.",
        )

    if not hasattr(PolicyBuilder, "build_server_verifier") or not hasattr(
        PolicyBuilder, "build_client_verifier"
    ):
        fail(
            2,
            "PolicyBuilder.build_server_verifier / build_client_verifier "
            "missing — install cryptography>=45.",
        )
    if not hasattr(ExtensionPolicy, "permit_all") or not hasattr(
        ExtensionPolicy, "webpki_defaults_ca"
    ):
        fail(
            2,
            "ExtensionPolicy.permit_all / webpki_defaults_ca missing — "
            "install cryptography>=45.",
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
    mode = spec.get("mode")

    if (
        not isinstance(leaf_pem, str)
        or not isinstance(intermediates_pem, list)
        or not isinstance(roots_pem, list)
    ):
        fail(1, "shape: {leaf:str, intermediates:[str], roots:[str], mode:str, ...}")
    if not isinstance(validation_time_unix, int):
        fail(1, "validation_time_unix must be an integer (unix seconds)")
    if mode not in ("server", "client"):
        fail(1, 'mode must be "server" or "client"')

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

    builder = PolicyBuilder().store(Store(roots)).time(pinned_time)
    builder = builder.extension_policies(
        ee_policy=_ee_policy(ExtensionPolicy, Criticality, x509, mode),
        ca_policy=ExtensionPolicy.webpki_defaults_ca(),
    )

    try:
        if mode == "server":
            subject = _build_subject(x509, spec)
            verifier = builder.build_server_verifier(subject)
        else:
            verifier = builder.build_client_verifier()
        verifier.verify(leaf, intermediates)
        verdict = {"verdict": "pass", "reason": None}
    except Exception as e:  # noqa: BLE001 — pyca raises a tree of exception types
        verdict = {
            "verdict": "fail",
            "reason": f"{type(e).__name__}: {e}",
        }

    json.dump(verdict, sys.stdout)
    sys.stdout.write("\n")


def _ee_policy(ExtensionPolicy, Criticality, x509_mod, mode):
    """Build the EE extension policy for the requested mode.

    For mode=="server", we install permit_all + require_present(SAN). pyca's
    PolicyBuilder refuses to build a ServerVerifier without SAN-in-policy
    (it raises ValueError at build_server_verifier() time). require_present
    here is the minimum that satisfies that gate while keeping every other
    extension permissive — exactly the surface verify_tls_server exercises.

    For mode=="client", permit_all alone is acceptable: build_client_verifier
    does not have the SAN-in-policy gate (no subject argument), and
    id-kp-clientAuth enforcement happens at the verifier level rather than
    at the EE-policy level. Keeping the EE policy permissive matches what
    verify_tls_client_dns enforces under Rfc5280Profile.
    """
    if mode == "server":
        return ExtensionPolicy.permit_all().require_present(
            x509_mod.SubjectAlternativeName, Criticality.AGNOSTIC, None
        )
    return ExtensionPolicy.permit_all()


def _build_subject(x509_mod, spec):
    """Construct the pyca GeneralName subject for ServerVerifier.

    Exactly one of {dns, ipv4, ipv6} must be set in the spec.
    """
    dns = spec.get("dns")
    ipv4 = spec.get("ipv4")
    ipv6 = spec.get("ipv6")
    set_count = sum(1 for v in (dns, ipv4, ipv6) if v is not None)
    if set_count != 1:
        fail(
            1,
            'mode=="server" requires exactly one of {dns, ipv4, ipv6} '
            f"(got {set_count})",
        )
    if dns is not None:
        if not isinstance(dns, str):
            fail(1, "dns must be a string")
        return x509_mod.DNSName(dns)
    if ipv4 is not None:
        if not isinstance(ipv4, str):
            fail(1, "ipv4 must be a string")
        try:
            addr = ipaddress.IPv4Address(ipv4)
        except (ValueError, ipaddress.AddressValueError) as e:
            fail(1, f"ipv4 not parseable: {e}")
        return x509_mod.IPAddress(addr)
    # ipv6
    if not isinstance(ipv6, str):
        fail(1, "ipv6 must be a string")
    try:
        addr = ipaddress.IPv6Address(ipv6)
    except (ValueError, ipaddress.AddressValueError) as e:
        fail(1, f"ipv6 not parseable: {e}")
    return x509_mod.IPAddress(addr)


if __name__ == "__main__":
    main()
