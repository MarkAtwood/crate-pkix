#!/usr/bin/env python3
"""Generate an x509_entry SCT over the *precert oracle's final cert*.

Why this fixture exists (PKIX-d4h.5):

RFC 6962 §3.2 puts `entry_type` inside the digitally-signed structure,
not on the transmitted SCT, so a verifier must be told which entry type
to assume. Being told wrong used to be reported as
`Error::InvalidSignature` — the same answer as a forged SCT.

`verify_sct_for_precert` can now notice that case, because it already
holds the leaf DER that the x509_entry form signs over. Exercising that
needs an SCT which:

  - is a genuine x509_entry SCT (so the reverse check succeeds), and
  - commits to a leaf that CARRIES an embedded SCT list, because
    `verify_sct_for_precert` strips that extension to rebuild the TBS
    and fails with `LeafMissingSctList` before any signature check if
    it is absent.

`sct-oracle/cert.der` satisfies the first and not the second, which is
why this cannot reuse the existing x509 oracle. `precert-leaf-final.der`
satisfies the second, so this script signs an x509_entry SCT over it
with the precert oracle's log key.

That combination is realistic, not contrived: a CA may log the final
certificate (x509_entry) while that certificate also carries embedded
precert SCTs.

Outputs, committed beside the other oracle fixtures:

  x509-over-precert-leaf-sct.bin           wire-format SCT
  x509-over-precert-leaf-signed-input.bin  the signed bytes, for
                                           independent inspection

Signed with precert-log-key.pem, so the log_id is precert-log-id.bin
and `precert_oracle_log_list()` already trusts it.

Run:

    python3 pkix-ct/tests/fixtures/sct-oracle/gen_x509_entry_sct_over_precert_leaf.py
"""

import pathlib
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from gen_x509_entry_sct import (  # noqa: E402
    HASH_ALG_SHA256,
    SIG_ALG_ECDSA,
    build_sct_wire,
    build_signed_input_x509_entry,
)

HERE = pathlib.Path(__file__).resolve().parent

# Same timestamp as the precert oracle, so the SCT sits inside the log's
# usable window and the test is not accidentally exercising the window
# check instead of the entry-type logic.
TIMESTAMP_MS = 1_700_000_000_000


def main() -> int:
    leaf_der = (HERE / "precert-leaf-final.der").read_bytes()
    log_id = (HERE / "precert-log-id.bin").read_bytes()
    log_key = serialization.load_pem_private_key(
        (HERE / "precert-log-key.pem").read_bytes(), password=None
    )
    assert isinstance(log_key, ec.EllipticCurvePrivateKey), "expected the P-256 log key"

    extensions = b""
    signed_input = build_signed_input_x509_entry(TIMESTAMP_MS, leaf_der, extensions)
    signature = log_key.sign(signed_input, ec.ECDSA(hashes.SHA256()))

    sct = build_sct_wire(
        log_id=log_id,
        timestamp_ms=TIMESTAMP_MS,
        extensions=extensions,
        hash_alg=HASH_ALG_SHA256,
        sig_alg=SIG_ALG_ECDSA,
        signature=signature,
    )

    (HERE / "x509-over-precert-leaf-sct.bin").write_bytes(sct)
    (HERE / "x509-over-precert-leaf-signed-input.bin").write_bytes(signed_input)
    print(f"  x509-over-precert-leaf-sct.bin: {len(sct)} bytes")
    print(f"  x509-over-precert-leaf-signed-input.bin: {len(signed_input)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
