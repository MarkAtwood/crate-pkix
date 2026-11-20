#!/usr/bin/env python3
"""Generate review DoS fixtures for pkix-path.

Reuses the DER helpers and keys of ../nc/gen.py (imported by path).

dn_wide_rdn_*.der: unsigned-in-spirit certs (signed by the review root
   key, but the signature is irrelevant: the work happens before any
   signature check) whose issuer == subject is ONE RDN holding N
   BMPString CN AVAs. `names_match` is O(N^2) per call, each comparison
   allocating two BMPString->UTF-8 buffers; `check_inputs` calls it
   O(chain^2) times and `validate_path` once more per cert.

Run:  python3 -I gen.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# Import only the helper section of ../nc/gen.py without re-running its
# scenario writes: exec the source up to the "PKI" marker.
src = open(os.path.join(HERE, "..", "nc", "gen.py")).read()
helpers_src = src.split("# ---------------------------------------------------------------- PKI")[0]
g = {"__file__": os.path.join(HERE, "..", "nc", "gen.py"), "__name__": "ncgen_helpers"}
exec(compile(helpers_src, "nc/gen.py", "exec"), g)

tlv, seq, oid, integer, name, ext, ext_bc, ext_ku = (
    g[k] for k in ("tlv", "seq", "oid", "integer", "name", "ext", "ext_bc", "ext_ku")
)
cert, key, simple_name, BMP, UTF8, OID_CN = (
    g[k] for k in ("cert", "key", "simple_name", "BMP", "UTF8", "OID_CN")
)


def write(fname, der):
    with open(os.path.join(HERE, fname), "wb") as f:
        f.write(der)


ROOT_KEY, ROOT_SPKI = key("root")  # resolves to ../nc/root.key.pem via HERE of helpers
ROOT_NAME = simple_name("Review Root")

# ------------------------------------------------------------ 1. wide RDN
N_AVAS = 1000
CHAIN = 2
wide = name([[(OID_CN, BMP, f"v{i:07d}") for i in range(N_AVAS)]])
for k in range(CHAIN):
    # Distinct serials (cert() increments a global counter) so
    # check_inputs does not short-circuit on DuplicateCertificate.
    write(f"dn_wide_rdn_{k}.der", cert(wide, wide, ROOT_SPKI, ROOT_KEY, [ext_bc(True), ext_ku(True)]))

print("ok")
