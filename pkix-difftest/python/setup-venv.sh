#!/usr/bin/env bash
# Idempotent venv bootstrap for the pkix-difftest pyca oracle.
#
# Creates ./pkix-difftest/python/.venv and installs cryptography >= 45 (which
# provides build_client_verifier and ExtensionPolicy.permit_all). System
# Python 3.12's cryptography 41.0.7 lacks the verification module entirely,
# so a venv is required.
#
# Usage:
#   pkix-difftest/python/setup-venv.sh
#
# Re-running is safe; pip skips already-installed packages.
#
# After running, point the harness at the venv via:
#   export PYCA_DIFFTEST_PYTHON="$PWD/pkix-difftest/python/.venv/bin/python"
#
# (Or rely on the Rust wrapper's auto-detection of the .venv path.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
REQUIRED_VERSION="cryptography>=45"

echo "pkix-difftest/python: setting up venv at ${VENV_DIR}"

if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
    echo "  created venv"
fi

# Use the venv's pip directly, do not activate. Activation modifies PATH and
# is unnecessary for one-shot pip install.
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet "${REQUIRED_VERSION}"

# Sanity check: confirm the new module is importable from this venv.
if ! "${VENV_DIR}/bin/python" -c "from cryptography.x509.verification import PolicyBuilder, Store" 2>/dev/null; then
    echo "  ERROR: cryptography.x509.verification not importable in venv" >&2
    exit 1
fi

INSTALLED_VER="$("${VENV_DIR}/bin/python" -c 'import cryptography; print(cryptography.__version__)')"
echo "  cryptography ${INSTALLED_VER} ready"
echo
echo "To use the venv with pkix-difftest, export:"
echo "  PYCA_DIFFTEST_PYTHON=\"${VENV_DIR}/bin/python\""
echo
echo "Or rely on the Rust wrapper's auto-detection (it tries this path by default)."
