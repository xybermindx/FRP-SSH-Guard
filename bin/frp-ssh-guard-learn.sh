#!/usr/bin/env bash
# Stable service entry point; trusted journal parsing lives in Python.
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/frp-ssh-guard-learn.py"
