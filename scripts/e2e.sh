#!/usr/bin/env bash
# End-to-end test: builds atlas-portmap (with the race detector unless E2E_NO_RACE=1) and maps a
# synthetic network served by snmpsim. snmpsim lives in a throwaway venv under .cache/.
set -euo pipefail
cd "$(dirname "$0")/.."
VENV=.cache/e2e-venv
if [ ! -x "$VENV/bin/snmpsim-command-responder" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  # snmpsim 1.2.x imports pysmi without declaring it, and needs cryptography for SNMPv3
  # privacy (without it the agent cannot decrypt AES and answers v3 requests with a report).
  "$VENV/bin/pip" install -q 'snmpsim>=1.2,<2' 'pysmi>=2,<3' 'cryptography>=43'
fi
export SNMPSIM="$PWD/$VENV/bin/snmpsim-command-responder"
exec go test -tags e2e -count=1 -v ./e2e/ "$@"
