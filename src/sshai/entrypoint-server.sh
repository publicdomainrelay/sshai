#!/usr/bin/env bash

if [[ "x${CALLER_PATH}" = "x" ]]; then
  export CALLER_PATH="/host"
fi
mkdir -p "${CALLER_PATH}"

source "${CALLER_PATH}/util.sh"

export AGI_SOCK="${CALLER_PATH}/agi.sock"

tail -F "${CALLER_PATH}/agi.logs.txt" 2>/dev/null &
(cd "${CALLER_PATH}" && python -m uvicorn "agi:app" --uds "${AGI_SOCK}" 1>"${CALLER_PATH}/agi.logs.txt" 2>&1 &)

mkdir -p /var/run/alice-server/
agi_sshd
