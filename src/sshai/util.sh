node_install() {
  sudo dnf install -y node
}

deno_install() {
  if [ ! -f /usr/bin/deno ]; then
    curl -fsSL https://deno.land/install.sh | sh
    export DENO_INSTALL="${HOME}/.deno"
    export PATH="$DENO_INSTALL/bin:$PATH"
    hash -r
    cp -v $(which deno) /usr/bin/deno || true
  fi
}

check_policy_engine_request() {
    local agi_policy_engine_sock="${AGI_NAME}_POLICY_ENGINE_SOCK"
    curl --unix-socket "${!agi_policy_engine_sock}" -sfL http://localhost/request/status/$POLICY_ENGINE_TASK_ID | jq
}

check_error_policy_engine_request() {
    local agi_policy_engine_sock="${AGI_NAME}_POLICY_ENGINE_SOCK"
    curl --unix-socket "${!agi_policy_engine_sock}" -sfL http://localhost/request/status/$POLICY_ENGINE_TASK_ID | jq -r .detail.annotations.error[0]
}

console_output_policy_engine_request() {
    local agi_policy_engine_sock="${AGI_NAME}_POLICY_ENGINE_SOCK"
    curl --unix-socket "${!agi_policy_engine_sock}" -sfL http://localhost/request/console_output/$POLICY_ENGINE_TASK_ID
}

submit_policy_engine_request() {
    tail -F "${CALLER_PATH}/policy_engine.logs.txt" &
    TAIL_PID=$!

    local policy_engine_pid=0
    local agi_policy_engine_sock="${AGI_NAME}_POLICY_ENGINE_SOCK"
    if [ ! -S "${!agi_policy_engine_sock}" ]; then
      DEBUG=1 NO_CELERY=1 python -u ${CALLER_PATH}/policy_engine.py api --bind "unix:${!agi_policy_engine_sock}" --workers 1 1>"${CALLER_PATH}/policy_engine.logs.txt" 2>&1 &
      policy_engine_pid=$!
    fi
    until [ -S "${!agi_policy_engine_sock}" ]; do
      sleep 0.01
    done

    export POLICY_ENGINE_TASK_ID=$(curl --unix-socket "${!agi_policy_engine_sock}" -X POST -H "Content-Type: application/json" -d @<(cat "${CALLER_PATH}/request.yml" | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') http://localhost/request/create  | jq -r .detail.id)

    STATUS=$(curl --unix-socket "${!agi_policy_engine_sock}" -sfL http://localhost/request/status/$POLICY_ENGINE_TASK_ID | jq -r .status)
    while [ "x${STATUS}" != "xcomplete" ]; do
        STATUS=$(curl --unix-socket "${!agi_policy_engine_sock}" -sfL http://localhost/request/status/$POLICY_ENGINE_TASK_ID | jq -r .status)
        sleep 0.01
    done
    kill "${TAIL_PID}"
    STATUS=$(curl --unix-socket "${!agi_policy_engine_sock}" -sfL http://localhost/request/status/$POLICY_ENGINE_TASK_ID | python -m json.tool > "${CALLER_PATH}/last-request-status.json")
    cat "${CALLER_PATH}/last-request-status.json" | jq
    export STATUS=$(cat "${CALLER_PATH}/last-request-status.json" | jq -r .status)

    if [ "x${policy_engine_pid}" != "x0" ]; then
        kill "${policy_engine_pid}"
    fi
}

policy_engine_deps() {
  if [ ! -f "${CALLER_PATH}/.venv/bin/activate" ]; then
    python -m venv "${CALLER_PATH}/.venv"
  fi
  OLD_PS1="${PS1}"
  source "${CALLER_PATH}/.venv/bin/activate"
  export PS1="${OLD_PS1}"
  python -m pip install -U pip setuptools wheel build
  python -m pip install -U pyyaml snoop pytest httpx cachetools aiohttp gidgethub[aiohttp] celery[redis] fastapi pydantic gunicorn uvicorn

  # Other deps
  # - Formatting output as markdown for CLI
  python -m pip install -U rich uv

  # MCP deps
  python -m pip install -U \
    'mcp-proxy@git+https://github.com/johnandersen777/mcp-proxy@mcp_enable_over_unix_socket'
}

find_listening_ports() {
  # Check if PID is provided
  if [ -z "$1" ]; then
    echo "Usage: find_listening_ports <PID>" 1>&2
    return 1
  fi

  PID=$1

  # Check if the process with the given PID exists
  if ! ps -p $PID > /dev/null 2>&1; then
    echo "Process with PID $PID does not exist." 1>&2
    return 1
  fi

  # Find listening TCP ports for the given PID using ss
  LISTENING_PORTS=$(ss -ltnp 2>/dev/null | grep "pid=$PID")

  if [ -z "$LISTENING_PORTS" ]; then
    echo "Process with PID $PID not listening on any ports." 1>&2
    return 1
  fi

  echo "$LISTENING_PORTS" | awk '{print $4}' | awk -F':' '{print $NF}'
}

agi() {
  local input="${AGI_NAME}_INPUT"
  local ndjson_output="${AGI_NAME}_NDJSON_OUTPUT"
  tee -a ${!input} && tail -F ${!ndjson_output} | jq
}
