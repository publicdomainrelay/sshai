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

submit_policy_engine_request() {
    tail -F "${CALLER_PATH}/policy_engine.logs.txt" &
    TAIL_PID=$!

    export POLICY_ENGINE_PORT=$(cat "${CALLER_PATH}/policy_engine_port.txt")

    TASK_ID=$(curl -X POST -H "Content-Type: application/json" -d @<(cat "${CALLER_PATH}/request.yml" | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') http://localhost:$POLICY_ENGINE_PORT/request/create  | jq -r .detail.id)

    STATUS=$(curl -sfL http://localhost:$POLICY_ENGINE_PORT/request/status/$TASK_ID | jq -r .status)
    while [ "x${STATUS}" != "xcomplete" ]; do
        STATUS=$(curl -sfL http://localhost:$POLICY_ENGINE_PORT/request/status/$TASK_ID | jq -r .status)
    done
    kill "${TAIL_PID}"
    STATUS=$(curl -sfL http://localhost:$POLICY_ENGINE_PORT/request/status/$TASK_ID | python -m json.tool > "${CALLER_PATH}/last-request-status.json")
    cat "${CALLER_PATH}/last-request-status.json" | jq
    export STATUS=$(cat "${CALLER_PATH}/last-request-status.json" | jq -r .status)
}

policy_engine_deps() {
  python -m pip install -U pip setuptools wheel build
  python -m pip install -U pyyaml snoop pytest httpx cachetools aiohttp gidgethub[aiohttp] celery[redis] fastapi pydantic gunicorn uvicorn

  # Other deps
  # - Formatting output as markdown for CLI
  python -m pip install -U rich

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
