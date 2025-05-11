#!/usr/bin/env bash
if [ "x${AGI_DEBUG}" != "x" ]; then
  set -x
fi

#!/bin/bash

# Arrays to hold PIDs, directories, and cleanup functions
declare -a PIDs
declare -a directories
declare -a cleanup_functions

# Function to kill processes in PIDs array
cleanup_pids() {
  echo "Cleaning up PIDs..."
  for pid in "${PIDs[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      echo "Killing process $pid"
      kill "$pid" || echo "Failed to kill process $pid"
    fi
  done
}

# Function to remove directories in directories array
cleanup_dirs() {
  echo "Cleaning up directories..."
  for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
      echo "Removing directory $dir"
      rm -rf "$dir" || echo "Failed to remove directory $dir"
    fi
  done
}

# Function to execute all cleanup functions
run_cleanup() {
  # Iterate through all cleanup functions and execute them
  for cleanup_func in "${cleanup_functions[@]}"; do
    $cleanup_func
  done
}

# Trap to call cleanup functions on exit (EXIT signal)
trap run_cleanup EXIT

add_cleanup_function() {
  cleanup_functions+=("$1")
}

# Add cleanup functions to the array
add_cleanup_function cleanup_pids
add_cleanup_function cleanup_dirs

mkdir -pv "${CALLER_PATH}"
# directories+=("${CALLER_PATH}")
rm -f "${CALLER_PATH}/input.txt"
touch "${CALLER_PATH}/input.txt"
rm -f "${CALLER_PATH}/input-last-line.txt"
touch "${CALLER_PATH}/input-last-line.txt"

export agi_sock="${AGI_NAME}_AGI_SOCK"
export agi_sock_dir="${AGI_NAME}_SOCK_DIR"

curl -s --unix-socket "${!agi_sock}" -fLo "${CALLER_PATH}/util.sh" http://localhost/files/util.sh

cat > "${CALLER_PATH}/entrypoint.sh" <<WRITE_OUT_SH_EOF
#!/usr/bin/env bash
set -uo pipefail

# trap bash EXIT

if [ "x\$CALLER_PATH" = "x" ]; then
    export CALLER_PATH="${TEMPDIR}"
fi
export PS1='${AGI_PS1}'
WRITE_OUT_SH_EOF
curl -s --unix-socket "${!agi_sock}" -fL http://localhost/files/entrypoint.sh >> "${CALLER_PATH}/entrypoint.sh"

chmod 700 "${CALLER_PATH}/entrypoint.sh"

cat > "${CALLER_PATH}/request.yml" <<WRITE_OUT_SH_EOF
context:
  secrets: {}
  config:
    cwd: "${CALLER_PATH}"
inputs: {}
stack: {}
workflow:
  jobs:
    ssh:
      runs_on: target
      steps:
      - run: 'echo Hello World'
  name: null
  'on':
  - push
WRITE_OUT_SH_EOF

curl -s --unix-socket "${!agi_sock}" -fLo "${CALLER_PATH}/policy_engine.py" http://localhost/files/policy_engine.py

export FAIL_ON_ERROR=0
source "${CALLER_PATH}/entrypoint.sh"
unset FAIL_ON_ERROR
source "${CALLER_PATH}/util.sh"

if [ ! -f "${CALLER_PATH}/policy_engine.logs.txt" ]; then
    policy_engine_deps
fi

if [ -f "${CALLER_PATH}/.venv/bin/activate" ]; then
  OLD_PS1="${PS1}"
  source "${CALLER_PATH}/.venv/bin/activate"
  export PS1="${OLD_PS1}"
fi

export ${AGI_NAME}_POLICY_ENGINE_SOCK="${!agi_sock_dir}/policy-engine.sock"
export agi_policy_engine_sock="${AGI_NAME}_POLICY_ENGINE_SOCK"
DEBUG=1 NO_CELERY=1 python -u ${CALLER_PATH}/policy_engine.py api --bind "unix:${!agi_policy_engine_sock}" --workers 1 1>"${CALLER_PATH}/policy_engine.logs.txt" 2>&1 &
POLICY_ENGINE_PID=$!
PIDs+=("${POLICY_ENGINE_PID}")
until [ -S "${!agi_policy_engine_sock}" ]; do
  sleep 0.01
done

submit_policy_engine_request

export ${AGI_NAME}_MCP_REVERSE_PROXY_SOCK="${!agi_sock_dir}/mcp-reverse-proxy.sock"
export agi_mcp_reverse_proxy_sock="${AGI_NAME}_MCP_REVERSE_PROXY_SOCK"
curl -s --unix-socket "${!agi_sock}" -fLo "${CALLER_PATH}/Caddyfile" http://localhost/files/Caddyfile
sed -i -e "s#{{CALLER_PATH}}#${CALLER_PATH}#g" "${CALLER_PATH}/Caddyfile"
sed -i -e "s#{{AGI_SOCK_DIR}}#${!agi_sock_dir}#g" "${CALLER_PATH}/Caddyfile"

curl -s --unix-socket "${!agi_sock}" -fLo "${CALLER_PATH}/mcp_server_files.py" http://localhost/files/mcp_server_files.py

export agi_output="${AGI_NAME}_OUTPUT"
export agi_output_sock="${AGI_NAME}_OUTPUT_SOCK"
export ${AGI_NAME}_OUTPUT="${CALLER_PATH}/output.txt"
export ${AGI_NAME}_OUTPUT_SOCK="${!agi_sock_dir}/text-output.sock"
rm -fv "${!agi_output_sock}"
touch "${!agi_output}"
socat "UNIX-LISTEN:${!agi_output_sock},fork" EXEC:"/usr/bin/tee ${!agi_output}" &
OUTPUT_SOCK_PID=$!
PIDs+=("${OUTPUT_SOCK_PID}")
until [ -S "${!agi_output_sock}" ]; do
  sleep 0.01
done
until [ -f "${!agi_output}" ]; do
  sleep 0.01
done
ls -lAF "${!agi_output}"

export agi_ndjson_output="${AGI_NAME}_NDJSON_OUTPUT"
export agi_ndjson_output_sock="${AGI_NAME}_NDJSON_OUTPUT_SOCK"
export ${AGI_NAME}_NDJSON_OUTPUT="${CALLER_PATH}/output.ndjson"
export ${AGI_NAME}_NDJSON_OUTPUT_SOCK="${!agi_sock_dir}/ndjson-output.sock"
rm -fv "${!agi_ndjson_output_sock}"
touch "${!agi_ndjson_output}"
socat "UNIX-LISTEN:${!agi_ndjson_output_sock},fork" EXEC:"/usr/bin/tee ${!agi_ndjson_output}" &
NDJSON_OUTPUT_SOCK_PID=$!
PIDs+=("${NDJSON_OUTPUT_SOCK_PID}")
until [ -S "${!agi_ndjson_output_sock}" ]; do
  sleep 0.01
done
until [ -f "${!agi_ndjson_output}" ]; do
  sleep 0.01
done
ls -lAF "${!agi_ndjson_output}"

export agi_input="${AGI_NAME}_INPUT"
export agi_input_sock="${AGI_NAME}_INPUT_SOCK"
export ${AGI_NAME}_INPUT="${CALLER_PATH}/input.txt"
export ${AGI_NAME}_INPUT_SOCK="${!agi_sock_dir}/input.sock"
export ${AGI_NAME}_INPUT_LAST_LINE="${CALLER_PATH}/input-last-line.txt"
rm -fv "${!agi_input_sock}"
socat "UNIX-LISTEN:${!agi_input_sock},fork" EXEC:"/usr/bin/tail -F ${!agi_input}" &
until [ -S "${!agi_input_sock}" ]; do
  sleep 0.01
done
INPUT_SOCK_PID=$!
PIDs+=("${INPUT_SOCK_PID}")
ls -lAF "${!agi_input_sock}"

# if [ ! -f "${CALLER_PATH}/caddy.logs.txt" ]; then
export agi_mcp_reverse_proxy_sock="${AGI_NAME}_MCP_REVERSE_PROXY_SOCK"
export ${AGI_NAME}_MCP_REVERSE_PROXY_SOCK="${!agi_sock_dir}/mcp-reverse-proxy.sock"
HOME=${CALLER_PATH} caddy run --config ${CALLER_PATH}/Caddyfile 1>"${CALLER_PATH}/caddy.logs.txt" 2>&1 &
CADDY_PID=$!
PIDs+=("${CADDY_PID}")
until [ -S "${!agi_mcp_reverse_proxy_sock}" ]; do
  sleep 0.01
done

# cd ${CALLER_PATH}
# npm install @wonderwhy-er/desktop-commander@latest
# python -um mcp_proxy --sse-uds ${CALLER_PATH}/desktopcommander.sock -- npx @wonderwhy-er/desktop-commander@latest start 1>"${CALLER_PATH}/mcp_server_desktopcommander.logs.txt" 2>&1 &
python -um mcp_proxy --sse-uds "${!agi_sock_dir}/desktopcommander.sock" -- uvx mcp-server-fetch 1>"${CALLER_PATH}/mcp_server_desktopcommander.logs.txt" 2>&1 &
MCP_SERVER_DESKTOPCOMMANDER_PID=$!
PIDs+=("${MCP_SERVER_DESKTOPCOMMANDER_PID}")
until [ -S "${!agi_sock_dir}/desktopcommander.sock" ]; do
  sleep 0.01
done

python -u ${CALLER_PATH}/mcp_server_files.py --transport sse --uds "${!agi_sock_dir}/files.sock" 1>"${CALLER_PATH}/mcp_server_files.logs.txt" 2>&1 &
MCP_SERVER_FILES_PID=$!
PIDs+=("${MCP_SERVER_FILES_PID}")
until [ -S "${!agi_sock_dir}/files.sock" ]; do
  sleep 0.01
done

set +u
if [ "x${AGI_DEBUG}" != "x" ]; then
  set +x
fi
