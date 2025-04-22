# Ghost in Shell via SSH

```bash
# From within TMUX
export SSH_CALLER_PATH=$(mktemp -d); export AGI_SOCK="${SSH_CALLER_PATH}/agi.sock"; export INPUT_SOCK="${SSH_CALLER_PATH}/input.sock"; export OUTPUT_SOCK="${SSH_CALLER_PATH}/text-output.sock"; export NDJSON_OUTPUT_SOCK="${SSH_CALLER_PATH}/ndjson-output.sock"; export MCP_REVERSE_PROXY_SOCK="${SSH_CALLER_PATH}/mcp-reverse-proxy.sock"; ssh -NnT -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no -R /tmux.sock:$(echo $TMUX | sed -e 's/,.*//g') -R "${OUTPUT_SOCK}:${OUTPUT_SOCK}" -R "${NDJSON_OUTPUT_SOCK}:${NDJSON_OUTPUT_SOCK}" -R "${MCP_REVERSE_PROXY_SOCK}:${MCP_REVERSE_PROXY_SOCK}" -R "${INPUT_SOCK}:${INPUT_SOCK}" -L "${AGI_SOCK}:${AGI_SOCK}" user@localhost
```

[![asciicast](https://asciinema.org/a/716563.svg)](https://asciinema.org/a/716563)

## Hosting

```bash
# Temporary branch installs present until pending PRs close
pip install sshai \
    "mcp-proxy@git+https://github.com/johnandersen777/mcp-proxy@mcp_enable_over_unix_socket" \
    "mcp@git+https://github.com/johnandersen777/python-sdk@mcp_enable_over_unix_socket" \
    "openai-agents@git+https://github.com/johnandersen777/openai-agents-python@additional_properties_dict_keys_mcp_enable_over_unix_socket"

export OPENAI_API_KEY=AAA
sshai --uds /tmp/agi.sock

# Now connect to port 2222
```

## TODOs

- We need to re-try TMUX connect when it doesn't work on ssh client connect
