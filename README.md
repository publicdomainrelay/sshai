# Ghost in Shell via SSH

[![asciicast](https://asciinema.org/a/716333.svg)](https://asciinema.org/a/716333)

```bash
# From within TMUX
export INPUT_SOCK="$(mktemp -d)/input.sock"; export OUTPUT_SOCK="$(mktemp -d)/text-output.sock"; export NDJSON_OUTPUT_SOCK="$(mktemp -d)/ndjson-output.sock"; export MCP_REVERSE_PROXY_SOCK="$(mktemp -d)/mcp-reverse-proxy.sock"; ssh -NnT -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no -R /tmux.sock:$(echo $TMUX | sed -e 's/,.*//g') -R "${OUTPUT_SOCK}:${OUTPUT_SOCK}" -R "${NDJSON_OUTPUT_SOCK}:${NDJSON_OUTPUT_SOCK}" -R "${MCP_REVERSE_PROXY_SOCK}:${MCP_REVERSE_PROXY_SOCK}" -R "${INPUT_SOCK}:${INPUT_SOCK}" user@alice.chadig.com
```

## Hosting

```bash
pip install sshai

export OPENAI_API_KEY=AAA
sshai --uds /tmp/agi.sock

# Now connect to port 2222
```

## TODOs

- We need to re-try TMUX connect when it doesn't work on ssh client connect
