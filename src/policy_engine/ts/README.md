# Policy Engine (TypeScript / Deno + Hono)

A TypeScript implementation of the policy engine — GitHub Actions workflow
evaluation — built on [Deno](https://deno.com) and [Hono](https://hono.dev).
It is a port of the Go implementation in [`../common`](../common), exposing the
same HTTP API and execution semantics.

## Layout

| File | Purpose |
| --- | --- |
| `main.ts` | CLI entrypoint (`api` and `run` commands) |
| `src/models.ts` | Request/response types, `Task`, `TaskManager`, execution context |
| `src/workflow.ts` | Workflow executor: expression evaluation, `run`/`uses` steps, outputs, annotations |
| `src/server.ts` | Hono app: request lifecycle, console output (plain + SSE), webhook, health |
| `src/logger.ts` | Leveled logging (`POLICY_ENGINE_LOG_LEVEL`) |

## Running

```bash
# Start the HTTP API server (default 127.0.0.1:8080)
deno task api
deno run --allow-all main.ts api --bind 0.0.0.0:9090
deno run --allow-all main.ts api --bind unix:/tmp/pe.sock

# Execute a workflow locally and print the status JSON
deno run --allow-all main.ts run --workflow ./workflow.yml --repository acme/widgets
deno run --allow-all main.ts run --workflow 'name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - run: echo hi' --input name=test
```

## HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/request/create` | Submit a workflow; returns `{status: submitted, detail: {id}}` |
| `GET` | `/request/status/:id` | Poll request status |
| `GET` | `/request/console_output/:id` | Full console output (text) |
| `GET` | `/request/console_output_stream/:id` | Console output as Server-Sent Events |
| `POST` | `/webhook/github` | GitHub `push` / `pull_request` webhook receiver |
| `GET` | `/rate_limit` | GitHub-API-compatible rate limit stub |
| `GET` | `/health` | Health check |

## Expression evaluation

`${{ ... }}` expressions are evaluated as JavaScript via a sandboxed `deno run`
subprocess, with the `github`, `runner`, `steps`, and `inputs` contexts in
scope (matching the Go/Python implementations). Step outputs stored as the
strings `"true"`/`"false"` are coerced to real booleans so comparisons like
`steps.x.outputs.y === true` behave as expected. Unresolved conditions fail
closed.

## Action resolution (`uses`)

1. Local path (`./path` or `/abs/path`)
2. Repo-supplied actions dir (`ACTIONS_DIR`, default `<workspace>/.tangled/actions`)
3. Bundled actions dir (`BUNDLED_ACTIONS_DIR`)
4. Download from GitHub (cached under `.cache/<org>/<repo>`)

Node actions run through Deno's Node compatibility layer; composite actions run
their `run` steps in sequence.

## Tests

```bash
deno task test
```

## Environment variables

| Variable | Effect |
| --- | --- |
| `POLICY_ENGINE_LOG_LEVEL` | `trace` / `debug` / `info` (default) / `warn` / `error` |
| `BUNDLED_ACTIONS_DIR` | Directory of pre-bundled actions |
| `DEBUG_DENO_PACKAGES` | Set to `1` to show Deno package download messages |
