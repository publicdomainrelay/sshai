# Policy Engine (TypeScript / Deno + Hono)

A TypeScript implementation of the policy engine — GitHub Actions workflow evaluation — built on
[Deno](https://deno.com) and [Hono](https://hono.dev). It is a port of the Go implementation in
[`../common`](../common), exposing the same HTTP API and execution semantics.

## Layout

| File              | Purpose                                                                            |
| ----------------- | ---------------------------------------------------------------------------------- |
| `main.ts`         | CLI entrypoint (`api` and `run` commands)                                          |
| `src/models.ts`   | Request/response types, `Task`, `TaskManager`, execution context                   |
| `src/workflow.ts` | Workflow executor: expression evaluation, `run`/`uses` steps, outputs, annotations |
| `src/eval.ts`     | Native sandboxed expression evaluator (permission-restricted Worker)               |
| `src/config.ts`   | Sandbox configuration (full vs. net-only)                                          |
| `src/server.ts`   | Hono app: request lifecycle, console output (plain + SSE), webhook, health         |
| `src/logger.ts`   | Leveled logging (`POLICY_ENGINE_LOG_LEVEL`)                                        |

> **Note:** the engine evaluates expressions in a permission-restricted Web Worker, which requires
> Deno's `--unstable-worker-options` flag. It is baked into the shebang and the `deno task`
> definitions; pass it explicitly if you invoke `deno run` yourself.

## Running

```bash
# Start the HTTP API server (default 127.0.0.1:8080)
deno task api
deno task api --bind 0.0.0.0:9090
deno task api --bind unix:/tmp/pe.sock

# Execute a workflow locally and print the status JSON
deno task run --workflow ./workflow.yml --repository acme/widgets
deno task run --workflow 'name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - run: echo hi' --input name=test

# Equivalent raw invocation (note the unstable flag)
deno run --allow-all --unstable-worker-options main.ts api --bind 0.0.0.0:9090
```

## HTTP API

| Method | Path                                 | Description                                                    |
| ------ | ------------------------------------ | -------------------------------------------------------------- |
| `POST` | `/request/create`                    | Submit a workflow; returns `{status: submitted, detail: {id}}` |
| `GET`  | `/request/status/:id`                | Poll request status                                            |
| `GET`  | `/request/console_output/:id`        | Full console output (text)                                     |
| `GET`  | `/request/console_output_stream/:id` | Console output as Server-Sent Events                           |
| `POST` | `/webhook/github`                    | GitHub `push` / `pull_request` webhook receiver                |
| `GET`  | `/rate_limit`                        | GitHub-API-compatible rate limit stub                          |
| `GET`  | `/health`                            | Health check                                                   |

## Expression evaluation & sandboxing

`${{ ... }}` expressions are evaluated as JavaScript with the `github`, `runner`, `steps`, and
`inputs` contexts in scope. Step outputs stored as the strings `"true"`/`"false"` are coerced to
real booleans so comparisons like `steps.x.outputs.y === true` behave as expected. Unresolved
conditions fail closed.

Evaluation **never shells out to the `deno` binary**. Instead each expression runs inside a
long-lived, in-process Web Worker whose Deno permissions are locked down. Even though the host
process may run with `--allow-all`, the worker can only do what its permission set allows:

| Mode             | Worker permissions            | `run` / `uses` steps | Filesystem               |
| ---------------- | ----------------------------- | -------------------- | ------------------------ |
| `full` (default) | none (no net, no FS, no exec) | executed normally    | ephemeral workspace/temp |
| `net-only`       | network only                  | **refused**          | **never touched**        |

In `net-only` mode the engine is a pure policy evaluator: expressions may make network calls (and
nothing else), and any step that would require the filesystem or process execution is rejected with
a clear error. This is enabled with the `--net-only` CLI flag or the `POLICY_ENGINE_NET_ONLY`
environment variable.

```bash
# Strict network-only sandbox — never touches the filesystem, never execs
deno task api --net-only
POLICY_ENGINE_NET_ONLY=1 deno task api
```

## Action resolution (`uses`)

1. Local path (`./path` or `/abs/path`)
2. Repo-supplied actions dir (`ACTIONS_DIR`, default `<workspace>/.tangled/actions`)
3. Bundled actions dir (`BUNDLED_ACTIONS_DIR`)
4. Download from GitHub (cached under `.cache/<org>/<repo>`)

Node actions run through Deno's Node compatibility layer; composite actions run their `run` steps in
sequence.

## Tests

```bash
deno task test
```

## Environment variables

| Variable                  | Effect                                                      |
| ------------------------- | ----------------------------------------------------------- |
| `POLICY_ENGINE_LOG_LEVEL` | `trace` / `debug` / `info` (default) / `warn` / `error`     |
| `POLICY_ENGINE_NET_ONLY`  | Set truthy (`1`/`true`) for the strict network-only sandbox |
| `BUNDLED_ACTIONS_DIR`     | Directory of pre-bundled actions                            |
| `DEBUG_DENO_PACKAGES`     | Set to `1` to show Deno package download messages           |
