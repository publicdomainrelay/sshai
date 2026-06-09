#!/usr/bin/env -S deno run --allow-all --unstable-worker-options
// Policy engine CLI entrypoint (Deno + Hono).
//
// Expression evaluation runs in an in-process, permission-restricted Web
// Worker (never a `deno run` subprocess), which requires the
// --unstable-worker-options flag — already present in the shebang and the
// deno tasks.
//
// Usage:
//   deno run --allow-all --unstable-worker-options main.ts api [--bind ...] [--net-only]
//   deno run --allow-all --unstable-worker-options main.ts run --workflow <file|inline> [--net-only]

import { parseArgs } from "@std/cli/parse-args";
import { createApp, parseBind } from "./src/server.ts";
import type { PolicyEngineRequest } from "./src/models.ts";
import { WorkflowExecutor } from "./src/workflow.ts";
import { resolveSandboxConfig } from "./src/config.ts";
import { Info } from "./src/logger.ts";

function usage(): never {
  console.error(`policy-engine — GitHub Actions workflow evaluation

Commands:
  api            Start the HTTP API server
                   --bind <addr>    Address to bind (default 127.0.0.1:8080)
                   --net-only       Strict sandbox: expression eval gets network
                                    access only; no filesystem, no exec, no
                                    run/uses steps (env: POLICY_ENGINE_NET_ONLY)
                   --fs-api         Start an in-process HTTP filesystem API on a
                                    random port and inject POLICY_ENGINE_FS_API_URL
                                    into action workers (env: POLICY_ENGINE_FS_API)
  run            Execute a workflow locally and print the status JSON
                   --workflow <s>   Workflow file path or inline YAML (required)
                   --input k=v      Input pairs (repeatable)
                   --repository <s> org/repo (sets GITHUB_REPOSITORY)
                   --net-only       See above
                   --fs-api         See above
`);
  Deno.exit(2);
}

function sandboxFromFlags(flags: { "net-only"?: boolean; "fs-api"?: boolean }) {
  return resolveSandboxConfig({
    netOnly: flags["net-only"] ? true : undefined,
    fsApi: flags["fs-api"] ? true : undefined,
  });
}

function cmdApi(args: string[]): void {
  const flags = parseArgs(args, {
    string: ["bind"],
    boolean: ["net-only", "fs-api"],
    default: { bind: "127.0.0.1:8080" },
  });
  const sandbox = sandboxFromFlags(flags);
  const { app } = createApp(sandbox);
  const opts = parseBind(flags.bind);
  Info("starting policy engine API server on %s (net-only=%v)", flags.bind, sandbox.netOnly);
  // deno-lint-ignore no-explicit-any
  Deno.serve(opts as any, app.fetch);
}

async function cmdRun(args: string[]): Promise<void> {
  const flags = parseArgs(args, {
    string: ["workflow", "repository"],
    boolean: ["net-only", "fs-api"],
    collect: ["input"],
  });
  if (!flags.workflow) usage();

  // A workflow value that points at an existing file is read; otherwise it is
  // treated as inline YAML.
  let workflow = flags.workflow as string;
  try {
    const stat = await Deno.stat(workflow);
    if (stat.isFile) workflow = await Deno.readTextFile(workflow);
  } catch {
    // not a file — treat as inline
  }

  const inputs: Record<string, unknown> = {};
  for (const pair of (flags.input as string[] | undefined) ?? []) {
    const idx = pair.indexOf("=");
    if (idx >= 0) inputs[pair.slice(0, idx)] = pair.slice(idx + 1);
  }

  const env: Record<string, unknown> = {};
  if (flags.repository) env["GITHUB_REPOSITORY"] = flags.repository;

  const request: PolicyEngineRequest = {
    workflow,
    inputs,
    context: { config: { env } },
  };

  const executor = new WorkflowExecutor({ sandbox: sandboxFromFlags(flags) });
  const status = await executor.executeWorkflow(request);
  console.log(JSON.stringify(status, null, 2));

  const detail = status.detail as { exit_status?: string };
  if (detail?.exit_status === "failure") Deno.exit(1);
}

async function main(): Promise<void> {
  const [command, ...rest] = Deno.args;
  switch (command) {
    case "api":
      await cmdApi(rest);
      break;
    case "run":
      await cmdRun(rest);
      break;
    default:
      usage();
  }
}

if (import.meta.main) {
  await main();
}
