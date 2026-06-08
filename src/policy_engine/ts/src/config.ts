// Sandbox configuration for the policy engine.
//
// The engine never shells out to the `deno` binary to evaluate expressions —
// instead it runs them in an in-process Web Worker with restricted Deno
// permissions (see src/eval.ts). This module resolves how that sandbox is
// configured, from CLI flags and/or environment variables.

/**
 * SandboxConfig controls how untrusted workflow content is executed.
 *
 * - `netOnly`: when true, the engine runs in a strict network-only sandbox.
 *   Expression evaluation is granted `net` permission (and nothing else),
 *   and any step that would require the filesystem or process execution
 *   (`run` steps, `uses` actions) is refused. When false (the default), the
 *   expression sandbox is granted no permissions at all, while `run`/`uses`
 *   steps execute normally.
 */
export interface SandboxConfig {
  netOnly: boolean;
}

/** Interpret common truthy strings ("1", "true", "yes", "on") as true. */
export function envBool(name: string): boolean {
  const v = (Deno.env.get(name) ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/**
 * Resolve the sandbox configuration. An explicit flag value (from the CLI)
 * takes precedence; otherwise the POLICY_ENGINE_NET_ONLY environment variable
 * is consulted. Defaults to the unrestricted ("full") sandbox.
 */
export function resolveSandboxConfig(flag?: boolean): SandboxConfig {
  const netOnly = flag !== undefined ? flag : envBool("POLICY_ENGINE_NET_ONLY");
  return { netOnly };
}
