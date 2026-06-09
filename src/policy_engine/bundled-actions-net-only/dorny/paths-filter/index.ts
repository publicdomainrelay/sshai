// Net-only variant of dorny/paths-filter.
//
// Differences from the standard variant:
//   - Uses dynamic import() for @std/yaml and @std/path so they work after
//     the policy-engine shim is prepended (static top-level imports must be
//     first in a module, but the shim is injected before the action source).
//   - Writes GITHUB_OUTPUT via the virtual FS shim (Deno.writeTextFile to the
//     sentinel path is intercepted) — no FS API needed for outputs.
//   - The import: true worker permission is required; the engine sets this
//     automatically when allowNet is true.

const { parse } = await import("jsr:@std/yaml");
const { globToRegExp } = await import("jsr:@std/path/posix");

const knot = Deno.env.get("SPINDLE_KNOT") ?? "";
const repoDid = Deno.env.get("SPINDLE_REPO_DID") ?? "";
const inputBase = Deno.env.get("INPUT_BASE") ?? "";
const currRef = Deno.env.get("INPUT_REF") || (Deno.env.get("GITHUB_SHA") ?? "");
const filtersYaml = Deno.env.get("INPUT_FILTERS") ?? "";
const githubOutput = Deno.env.get("GITHUB_OUTPUT") ?? "";

if (!knot || !repoDid || !currRef || !filtersYaml) {
  console.error(
    "::error::paths-filter: SPINDLE_KNOT, SPINDLE_REPO_DID, GITHUB_SHA, and filters input required",
  );
  Deno.exit(1);
}

const knotUrl = knot.startsWith("http") ? knot : `https://${knot}`;

interface TangledCommit {
  hash?: string;
  this?: string;
}

function commitHash(commit: TangledCommit): string | undefined {
  return typeof commit.hash === "string" ? commit.hash : commit.this;
}

async function findPreviousCommit(ref: string): Promise<string> {
  const listUrl =
    `${knotUrl}/xrpc/sh.tangled.git.temp.listCommits?repo=${encodeURIComponent(repoDid)}&ref=${encodeURIComponent(ref)}&limit=2`;
  const resp = await fetch(listUrl);
  if (!resp.ok) {
    console.error(
      `::error::paths-filter: failed to discover previous commit for "${ref}": ${resp.status} ${resp.statusText}`,
    );
    Deno.exit(1);
  }
  const data = await resp.json();
  const commits: TangledCommit[] = data.commits ?? [];
  const previous = commits[1] && commitHash(commits[1]);
  if (!previous) {
    console.error(`::error::paths-filter: "${ref}" has no previous commit to compare against`);
    Deno.exit(1);
  }
  return previous;
}

const baseRef = inputBase || (await findPreviousCommit(currRef));

const compareUrl =
  `${knotUrl}/xrpc/sh.tangled.repo.compare?repo=${encodeURIComponent(repoDid)}&rev1=${encodeURIComponent(baseRef)}&rev2=${encodeURIComponent(currRef)}`;

const resp = await fetch(compareUrl);
if (!resp.ok) {
  console.error(
    `::error::paths-filter: failed to fetch changed files: ${resp.status} ${resp.statusText}`,
  );
  Deno.exit(1);
}

const data = await resp.json();
const changedFiles: string[] = (data.files ?? []).map((f: { path: string }) => f.path);

const filters = parse(filtersYaml) as Record<string, string[]>;

const results: Record<string, boolean> = {};
for (const [name, patterns] of Object.entries(filters)) {
  const patternList = Array.isArray(patterns) ? patterns : [patterns];
  results[name] = changedFiles.some((file) =>
    patternList.some((pattern) =>
      globToRegExp(pattern, { extended: true, globstar: true }).test(file)
    )
  );
}

if (githubOutput) {
  for (const [key, value] of Object.entries(results)) {
    await Deno.writeTextFile(githubOutput, `${key}=${value}\n`, { append: true });
  }
}
