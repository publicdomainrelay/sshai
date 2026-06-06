import { parse } from "jsr:@std/yaml";
import { globToRegExp } from "jsr:@std/path/posix";

const knot = Deno.env.get("SPINDLE_KNOT") ?? "";
const repoDid = Deno.env.get("SPINDLE_REPO_DID") ?? "";
const baseRef = Deno.env.get("INPUT_BASE") ?? "main";
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
const changedFiles: string[] = (data.files ?? []).map(
  (f: { path: string }) => f.path,
);

// filters YAML: Record<string, string[]>
const filters = parse(filtersYaml) as Record<string, string[]>;

const results: Record<string, boolean> = {};
for (const [name, patterns] of Object.entries(filters)) {
  const patternList = Array.isArray(patterns) ? patterns : [patterns];
  results[name] = changedFiles.some((file) =>
    patternList.some((pattern) => globToRegExp(pattern, { extended: true, globstar: true }).test(file))
  );
}

const changesJson = JSON.stringify(results);
console.log(`Filter results: ${changesJson}`);

if (githubOutput) {
  await Deno.writeTextFile(githubOutput, `changes=${changesJson}\n`, {
    append: true,
  });
}
