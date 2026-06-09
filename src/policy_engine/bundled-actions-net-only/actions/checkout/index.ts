// Net-only variant of tangled/checkout.
//
// Delegates all filesystem operations to the POLICY_ENGINE_FS_API_URL server
// (started by the policy engine when --fs-api is set) instead of calling
// Deno.mkdir / Deno.writeFile directly, allowing the action to run inside the
// permission-restricted worker where real FS access is blocked.

const knot = Deno.env.get("SPINDLE_KNOT") ?? "";
const repoDid = Deno.env.get("SPINDLE_REPO_DID") ?? "";
const ref = Deno.env.get("INPUT_REF") || (Deno.env.get("GITHUB_SHA") ?? "");
const dest = Deno.env.get("INPUT_PATH") || ".";
const fsApiUrl = (Deno.env.get("POLICY_ENGINE_FS_API_URL") ?? "").replace(/\/$/, "");

if (!knot || !repoDid || !ref) {
  console.error(
    "::error::tangled/checkout: SPINDLE_KNOT, SPINDLE_REPO_DID, and GITHUB_SHA must be set",
  );
  Deno.exit(1);
}

if (!fsApiUrl) {
  console.error(
    "::error::tangled/checkout (net-only): POLICY_ENGINE_FS_API_URL must be set — start the engine with --fs-api",
  );
  Deno.exit(1);
}

const knotUrl = knot.startsWith("http") ? knot : `https://${knot}`;

interface TreeEntry {
  mode: string;
  name: string;
}

const DIR_MODE = "0040000";

async function fetchTree(subpath: string): Promise<string[]> {
  const treeUrl =
    `${knotUrl}/xrpc/sh.tangled.repo.tree?repo=${encodeURIComponent(repoDid)}&ref=${encodeURIComponent(ref)}&path=${encodeURIComponent(subpath)}`;
  const resp = await fetch(treeUrl);
  if (!resp.ok) {
    throw new Error(`failed to list tree at "${subpath}": ${resp.status} ${resp.statusText}`);
  }
  const data = await resp.json();
  const entries: TreeEntry[] = data.files ?? [];

  const filePaths: string[] = [];
  const subtrees: Promise<string[]>[] = [];

  for (const entry of entries) {
    const fullpath = subpath ? `${subpath}/${entry.name}` : entry.name;
    if (entry.mode === DIR_MODE) {
      subtrees.push(fetchTree(fullpath));
    } else {
      filePaths.push(fullpath);
    }
  }

  const nested = await Promise.all(subtrees);
  for (const paths of nested) filePaths.push(...paths);
  return filePaths;
}

async function fsApiMkdir(path: string): Promise<void> {
  const resp = await fetch(`${fsApiUrl}/mkdir?path=${encodeURIComponent(path)}`, { method: "POST" });
  if (!resp.ok) throw new Error(`mkdir ${path}: ${resp.status} ${await resp.text()}`);
}

async function fsApiWriteFile(path: string, body: Uint8Array): Promise<void> {
  const resp = await fetch(`${fsApiUrl}/file?path=${encodeURIComponent(path)}`, {
    method: "PUT",
    body,
  });
  if (!resp.ok) throw new Error(`write ${path}: ${resp.status} ${await resp.text()}`);
}

async function fetchAndWriteFile(fullpath: string): Promise<void> {
  const blobUrl =
    `${knotUrl}/xrpc/sh.tangled.repo.blob?repo=${encodeURIComponent(repoDid)}&ref=${encodeURIComponent(ref)}&path=${encodeURIComponent(fullpath)}&raw=true`;
  const resp = await fetch(blobUrl);
  if (!resp.ok) {
    throw new Error(`failed to fetch blob "${fullpath}": ${resp.status} ${resp.statusText}`);
  }
  const destPath = `${dest}/${fullpath}`;
  const body = new Uint8Array(await resp.arrayBuffer());
  await fsApiWriteFile(destPath, body);
}

await fsApiMkdir(dest);

const filePaths = await fetchTree("");
await Promise.all(filePaths.map((p) => fetchAndWriteFile(p)));

console.log(`Checked out ${ref} from ${knotUrl} (${filePaths.length} files)`);
