const knot = Deno.env.get("SPINDLE_KNOT") ?? "";
const repoDid = Deno.env.get("SPINDLE_REPO_DID") ?? "";
const ref = Deno.env.get("INPUT_REF") || (Deno.env.get("GITHUB_SHA") ?? "");
const dest = Deno.env.get("INPUT_PATH") || ".";

if (!knot || !repoDid || !ref) {
  console.error(
    "::error::tangled/checkout: SPINDLE_KNOT, SPINDLE_REPO_DID, and GITHUB_SHA must be set",
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
    throw new Error(
      `failed to list tree at "${subpath}": ${resp.status} ${resp.statusText}`,
    );
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
  for (const paths of nested) {
    filePaths.push(...paths);
  }
  return filePaths;
}

async function fetchAndWriteFile(fullpath: string): Promise<void> {
  const blobUrl =
    `${knotUrl}/xrpc/sh.tangled.repo.blob?repo=${encodeURIComponent(repoDid)}&ref=${encodeURIComponent(ref)}&path=${encodeURIComponent(fullpath)}&raw=true`;
  const resp = await fetch(blobUrl);
  if (!resp.ok) {
    throw new Error(
      `failed to fetch blob "${fullpath}": ${resp.status} ${resp.statusText}`,
    );
  }
  const destPath = `${dest}/${fullpath}`;
  await Deno.mkdir(destPath.substring(0, destPath.lastIndexOf("/")), {
    recursive: true,
  });
  const body = new Uint8Array(await resp.arrayBuffer());
  await Deno.writeFile(destPath, body);
}

await Deno.mkdir(dest, { recursive: true });

const filePaths = await fetchTree("");
await Promise.all(filePaths.map((p) => fetchAndWriteFile(p)));

console.log(`Checked out ${ref} from ${knotUrl} (${filePaths.length} files)`);
