import { assertEquals, assertStringIncludes } from "@std/assert";
import { join } from "@std/path";
import { startFsApiServer } from "./fs_api.ts";

Deno.test("FsApiServer: mkdir, write, read, ls", async () => {
  const root = await Deno.makeTempDir({ prefix: "pe-fsapi-test-" });
  const srv = await startFsApiServer(root);

  try {
    // mkdir
    let r = await fetch(`${srv.url}/mkdir?path=sub/dir`, { method: "POST" });
    assertEquals(r.status, 200);

    // write file (PUT)
    const content = new TextEncoder().encode("hello world");
    r = await fetch(`${srv.url}/file?path=sub/dir/hello.txt`, {
      method: "PUT",
      body: content,
    });
    assertEquals(r.status, 200);

    // verify on real FS
    const onDisk = await Deno.readTextFile(join(root, "sub/dir/hello.txt"));
    assertEquals(onDisk, "hello world");

    // read file (GET)
    r = await fetch(`${srv.url}/file?path=sub/dir/hello.txt`);
    assertEquals(r.status, 200);
    const bytes = new Uint8Array(await r.arrayBuffer());
    assertEquals(new TextDecoder().decode(bytes), "hello world");

    // ls
    r = await fetch(`${srv.url}/ls?path=sub/dir`);
    assertEquals(r.status, 200);
    const entries = await r.json() as { name: string; type: string }[];
    assertEquals(entries.length, 1);
    assertEquals(entries[0].name, "hello.txt");
    assertEquals(entries[0].type, "file");

    // path traversal is blocked
    r = await fetch(`${srv.url}/file?path=../escape`);
    assertEquals(r.status, 403);
  } finally {
    await srv.close();
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("WorkflowExecutor: fs-api injects POLICY_ENGINE_FS_API_URL", async () => {
  const { WorkflowExecutor } = await import("./workflow.ts");

  // A bundled net-only action that reads the URL from its env and hits the FS API.
  const bundled = await Deno.makeTempDir({ prefix: "pe-bundled-fsapi-" });
  const actDir = join(bundled, "test", "fsact");
  await Deno.mkdir(actDir, { recursive: true });
  await Deno.writeTextFile(
    join(actDir, "action.yml"),
    `name: Test\ndescription: t\nruns:\n  using: node20\n  main: index.ts\n`,
  );
  await Deno.writeTextFile(
    join(actDir, "index.ts"),
    `const fsUrl = (Deno.env.get("POLICY_ENGINE_FS_API_URL") ?? "").replace(/\\/+$/, "");
if (!fsUrl) { console.error("no FS API URL"); Deno.exit(1); }
// Write a file via the API.
const body = new TextEncoder().encode("from-action");
const r = await fetch(fsUrl + "/file?path=result.txt", { method: "PUT", body });
if (!r.ok) { console.error("write failed: " + r.status); Deno.exit(1); }
// Read it back.
const r2 = await fetch(fsUrl + "/file?path=result.txt");
const text = new TextDecoder().decode(new Uint8Array(await r2.arrayBuffer()));
console.log("read-back: " + text);
const out = Deno.env.get("GITHUB_OUTPUT");
if (out) await Deno.writeTextFile(out, "content=" + text + "\\n", { append: true });
`,
  );

  Deno.env.set("BUNDLED_ACTIONS_DIR", bundled);
  try {
    const executor = new WorkflowExecutor({ sandbox: { netOnly: true, fsApi: true } });
    const status = await executor.executeWorkflow({
      workflow: `name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - id: a
      uses: test/fsact@v1`,
    });
    assertEquals((status.detail as { exit_status: string }).exit_status, "success");
    assertStringIncludes(status.console_output ?? "", "read-back: from-action");
  } finally {
    Deno.env.delete("BUNDLED_ACTIONS_DIR");
    await Deno.remove(bundled, { recursive: true });
  }
});
