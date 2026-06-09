import { assertEquals, assertStringIncludes } from "@std/assert";
import { runActionInWorker } from "./action_worker.ts";
import { WorkflowExecutor } from "./workflow.ts";
import { join } from "@std/path";

Deno.test("runActionInWorker: injects inputs, captures output and console", async () => {
  const source = `
const name = Deno.env.get("INPUT_NAME") ?? "world";
console.log("hello " + name);
const out = Deno.env.get("GITHUB_OUTPUT");
await Deno.writeTextFile(out, "greeting=hi-" + name + "\\n", { append: true });
`;
  const lines: string[] = [];
  const res = await runActionInWorker({
    source,
    env: { INPUT_NAME: "deno" },
    allowNet: false,
    onLine: (l) => lines.push(l),
  });
  assertEquals(res.code, 0);
  assertEquals(res.output, "greeting=hi-deno\n");
  assertEquals(lines, ["hello deno"]);
});

Deno.test("runActionInWorker: blocks real filesystem writes (uncaught -> exit 1)", async () => {
  const source = `await Deno.writeTextFile("/tmp/pe_should_not_exist", "x");`;
  const lines: string[] = [];
  const res = await runActionInWorker({
    source,
    env: {},
    allowNet: false,
    onLine: (l) => lines.push(l),
  });
  assertEquals(res.code, 1);
  assertStringIncludes(lines.join("\n"), "NotCapable");
});

Deno.test("runActionInWorker: blocks subprocess execution", async () => {
  const source = `
try { new Deno.Command("echo", { args: ["hi"] }).outputSync(); console.log("RAN"); }
catch (e) { console.log("blocked:" + e.name); }
`;
  const lines: string[] = [];
  const res = await runActionInWorker({
    source,
    env: {},
    allowNet: false,
    onLine: (l) => lines.push(l),
  });
  assertEquals(res.code, 0);
  assertStringIncludes(lines.join("\n"), "blocked:NotCapable");
});

Deno.test("runActionInWorker: network is gated by allowNet", async () => {
  const ac = new AbortController();
  const server = Deno.serve(
    { port: 0, signal: ac.signal, onListen: () => {} },
    () => new Response("pong"),
  );
  const port = (server.addr as Deno.NetAddr).port;
  const url = `http://127.0.0.1:${port}/`;

  try {
    // With net: succeeds.
    const ok = await runActionInWorker({
      source: `const r = await fetch(${
        JSON.stringify(url)
      }); console.log("got:" + (await r.text()));`,
      env: {},
      allowNet: true,
    });
    assertEquals(ok.code, 0);

    // Without net: fetch is denied -> uncaught -> exit 1.
    const lines: string[] = [];
    const denied = await runActionInWorker({
      source: `await fetch(${JSON.stringify(url)});`,
      env: {},
      allowNet: false,
      onLine: (l) => lines.push(l),
    });
    assertEquals(denied.code, 1);
    assertStringIncludes(lines.join("\n"), "NotCapable");
  } finally {
    ac.abort();
    await server.finished;
  }
});

Deno.test("WorkflowExecutor: runs a TS uses-action in net-only mode", async () => {
  // A bundled Deno-native action that fetches and writes a step output.
  const ac = new AbortController();
  const server = Deno.serve(
    { port: 0, signal: ac.signal, onListen: () => {} },
    () => new Response(JSON.stringify({ value: 42 })),
  );
  const port = (server.addr as Deno.NetAddr).port;

  const bundled = await Deno.makeTempDir({ prefix: "pe-bundled-" });
  const actDir = join(bundled, "test", "act");
  await Deno.mkdir(actDir, { recursive: true });
  await Deno.writeTextFile(
    join(actDir, "action.yml"),
    `name: Test\ndescription: t\ninputs:\n  endpoint:\n    default: ""\nruns:\n  using: node20\n  main: index.ts\n`,
  );
  await Deno.writeTextFile(
    join(actDir, "index.ts"),
    `const ep = Deno.env.get("INPUT_ENDPOINT") ?? "";
const resp = await fetch(ep);
const data = await resp.json();
console.log("fetched value " + data.value);
const out = Deno.env.get("GITHUB_OUTPUT");
if (out) await Deno.writeTextFile(out, "value=" + data.value + "\\n", { append: true });
`,
  );

  Deno.env.set("BUNDLED_ACTIONS_DIR", bundled);
  try {
    const executor = new WorkflowExecutor({ sandbox: { netOnly: true } });
    const status = await executor.executeWorkflow({
      workflow: `name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - id: a
      uses: test/act@v1
      with:
        endpoint: http://127.0.0.1:${port}/`,
    });
    assertEquals((status.detail as { exit_status: string }).exit_status, "success");
    assertStringIncludes(status.console_output ?? "", "fetched value 42");
  } finally {
    Deno.env.delete("BUNDLED_ACTIONS_DIR");
    ac.abort();
    await server.finished;
    await Deno.remove(bundled, { recursive: true });
  }
});
