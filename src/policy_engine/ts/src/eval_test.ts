import { assertEquals, assertRejects, assertStringIncludes } from "@std/assert";
import { ExpressionEvaluator } from "./eval.ts";
import { WorkflowExecutor } from "./workflow.ts";

Deno.test("ExpressionEvaluator: evaluates a pure expression in the worker", async () => {
  const ev = new ExpressionEvaluator();
  try {
    assertEquals(await ev.evaluate(`(() => 1 + 2)()`), "3");
    assertEquals(await ev.evaluate(`(() => "a" === "a")()`), "true");
    assertEquals(await ev.evaluate(`(() => { const x = {a:{b:5}}; return x.a.b; })()`), "5");
  } finally {
    ev.close();
  }
});

Deno.test("ExpressionEvaluator: reuses one worker across many evaluations", async () => {
  const ev = new ExpressionEvaluator();
  try {
    const results = await Promise.all(
      [...Array(20)].map((_, i) => ev.evaluate(`(() => ${i} * 2)()`)),
    );
    assertEquals(results, [...Array(20)].map((_, i) => String(i * 2)));
  } finally {
    ev.close();
  }
});

Deno.test("ExpressionEvaluator: sandbox blocks filesystem access (default, no perms)", async () => {
  const ev = new ExpressionEvaluator();
  try {
    await assertRejects(
      () => ev.evaluate(`(() => Deno.readTextFileSync("/etc/hostname"))()`),
      Error,
    );
  } finally {
    ev.close();
  }
});

Deno.test("ExpressionEvaluator: net-only sandbox still blocks filesystem and exec", async () => {
  const ev = new ExpressionEvaluator({ allowNet: true });
  try {
    await assertRejects(
      () => ev.evaluate(`(() => Deno.readTextFileSync("/etc/hostname"))()`),
      Error,
    );
    await assertRejects(
      () => ev.evaluate(`(() => new Deno.Command("echo", { args: ["hi"] }).outputSync())()`),
      Error,
    );
  } finally {
    ev.close();
  }
});

Deno.test("WorkflowExecutor: evaluates expressions natively (no subprocess)", async () => {
  const executor = new WorkflowExecutor();
  const status = await executor.executeWorkflow({
    workflow: `name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - if: ${"${{ 1 == 1 }}"}
      run: 'true'`,
  });
  assertEquals((status.detail as { exit_status: string }).exit_status, "success");
});

Deno.test("WorkflowExecutor: net-only mode refuses run steps (no exec, no FS)", async () => {
  const executor = new WorkflowExecutor({ sandbox: { netOnly: true } });
  const status = await executor.executeWorkflow({
    workflow: `name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - run: echo hi`,
  });
  const detail = status.detail as { exit_status: string; annotations: { error?: string[] } };
  assertEquals(detail.exit_status, "failure");
  assertStringIncludes(detail.annotations.error?.[0] ?? "", "net-only sandbox mode");
});

Deno.test("WorkflowExecutor: net-only mode still evaluates expressions", async () => {
  const executor = new WorkflowExecutor({ sandbox: { netOnly: true } });
  // The run step is skipped by a false if-condition, so no exec is attempted;
  // the expression itself is evaluated in the (net-only) sandbox worker.
  const status = await executor.executeWorkflow({
    workflow: `name: t
on: push
jobs:
  j:
    runs-on: self-hosted
    steps:
    - if: ${"${{ 1 == 2 }}"}
      run: echo nope`,
  });
  assertEquals((status.detail as { exit_status: string }).exit_status, "success");
});
