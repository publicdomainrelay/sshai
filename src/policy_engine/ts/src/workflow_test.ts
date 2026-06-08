import { assertEquals } from "jsr:@std/assert@^1.0.0";
import {
  convertBoolStrings,
  parseGitHubActionsOutputs,
  resolvePropertyPath,
  transformPropertyAccessors,
} from "./workflow.ts";

Deno.test("parseGitHubActionsOutputs: key=value", () => {
  const out = parseGitHubActionsOutputs("foo=bar\nbaz=qux\n");
  assertEquals(out, { foo: "bar", baz: "qux" });
});

Deno.test("parseGitHubActionsOutputs: heredoc block", () => {
  const content = "msg<<EOF\nline one\nline two\nEOF\nflag=true\n";
  const out = parseGitHubActionsOutputs(content);
  assertEquals(out, { msg: "line one\nline two", flag: "true" });
});

Deno.test("convertBoolStrings: nested string booleans become real booleans", () => {
  const input = { a: { outputs: { flag: "true", other: "false", name: "x" } } };
  assertEquals(convertBoolStrings(input), {
    a: { outputs: { flag: true, other: false, name: "x" } },
  });
});

Deno.test("transformPropertyAccessors: dots become bracket access", () => {
  assertEquals(
    transformPropertyAccessors("steps.greet.outputs.flag === true"),
    "steps['greet']['outputs']['flag'] === true",
  );
});

Deno.test("transformPropertyAccessors: leaves string literals untouched", () => {
  assertEquals(
    transformPropertyAccessors(`github.actor === "a.b.c"`),
    `github['actor'] === "a.b.c"`,
  );
});

Deno.test("resolvePropertyPath: resolves nested values", () => {
  const data = { github: { actor: "octocat" } };
  assertEquals(resolvePropertyPath("github.actor", data), "octocat");
  assertEquals(resolvePropertyPath("github.missing", data), undefined);
});
