// Workflow execution engine — a TypeScript (Deno) port of
// ../../common/workflow.go. Executes GitHub Actions workflows: evaluates
// ${{ }} expressions via Deno, runs `run` steps and `uses` actions
// (node / composite / local / remote), and collects outputs and annotations.

import { parse as parseYaml } from "@std/yaml";
import { join } from "@std/path";
import {
  type GitHubCheckSuiteAnnotation,
  type PolicyEngineRequest,
  type PolicyEngineStatus,
  type PolicyEngineWorkflow,
  type PolicyEngineWorkflowJob,
  type PolicyEngineWorkflowJobStep,
  StatusComplete,
  type Task,
  WorkflowExecutionContext,
} from "./models.ts";
import { Debug, Info, LogError, Trace } from "./logger.ts";

/** Parse a workflow from a string (YAML) or an object. */
export function parseWorkflow(input: unknown): PolicyEngineWorkflow {
  if (typeof input === "string") {
    return parseYaml(input) as PolicyEngineWorkflow;
  }
  if (input && typeof input === "object") {
    return input as PolicyEngineWorkflow;
  }
  throw new Error(`unsupported workflow type: ${typeof input}`);
}

interface ActionStep {
  run?: string;
  shell?: string;
  env?: Record<string, string>;
}

interface ActionDef {
  runs?: {
    using?: string;
    main?: string;
    steps?: ActionStep[];
  };
  inputs?: Record<string, { default?: string }>;
}

/** Executes workflows. */
export class WorkflowExecutor {
  denoPath: string;
  ctx: WorkflowExecutionContext;
  task: Task | null = null;

  constructor(denoPath = Deno.execPath()) {
    this.denoPath = denoPath;
    this.ctx = new WorkflowExecutionContext();
  }

  /** Execute a parsed workflow and return its final status. */
  async executeWorkflow(request: PolicyEngineRequest): Promise<PolicyEngineStatus> {
    Info("executing workflow");
    const workflow = parseWorkflow(request.workflow);
    const jobs = workflow.jobs ?? {};
    Info("workflow parsed: name=%q jobs=%d", workflow.name ?? "", Object.keys(jobs).length);

    await this.initializeContext(request);
    Debug("context initialized: workspace=%s", this.ctx.workspace);

    try {
      for (const [jobName, job] of Object.entries(jobs)) {
        Info("starting job: %s (steps=%d)", jobName, job.steps?.length ?? 0);
        try {
          await this.executeJob(jobName, job);
        } catch (err) {
          LogError("job %s failed: %v", jobName, err);
          this.ctx.error = err as Error;
          return this.createErrorStatus(err as Error);
        }
        Info("job %s completed successfully", jobName);
      }
      Info("workflow completed successfully");
      return this.createSuccessStatus();
    } finally {
      // Clean up ephemeral directories. cacheDir is intentionally kept.
      await this.removeAll(this.ctx.workspace);
      await this.removeAll(this.ctx.toolCacheDir);
      await this.removeAll(this.ctx.homeDir);
    }
  }

  private async removeAll(path: string): Promise<void> {
    if (!path) return;
    try {
      await Deno.remove(path, { recursive: true });
    } catch {
      // ignore
    }
  }

  /** Initialize the execution context from the request. */
  private async initializeContext(request: PolicyEngineRequest): Promise<void> {
    if (request.inputs) {
      Object.assign(this.ctx.inputs, request.inputs);
    }

    const context = request.context;
    if (context) {
      const config = context["config"] as Record<string, unknown> | undefined;
      const env = config?.["env"] as Record<string, unknown> | undefined;
      if (env) Object.assign(this.ctx.env, env);

      const secrets = context["secrets"] as Record<string, unknown> | undefined;
      if (secrets) {
        for (const [k, v] of Object.entries(secrets)) {
          if (typeof v === "string") this.ctx.secrets[k] = v;
        }
      }
    }

    // GITHUB_TOKEN is available as both a secret and an env var in real Actions.
    const token = this.ctx.secrets["GITHUB_TOKEN"];
    if (token && this.ctx.env["GITHUB_TOKEN"] === undefined) {
      this.ctx.env["GITHUB_TOKEN"] = token;
    }

    const cwd = Deno.cwd();
    this.ctx.cacheDir = join(cwd, ".cache");
    this.ctx.tempDir = join(cwd, ".tempdir");
    await Deno.mkdir(this.ctx.cacheDir, { recursive: true });
    await Deno.mkdir(this.ctx.tempDir, { recursive: true });

    this.ctx.workspace = await Deno.makeTempDir({ dir: this.ctx.tempDir, prefix: "workspace-" });
    this.ctx.toolCacheDir = await Deno.makeTempDir({ dir: this.ctx.tempDir, prefix: "toolcache-" });
    this.ctx.homeDir = await Deno.makeTempDir({ dir: this.ctx.tempDir, prefix: "home-" });
  }

  /** Execute a single job. */
  private async executeJob(_jobName: string, job: PolicyEngineWorkflowJob): Promise<void> {
    const steps = job.steps ?? [];
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      let stepName = `step_${i + 1}`;
      if (step.id) stepName = step.id;
      else if (step.name) stepName = step.name;

      if (step.if !== undefined && step.if !== null) {
        if (!this.evaluateCondition(step.if)) {
          Info("step %s skipped (if condition false)", stepName);
          continue;
        }
      }

      Info("starting step: %s", stepName);
      if (step.shell) this.ctx.shell = step.shell;

      const stepEnv = this.buildStepEnv(step);

      this.emit(`##[group]${stepName}`);

      let err: Error | null = null;
      try {
        if (step.uses) {
          await this.executeStepUses(step, stepEnv);
        } else if (step.run) {
          await this.executeStepRun(step, stepEnv);
        }
      } catch (e) {
        err = e as Error;
      }

      this.emit("##[endgroup]");

      if (err) {
        LogError("step %s failed: %v", stepName, err);
        this.emit(`##[error]step ${stepName} failed: ${err.message}`);
        throw new Error(`step ${stepName} failed: ${err.message}`);
      }
      Info("step %s completed", stepName);
    }
  }

  /** Append a marker line to both the snapshot buffer and the live task stream. */
  private emit(line: string): void {
    this.ctx.consoleOutput.push(line);
    if (this.task) this.task.appendConsoleOutput(line);
  }

  /**
   * Evaluate an `if` condition. Booleans/numbers are handled directly; string
   * conditions without ${{ }} are wrapped before evaluation. Unresolved
   * expressions fail closed (return false via throw), matching GitHub Actions.
   */
  evaluateCondition(condition: unknown): boolean {
    if (typeof condition === "boolean") return condition;
    if (typeof condition === "number") return condition !== 0;
    if (typeof condition === "string") {
      if (condition === "") return true;
      const trimmed = condition.trim().toLowerCase();
      if (trimmed === "true" || trimmed === "1") return true;
      if (trimmed === "false" || trimmed === "0") return false;

      let exprStr = condition;
      if (!exprStr.includes("${{")) exprStr = "${{ " + exprStr + " }}";
      let evaluated = this.evaluateExpression(exprStr);
      if (evaluated.includes("${{")) {
        throw new Error(`could not evaluate expression ${JSON.stringify(condition)}`);
      }
      evaluated = evaluated.trim().toLowerCase();
      if (evaluated === "__github_actions_always__") return true;
      if (
        evaluated === "false" || evaluated === "0" || evaluated === "" ||
        evaluated === "null" || evaluated === "undefined"
      ) {
        return false;
      }
      return true;
    }
    return true;
  }

  /** Build the environment map for a step. */
  buildStepEnv(step: PolicyEngineWorkflowJobStep): Record<string, string> {
    const env: Record<string, string> = {};

    for (const [k, v] of Object.entries(this.ctx.env)) {
      env[k] = String(v);
    }
    for (const [k, v] of Object.entries(step.env ?? {})) {
      env[k] = this.evaluateExpression(String(v));
    }
    for (const [k, v] of Object.entries(step.with ?? {})) {
      env["INPUT_" + k.toUpperCase()] = this.evaluateExpression(String(v));
    }

    env["GITHUB_WORKSPACE"] = this.ctx.workspace;
    env["RUNNER_TEMP"] = this.ctx.tempDir;
    env["RUNNER_TOOL_CACHE"] = this.ctx.toolCacheDir;
    env["AGENT_TOOLSDIRECTORY"] = this.ctx.toolCacheDir;
    env["HOME"] = this.ctx.homeDir;

    return env;
  }

  /** Evaluate all ${{ ... }} occurrences in a string. */
  evaluateExpression(expr: string): string {
    if (!expr.includes("${{")) return expr;
    return expr.replace(/\$\{\{\s*([\s\S]+?)\s*\}\}/g, (_m, inner: string) => {
      return this.evaluateInnerExpression(inner.trim());
    });
  }

  /** Evaluate a single expression (content between ${{ and }}) using Deno. */
  private evaluateInnerExpression(inner: string): string {
    try {
      return this.evaluateUsingJavaScript(inner);
    } catch {
      // Fall back to simple property-path resolution.
      const data: Record<string, unknown> = {
        github: this.buildGitHubContext(),
        steps: this.ctx.outputs,
        inputs: this.ctx.inputs,
        env: this.ctx.env,
      };
      const value = resolvePropertyPath(inner, data);
      if (value !== undefined && value !== null) return String(value);
      return "${{ " + inner + " }}";
    }
  }

  /**
   * Evaluate an expression by constructing a JS file with the github, runner,
   * steps, and inputs contexts and running it with Deno.
   */
  private evaluateUsingJavaScript(codeBlock: string): string {
    const githubCtx = this.buildGitHubContext();
    const stepsCtx = convertBoolStrings(this.ctx.outputs);
    const inputsCtx = this.ctx.inputs;
    const runnerCtx = { debug: 1 };

    const transformed = transformPropertyAccessors(codeBlock);

    const jsCode = `function always() { return "__GITHUB_ACTIONS_ALWAYS__"; }
const github = ${JSON.stringify(githubCtx)};
const runner = ${JSON.stringify(runnerCtx)};
const steps = ${JSON.stringify(stepsCtx)};
const inputs = ${JSON.stringify(inputsCtx)};
const result = (${transformed});
console.log(result)
`;
    Trace("evaluateUsingJavaScript(%s): %s", codeBlock, jsCode);

    const jsPath = Deno.makeTempFileSync({ dir: this.ctx.tempDir || undefined, suffix: ".js" });
    try {
      Deno.writeTextFileSync(jsPath, jsCode);
      const cmd = new Deno.Command(this.denoPath, {
        args: denoRunArgs("--no-prompt", jsPath),
        cwd: this.ctx.workspace || undefined,
        stdin: "null",
        stdout: "piped",
        stderr: "piped",
      });
      const { code, stdout, stderr } = cmd.outputSync();
      if (code !== 0) {
        throw new Error(`deno evaluation failed: ${new TextDecoder().decode(stderr)}`);
      }
      return new TextDecoder().decode(stdout).trim();
    } finally {
      try {
        Deno.removeSync(jsPath);
      } catch {
        // ignore
      }
    }
  }

  /** Build the github context for expression evaluation. */
  buildGitHubContext(): Record<string, unknown> {
    const ctx: Record<string, unknown> = {};
    const envMappings: Record<string, string> = {
      actor: "GITHUB_ACTOR",
      actor_id: "GITHUB_ACTOR_ID",
      repository: "GITHUB_REPOSITORY",
      api: "GITHUB_API",
      token: "GITHUB_TOKEN",
    };
    for (const [key, envVar] of Object.entries(envMappings)) {
      if (this.ctx.env[envVar] !== undefined) ctx[key] = this.ctx.env[envVar];
    }
    ctx["event"] = { inputs: this.ctx.inputs };
    return ctx;
  }

  /** Execute a step that uses an action. */
  private async executeStepUses(
    step: PolicyEngineWorkflowJobStep,
    env: Record<string, string>,
  ): Promise<void> {
    const uses = step.uses!;
    let actionPath = "";

    if (uses.startsWith("./") || uses.startsWith("/")) {
      actionPath = uses.startsWith("/") ? uses : join(this.ctx.workspace, uses);
      if (!(await exists(actionPath))) {
        throw new Error(`local action path does not exist: ${actionPath}`);
      }
      Debug("action resolved from local path: %s", actionPath);
    } else if (uses.includes("@")) {
      const [orgRepo, version] = splitN(uses, "@", 2);

      let repoActionsDir = env["ACTIONS_DIR"];
      if (!repoActionsDir) repoActionsDir = join(this.ctx.workspace, ".tangled", "actions");
      const repoLocal = join(repoActionsDir, orgRepo);
      if (await exists(repoLocal)) {
        actionPath = repoLocal;
        Debug("action %s resolved from repo-supplied dir: %s", orgRepo, actionPath);
      }

      if (!actionPath) {
        const bundledDir = Deno.env.get("BUNDLED_ACTIONS_DIR");
        if (bundledDir) {
          const bundledPath = join(bundledDir, orgRepo);
          if (await exists(bundledPath)) {
            actionPath = bundledPath;
            Debug("action %s resolved from bundled dir: %s", orgRepo, actionPath);
          }
        }
      }

      if (!actionPath) {
        Debug("downloading action %s@%s from GitHub", orgRepo, version);
        actionPath = await this.downloadAction(orgRepo, version);
        Debug("action %s downloaded to: %s", orgRepo, actionPath);
      }
    } else {
      throw new Error(
        `unsupported uses format (expected org/repo@version or ./path): ${uses}`,
      );
    }

    let actionYamlPath = join(actionPath, "action.yml");
    if (!(await exists(actionYamlPath))) actionYamlPath = join(actionPath, "action.yaml");
    const actionDef = parseYaml(await Deno.readTextFile(actionYamlPath)) as ActionDef;

    // Add default inputs.
    for (const [inputName, inputDef] of Object.entries(actionDef.inputs ?? {})) {
      const envKey = "INPUT_" + inputName.toUpperCase();
      if (env[envKey] === undefined && inputDef.default) {
        env[envKey] = this.evaluateExpression(inputDef.default);
      }
    }

    env["GITHUB_ACTION_PATH"] = actionPath;

    const using = actionDef.runs?.using ?? "";
    Debug("executing action type: %s", using);
    if (using.startsWith("node")) {
      await this.executeNodeAction(actionPath, actionDef.runs?.main ?? "", env, step.id);
    } else if (using === "composite") {
      await this.executeCompositeAction(actionDef.runs?.steps ?? [], env);
    } else {
      throw new Error(`unsupported action type: ${using}`);
    }
  }

  /** Download a GitHub Action to the cache directory and return its path. */
  private async downloadAction(orgRepo: string, version: string): Promise<string> {
    const extractedPath = join(this.ctx.cacheDir, orgRepo, "extracted");
    if (await exists(extractedPath)) return extractedPath;

    const downloadDir = join(this.ctx.cacheDir, orgRepo);
    await Deno.mkdir(downloadDir, { recursive: true });

    const urls = [
      `https://github.com/${orgRepo}/archive/refs/tags/${version}.zip`,
      `https://github.com/${orgRepo}/archive/${version}.zip`,
      `https://github.com/${orgRepo}/archive/refs/heads/${version}.zip`,
    ];

    let downloadErr: Error | null = null;
    for (const downloadURL of urls) {
      const compressedPath = join(downloadDir, "compressed.zip");
      try {
        const headers: HeadersInit = {};
        const token = this.ctx.secrets["GITHUB_TOKEN"];
        if (token) headers["Authorization"] = "Bearer " + token;

        const resp = await fetch(downloadURL, { headers });
        if (!resp.ok) {
          downloadErr = new Error(`download failed with status: ${resp.status}`);
          continue;
        }
        await Deno.writeFile(compressedPath, new Uint8Array(await resp.arrayBuffer()));

        const extractedTmpPath = join(downloadDir, "extracted_tmp");
        await unzip(compressedPath, extractedTmpPath);

        const entries: Deno.DirEntry[] = [];
        for await (const e of Deno.readDir(extractedTmpPath)) entries.push(e);
        if (entries.length === 0) {
          downloadErr = new Error("failed to find extracted directory");
          continue;
        }

        const srcDir = join(extractedTmpPath, entries[0].name);
        await Deno.rename(srcDir, extractedPath);
        await this.removeAll(extractedTmpPath);
        try {
          await Deno.remove(compressedPath);
        } catch { /* ignore */ }
        return extractedPath;
      } catch (e) {
        downloadErr = e as Error;
      }
    }
    throw new Error(`failed to download action from any URL: ${downloadErr?.message}`);
  }

  /** Execute a Node.js action using Deno's Node compatibility layer. */
  private async executeNodeAction(
    actionPath: string,
    main: string,
    env: Record<string, string>,
    stepID: string | undefined,
  ): Promise<void> {
    const ghFiles: Array<[string, string]> = [
      ["GITHUB_OUTPUT", "node-output-"],
      ["GITHUB_ENV", "node-env-"],
      ["GITHUB_PATH", "node-path-"],
      ["GITHUB_STATE", "node-state-"],
    ];
    const cleanup: string[] = [];
    for (const [envKey, prefix] of ghFiles) {
      const f = await Deno.makeTempFile({ dir: this.ctx.tempDir, prefix, suffix: ".txt" });
      env[envKey] = f;
      cleanup.push(f);
    }

    try {
      // Many actions are ncc-bundled CommonJS. Deno defaults a type-less
      // package.json to ESM, leaving __dirname undefined — force commonjs.
      const actionPkgPath = join(actionPath, "package.json");
      try {
        const pkg = JSON.parse(await Deno.readTextFile(actionPkgPath));
        if (pkg.type === undefined) {
          pkg.type = "commonjs";
          await Deno.writeTextFile(actionPkgPath, JSON.stringify(pkg));
        }
      } catch {
        await Deno.writeTextFile(actionPkgPath, `{"type":"commonjs"}`);
      }

      const mainPath = join(actionPath, main);
      const cmd = new Deno.Command(this.denoPath, {
        args: denoRunArgs("--allow-all", "--no-prompt", mainPath),
        cwd: this.ctx.workspace,
        env: env,
        stdout: "piped",
        stderr: "piped",
      });
      const output = await this.runAndStreamOutput(cmd);
      this.ctx.consoleOutput.push(output);

      // Parse outputs from GITHUB_OUTPUT.
      if (stepID) {
        const content = await readTextOrEmpty(env["GITHUB_OUTPUT"]);
        if (content) {
          const outputs = parseGitHubActionsOutputs(content);
          if (!this.ctx.outputs[stepID]) this.ctx.outputs[stepID] = {};
          this.ctx.outputs[stepID]["outputs"] = outputs;
        }
      }

      // Apply env updates from GITHUB_ENV.
      const envContent = await readTextOrEmpty(env["GITHUB_ENV"]);
      if (envContent) {
        for (const [k, v] of Object.entries(parseGitHubActionsOutputs(envContent))) {
          this.ctx.env[k] = v;
        }
      }
    } finally {
      for (const f of cleanup) {
        try {
          await Deno.remove(f);
        } catch { /* ignore */ }
      }
    }
  }

  /** Execute a composite action's run steps. */
  private async executeCompositeAction(
    steps: ActionStep[],
    env: Record<string, string>,
  ): Promise<void> {
    for (const step of steps) {
      if (!step.run) continue;
      const shell = step.shell || this.ctx.shell;
      const stepEnv = { ...env };
      for (const [k, v] of Object.entries(step.env ?? {})) {
        stepEnv[k] = this.evaluateExpression(v);
      }
      await this.runShellCommand(step.run, shell, stepEnv);
    }
  }

  /** Execute a `run` step. */
  private async executeStepRun(
    step: PolicyEngineWorkflowJobStep,
    env: Record<string, string>,
  ): Promise<void> {
    const runScript = this.evaluateExpression(step.run!);

    const outputFile = await Deno.makeTempFile({
      dir: this.ctx.tempDir,
      prefix: "output-",
      suffix: ".txt",
    });
    const envFile = await Deno.makeTempFile({
      dir: this.ctx.tempDir,
      prefix: "env-",
      suffix: ".txt",
    });
    const pathFile = await Deno.makeTempFile({
      dir: this.ctx.tempDir,
      prefix: "path-",
      suffix: ".txt",
    });

    env["GITHUB_OUTPUT"] = outputFile;
    env["GITHUB_ENV"] = envFile;
    env["GITHUB_PATH"] = pathFile;

    const shell = step.shell || this.ctx.shell;

    try {
      await this.runShellCommand(runScript, shell, env);

      if (step.id) {
        const outputs = parseGitHubActionsOutputs(await readTextOrEmpty(outputFile));
        if (!this.ctx.outputs[step.id]) this.ctx.outputs[step.id] = {};
        this.ctx.outputs[step.id]["outputs"] = outputs;
      }

      for (
        const [k, v] of Object.entries(parseGitHubActionsOutputs(await readTextOrEmpty(envFile)))
      ) {
        this.ctx.env[k] = v;
      }
    } finally {
      for (const f of [outputFile, envFile, pathFile]) {
        try {
          await Deno.remove(f);
        } catch { /* ignore */ }
      }
    }
  }

  /** Run a shell command, writing the script to a temp file. */
  private async runShellCommand(
    script: string,
    shell: string,
    env: Record<string, string>,
  ): Promise<void> {
    Debug("running shell command: shell=%s", shell);
    Trace("script content:\n%s", script);

    const scriptPath = await Deno.makeTempFile({ dir: this.ctx.tempDir, prefix: "script-" });
    try {
      await Deno.writeTextFile(scriptPath, script);

      let shellParts = shell.trim().split(/\s+/).filter((p) => p.length > 0);
      if (shellParts.length === 0) shellParts = ["bash", "-xe"];

      // Replace {0} placeholder with the script path.
      const args: string[] = [];
      let found = false;
      for (const part of shellParts) {
        if (part.includes("{0}")) {
          args.push(part.replace("{0}", scriptPath));
          found = true;
        } else {
          args.push(part);
        }
      }
      if (!found) args.push(scriptPath);

      const cmd = new Deno.Command(args[0], {
        args: args.slice(1),
        cwd: this.ctx.workspace,
        env: env,
        stdout: "piped",
        stderr: "piped",
      });
      const output = await this.runAndStreamOutput(cmd);
      this.ctx.consoleOutput.push(output);
      this.parseAnnotations(output);
    } finally {
      try {
        await Deno.remove(scriptPath);
      } catch { /* ignore */ }
    }
  }

  /** Run a command, capturing merged stdout/stderr and streaming lines to the task. */
  private async runAndStreamOutput(cmd: Deno.Command): Promise<string> {
    const child = cmd.spawn();
    const decoder = new TextDecoder();
    let output = "";

    const pump = async (stream: ReadableStream<Uint8Array>) => {
      for await (const chunk of stream) {
        const text = decoder.decode(chunk, { stream: true });
        output += text;
        for (const line of text.split("\n")) {
          if (line !== "") {
            Trace("| %s", line);
            if (this.task) this.task.appendConsoleOutput(line);
          }
        }
      }
    };

    await Promise.all([pump(child.stdout), pump(child.stderr)]);
    const status = await child.status;
    if (!status.success) {
      throw new Error(`command exited with code ${status.code}`);
    }
    return output;
  }

  /** Parse GitHub Actions workflow command annotations from output. */
  private parseAnnotations(output: string): void {
    for (let line of output.split("\n")) {
      if (!line.startsWith("::")) continue;
      line = line.slice(2);
      const idx = line.indexOf("::");
      const levelAndParams = idx >= 0 ? line.slice(0, idx) : line;
      const message = idx >= 0 ? line.slice(idx + 2) : "";

      const spaceIdx = levelAndParams.indexOf(" ");
      const level = spaceIdx >= 0 ? levelAndParams.slice(0, spaceIdx) : levelAndParams;
      if (level !== "error" && level !== "warning" && level !== "notice") continue;

      const annotation: GitHubCheckSuiteAnnotation = {
        annotation_level: level,
        message,
        title: message,
        raw_details: "::" + line,
      };

      if (spaceIdx >= 0) {
        const params = new URLSearchParams(levelAndParams.slice(spaceIdx + 1).replace(/,/g, "&"));
        const file = params.get("file");
        if (file) annotation.path = file;
        const path = params.get("path");
        if (path) annotation.path = path;
        const title = params.get("title");
        if (title) annotation.title = title;
        const lineNum = params.get("line");
        if (lineNum && !isNaN(Number(lineNum))) {
          annotation.start_line = Number(lineNum);
          annotation.end_line = Number(lineNum);
        }
        const endLine = params.get("endLine");
        if (endLine && !isNaN(Number(endLine))) annotation.end_line = Number(endLine);
      }

      (this.ctx.annotations[level] ??= []).push(annotation);
    }
  }

  private createSuccessStatus(): PolicyEngineStatus {
    return {
      status: StatusComplete,
      detail: {
        id: "",
        exit_status: "success",
        outputs: {},
        annotations: { ...this.ctx.annotations },
      },
      console_output: this.ctx.consoleOutput.join("\n"),
    };
  }

  private createErrorStatus(err: Error): PolicyEngineStatus {
    const annotations: Record<string, unknown> = { ...this.ctx.annotations };
    annotations["error"] = [err.message];
    return {
      status: StatusComplete,
      detail: {
        id: "",
        exit_status: "failure",
        outputs: {},
        annotations,
      },
      console_output: this.ctx.consoleOutput.join("\n"),
    };
  }
}

// --- module-level helpers ---

/**
 * Recursively convert string "true"/"false" into real booleans so that
 * comparisons like `steps.x.outputs.y === true` behave as expected.
 */
export function convertBoolStrings(value: unknown): unknown {
  if (value === "true") return true;
  if (value === "false") return false;
  if (Array.isArray(value)) return value.map(convertBoolStrings);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = convertBoolStrings(v);
    return out;
  }
  return value;
}

/** Convert dot notation to bracket notation, skipping string literals. */
export function transformPropertyAccessors(jsCode: string): string {
  let result = "";
  let i = 0;
  while (i < jsCode.length) {
    const ch = jsCode[i];
    if (ch === '"' || ch === "'") {
      const quote = ch;
      result += ch;
      i++;
      while (i < jsCode.length) {
        result += jsCode[i];
        if (jsCode[i] === quote) {
          i++;
          break;
        }
        i++;
      }
    } else if (ch === ".") {
      result += "['";
      i++;
      const start = i;
      while (i < jsCode.length && /[A-Za-z0-9_\-]/.test(jsCode[i])) i++;
      result += jsCode.slice(start, i);
      result += "']";
    } else {
      result += ch;
      i++;
    }
  }
  return result;
}

/** Resolve a property path like "github.actor" from data. */
export function resolvePropertyPath(path: string, data: Record<string, unknown>): unknown {
  let current: unknown = data;
  for (const part of path.split(".")) {
    if (current && typeof current === "object" && !Array.isArray(current)) {
      current = (current as Record<string, unknown>)[part];
      if (current === undefined) return undefined;
    } else {
      return undefined;
    }
  }
  return current;
}

/** Parse GitHub Actions output format (key=value and key<<delimiter blocks). */
export function parseGitHubActionsOutputs(content: string): Record<string, string> {
  const outputs: Record<string, string> = {};
  let currentKey = "";
  let currentDelimiter = "";
  let currentValue = "";

  for (const line of content.split("\n")) {
    if (currentDelimiter !== "") {
      if (line.startsWith(currentDelimiter)) {
        outputs[currentKey] = currentValue.replace(/\n$/, "");
        currentKey = "";
        currentDelimiter = "";
        currentValue = "";
      } else {
        currentValue += line + "\n";
      }
    } else if (line.includes("<<") && currentKey === "") {
      const [k, d] = splitN(line, "<<", 2);
      currentKey = k.trim();
      currentDelimiter = d.trim();
    } else if (line.includes("=") && currentKey === "") {
      const [k, v] = splitN(line, "=", 2);
      outputs[k.trim()] = v ?? "";
    }
  }
  return outputs;
}

/** Build the argument list for a `deno run` invocation, quieting downloads. */
export function denoRunArgs(...args: string[]): string[] {
  const result = ["run"];
  if (Deno.env.get("DEBUG_DENO_PACKAGES") !== "1") result.push("--quiet");
  return [...result, ...args];
}

/** Split a string on `sep` into at most `n` parts (like Go's strings.SplitN). */
function splitN(s: string, sep: string, n: number): string[] {
  const parts = s.split(sep);
  if (parts.length <= n) return parts;
  return [...parts.slice(0, n - 1), parts.slice(n - 1).join(sep)];
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

async function readTextOrEmpty(path: string | undefined): Promise<string> {
  if (!path) return "";
  try {
    return await Deno.readTextFile(path);
  } catch {
    return "";
  }
}

async function unzip(src: string, dest: string): Promise<void> {
  const cmd = new Deno.Command("unzip", { args: ["-q", "-o", src, "-d", dest] });
  const { success, code } = await cmd.output();
  if (!success) throw new Error(`unzip failed with code ${code}`);
}
