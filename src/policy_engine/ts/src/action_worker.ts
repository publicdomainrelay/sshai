// Native, sandboxed runner for JavaScript/TypeScript GitHub Actions.
//
// Instead of shelling out to `deno run --allow-all <action>` (full, unsandboxed
// process execution), this runs a Deno-native / ESM action's source inside an
// in-process Web Worker whose Deno permissions are locked down — the same
// mechanism used for expression evaluation. The action receives network access
// only (in net-only mode); it cannot read or write the real filesystem or spawn
// subprocesses. Action inputs are injected via a `Deno.env` shim (so no real
// environment access is needed), and writes to the GITHUB_OUTPUT / GITHUB_ENV /
// GITHUB_PATH / GITHUB_STATE command files are captured into an in-memory
// virtual filesystem and returned to the host.
//
// Requires the `--unstable-worker-options` flag (baked into the CLI shebang and
// the deno tasks).

/** Result of running an action in the sandboxed worker. */
export interface ActionRunResult {
  /** Process-style exit code (0 = success). */
  code: number;
  /** Captured contents of the GITHUB_OUTPUT command file. */
  output: string;
  /** Captured contents of the GITHUB_ENV command file. */
  env: string;
}

// Sentinel "paths" used as the GITHUB_* command-file locations. The action
// writes to these via Deno.writeTextFile; the shim intercepts them into an
// in-memory map rather than touching the real filesystem.
const SENTINELS = {
  GITHUB_OUTPUT: "pe-virtual:GITHUB_OUTPUT",
  GITHUB_ENV: "pe-virtual:GITHUB_ENV",
  GITHUB_PATH: "pe-virtual:GITHUB_PATH",
  GITHUB_STATE: "pe-virtual:GITHUB_STATE",
} as const;

/** Build the prelude injected ahead of the action source inside the worker. */
function buildShim(env: Record<string, string>): string {
  return `
const __pe_env = ${JSON.stringify(env)};
const __pe_vfs = {};
const __pe_ghPaths = new Set(
  [__pe_env.GITHUB_OUTPUT, __pe_env.GITHUB_ENV, __pe_env.GITHUB_PATH, __pe_env.GITHUB_STATE]
    .filter((v) => typeof v === "string" && v.length > 0),
);

// Inject inputs through a Deno.env shim so the action needs no env permission
// and never sees the host's real environment.
Object.defineProperty(Deno, "env", {
  configurable: true,
  value: {
    get: (k) => __pe_env[k],
    has: (k) => Object.prototype.hasOwnProperty.call(__pe_env, k),
    set: () => {},
    delete: () => {},
    toObject: () => ({ ...__pe_env }),
  },
});

// Capture writes to the GITHUB_* command files; delegate everything else to the
// real implementation, which the permission sandbox will deny.
const __pe_origWriteText = Deno.writeTextFile.bind(Deno);
const __pe_origWriteTextSync = Deno.writeTextFileSync.bind(Deno);
const __pe_origReadText = Deno.readTextFile.bind(Deno);
const __pe_origReadTextSync = Deno.readTextFileSync.bind(Deno);
function __pe_append(k, data, opts) {
  __pe_vfs[k] = (opts && opts.append ? (__pe_vfs[k] || "") : "") + data;
}
Deno.writeTextFile = (p, data, opts) => {
  const k = String(p);
  if (__pe_ghPaths.has(k)) { __pe_append(k, data, opts); return Promise.resolve(); }
  return __pe_origWriteText(p, data, opts);
};
Deno.writeTextFileSync = (p, data, opts) => {
  const k = String(p);
  if (__pe_ghPaths.has(k)) { __pe_append(k, data, opts); return; }
  return __pe_origWriteTextSync(p, data, opts);
};
Deno.readTextFile = (p, opts) => {
  const k = String(p);
  if (__pe_ghPaths.has(k)) return Promise.resolve(__pe_vfs[k] || "");
  return __pe_origReadText(p, opts);
};
Deno.readTextFileSync = (p) => {
  const k = String(p);
  if (__pe_ghPaths.has(k)) return __pe_vfs[k] || "";
  return __pe_origReadTextSync(p);
};

// Contain Deno.exit so the action cannot terminate the host process.
Deno.exit = (code = 0) => {
  self.postMessage({ k: "exit", code: typeof code === "number" ? code : 0, vfs: __pe_vfs });
  self.close();
};

// Stream console output back to the host line-by-line.
for (const m of ["log", "error", "warn", "info", "debug"]) {
  console[m] = (...args) =>
    self.postMessage({ k: "log", line: args.map((a) => typeof a === "string" ? a : Deno.inspect(a)).join(" ") });
}

self.addEventListener("error", (e) => {
  e.preventDefault();
  self.postMessage({ k: "log", line: String(e.message) });
  self.postMessage({ k: "exit", code: 1, vfs: __pe_vfs });
  self.close();
});
self.addEventListener("unhandledrejection", (e) => {
  e.preventDefault();
  self.postMessage({ k: "log", line: String(e.reason && e.reason.stack || e.reason) });
  self.postMessage({ k: "exit", code: 1, vfs: __pe_vfs });
  self.close();
});
`;
}

// Footer appended after the action source; runs only if the action neither
// called Deno.exit nor threw, signalling clean completion.
const FOOTER = `
;self.postMessage({ k: "exit", code: 0, vfs: __pe_vfs });
`;

/**
 * Run a JS/TS action's source inside the permission-restricted worker.
 * The provided env (including INPUT_* values) is injected; GITHUB_OUTPUT and
 * GITHUB_ENV command-file writes are captured and returned.
 */
export function runActionInWorker(opts: {
  source: string;
  env: Record<string, string>;
  allowNet: boolean;
  onLine?: (line: string) => void;
}): Promise<ActionRunResult> {
  // Point the GITHUB_* command files at in-memory sentinels.
  const env: Record<string, string> = {
    ...opts.env,
    GITHUB_OUTPUT: SENTINELS.GITHUB_OUTPUT,
    GITHUB_ENV: SENTINELS.GITHUB_ENV,
    GITHUB_PATH: SENTINELS.GITHUB_PATH,
    GITHUB_STATE: SENTINELS.GITHUB_STATE,
  };

  // @ts-nocheck disables type-checking for the worker module: action code is
  // untrusted and must run as-is (like `deno run`), never gated on type errors.
  const moduleSource = "// @ts-nocheck\n" + buildShim(env) + "\n" + opts.source + "\n" + FOOTER;
  const blobUrl = URL.createObjectURL(
    new Blob([moduleSource], { type: "text/typescript" }),
  );
  const worker = new Worker(blobUrl, {
    type: "module",
    deno: {
      permissions: {
        net: opts.allowNet ? true : false,
        read: false,
        write: false,
        run: false,
        env: false,
        sys: false,
        ffi: false,
        import: false,
      },
    },
  });

  return new Promise<ActionRunResult>((resolve, reject) => {
    worker.onmessage = (e: MessageEvent) => {
      const d = e.data as {
        k?: string;
        line?: string;
        code?: number;
        vfs?: Record<string, string>;
      };
      if (d.k === "log") {
        opts.onLine?.(d.line ?? "");
      } else if (d.k === "exit") {
        const vfs = d.vfs ?? {};
        worker.terminate();
        URL.revokeObjectURL(blobUrl);
        resolve({
          code: d.code ?? 0,
          output: vfs[SENTINELS.GITHUB_OUTPUT] ?? "",
          env: vfs[SENTINELS.GITHUB_ENV] ?? "",
        });
      }
    };
    worker.onerror = (e: ErrorEvent) => {
      e.preventDefault();
      worker.terminate();
      URL.revokeObjectURL(blobUrl);
      reject(new Error(`action worker error: ${e.message}`));
    };
  });
}
