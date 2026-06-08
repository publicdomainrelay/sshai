// Native, sandboxed JavaScript expression evaluator.
//
// GitHub Actions ${{ }} expressions are evaluated as JavaScript. Rather than
// shelling out to a `deno run` subprocess (which spawns a process and touches
// the filesystem), this evaluator runs the expression inside an in-process Web
// Worker whose Deno permissions are locked down. Even though the host process
// may run with broad permissions, the worker can only do what its permission
// set allows — by default nothing (no filesystem, no network, no subprocess),
// or, in net-only mode, network access and nothing else.
//
// Requires the `--unstable-worker-options` flag so per-worker permissions can
// be set; this is baked into the CLI shebang and the deno tasks.

import { Trace } from "./logger.ts";

/** Source of the worker that evaluates expressions in isolation. */
const WORKER_SOURCE = `
self.onmessage = (e) => {
  const { id, code } = e.data;
  try {
    // Indirect eval runs in global scope; the host builds a self-contained
    // IIFE in \`code\` that defines its own contexts and returns a value.
    const result = (0, eval)(code);
    self.postMessage({ id, ok: true, result: result === undefined ? "undefined" : String(result) });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message ? err.message : err) });
  }
};
`;

interface Pending {
  resolve: (result: string) => void;
  reject: (err: Error) => void;
}

export interface EvalResult {
  ok: boolean;
  result: string;
}

/**
 * Evaluates JavaScript expressions in a permission-restricted Web Worker.
 * A single worker is created lazily and reused for all evaluations; call
 * close() to terminate it.
 */
export class ExpressionEvaluator {
  private allowNet: boolean;
  private worker: Worker | null = null;
  private blobUrl: string | null = null;
  private nextId = 1;
  private pending = new Map<number, Pending>();

  constructor(opts: { allowNet?: boolean } = {}) {
    this.allowNet = opts.allowNet ?? false;
  }

  /** Permissions granted to the worker: never read/write/run; net is opt-in. */
  private permissions(): Deno.PermissionOptionsObject {
    return {
      net: this.allowNet ? true : false,
      read: false,
      write: false,
      run: false,
      env: false,
      sys: false,
      ffi: false,
      import: false,
    };
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;

    this.blobUrl = URL.createObjectURL(
      new Blob([WORKER_SOURCE], { type: "text/javascript" }),
    );
    const worker = new Worker(this.blobUrl, {
      type: "module",
      deno: { permissions: this.permissions() },
    });

    worker.onmessage = (e: MessageEvent) => {
      const { id, ok, result, error } = e.data as {
        id: number;
        ok: boolean;
        result?: string;
        error?: string;
      };
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      if (ok) p.resolve(result ?? "");
      else p.reject(new Error(error ?? "evaluation failed"));
    };

    worker.onerror = (e: ErrorEvent) => {
      // A worker-level error invalidates all in-flight evaluations. Reject
      // them and drop the worker so the next call rebuilds a fresh one.
      const err = new Error(`expression worker error: ${e.message}`);
      for (const [, p] of this.pending) p.reject(err);
      this.pending.clear();
      this.disposeWorker();
    };

    this.worker = worker;
    return worker;
  }

  /**
   * Evaluate a self-contained JavaScript expression (an IIFE string) and
   * return its result as a string. Rejects if the expression throws.
   */
  evaluate(code: string): Promise<string> {
    Trace("ExpressionEvaluator.evaluate: %s", code);
    const worker = this.ensureWorker();
    const id = this.nextId++;
    return new Promise<string>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      worker.postMessage({ id, code });
    });
  }

  private disposeWorker(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    if (this.blobUrl) {
      URL.revokeObjectURL(this.blobUrl);
      this.blobUrl = null;
    }
  }

  /** Terminate the worker and reject any outstanding evaluations. */
  close(): void {
    for (const [, p] of this.pending) p.reject(new Error("evaluator closed"));
    this.pending.clear();
    this.disposeWorker();
  }
}
