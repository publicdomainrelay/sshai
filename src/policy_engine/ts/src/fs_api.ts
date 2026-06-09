// Optional in-process HTTP filesystem API server.
//
// When enabled (--fs-api / POLICY_ENGINE_FS_API=1), the engine binds a Hono
// server on a random local port and exposes simple file-system primitives over
// HTTP.  The bound URL is injected as POLICY_ENGINE_FS_API_URL into every
// action worker's environment so that net-only actions (which cannot touch the
// real FS directly) can delegate writes/reads to the host via fetch().
//
// All paths are resolved relative to the supplied root directory and are
// validated to stay within it — traversal attacks are rejected with 403.

import { Hono } from "hono";
import { join, normalize, resolve } from "@std/path";

function safeJoin(root: string, rel: string): string | null {
  const full = normalize(resolve(root, rel.replace(/^\/+/, "")));
  return full.startsWith(root) ? full : null;
}

export interface FsApiServer {
  url: string;
  close(): Promise<void>;
}

export async function startFsApiServer(root: string): Promise<FsApiServer> {
  const app = new Hono();

  // GET /file?path=<rel>  → file bytes
  app.get("/file", async (c) => {
    const rel = c.req.query("path") ?? "";
    const full = safeJoin(root, rel);
    if (!full) return c.text("forbidden", 403);
    try {
      const bytes = await Deno.readFile(full);
      return new Response(bytes, {
        headers: { "content-type": "application/octet-stream" },
      });
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) return c.text("not found", 404);
      return c.text(String(e), 500);
    }
  });

  // PUT /file?path=<rel>  body → write file (creates parents)
  app.put("/file", async (c) => {
    const rel = c.req.query("path") ?? "";
    const full = safeJoin(root, rel);
    if (!full) return c.text("forbidden", 403);
    const parent = full.substring(0, full.lastIndexOf("/"));
    if (parent) await Deno.mkdir(parent, { recursive: true });
    const body = new Uint8Array(await c.req.arrayBuffer());
    await Deno.writeFile(full, body);
    return c.text("ok");
  });

  // POST /mkdir?path=<rel>  → create directory (recursive)
  app.post("/mkdir", async (c) => {
    const rel = c.req.query("path") ?? "";
    const full = safeJoin(root, rel);
    if (!full) return c.text("forbidden", 403);
    await Deno.mkdir(full, { recursive: true });
    return c.text("ok");
  });

  // GET /ls?path=<rel>  → JSON array of entry names with type
  app.get("/ls", async (c) => {
    const rel = c.req.query("path") ?? "";
    const full = safeJoin(root, rel || ".");
    if (!full) return c.text("forbidden", 403);
    try {
      const entries: { name: string; type: "file" | "dir" }[] = [];
      for await (const entry of Deno.readDir(full)) {
        entries.push({ name: entry.name, type: entry.isDirectory ? "dir" : "file" });
      }
      return c.json(entries);
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) return c.text("not found", 404);
      return c.text(String(e), 500);
    }
  });

  // Bind to a random local port.
  const ac = new AbortController();
  let resolveReady!: (port: number) => void;
  const readyPromise = new Promise<number>((r) => (resolveReady = r));

  const server = Deno.serve(
    {
      port: 0,
      hostname: "127.0.0.1",
      signal: ac.signal,
      onListen: ({ port }) => resolveReady(port),
    },
    app.fetch,
  );

  const port = await readyPromise;
  const url = `http://127.0.0.1:${port}`;

  return {
    url,
    close: async () => {
      ac.abort();
      await server.finished;
    },
  };
}
