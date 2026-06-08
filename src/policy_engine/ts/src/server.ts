// Hono-based HTTP server for the policy engine — a TypeScript (Deno) port of
// ../../common/server.go. Exposes the request lifecycle, console output (plain
// and SSE), the GitHub webhook receiver, and health/rate-limit endpoints.

import { Hono } from "hono";
import { cors } from "hono/cors";
import { streamSSE } from "hono/streaming";
import {
  type GitHubWebhookEvent,
  type PolicyEngineComplete,
  type PolicyEngineRequest,
  type PolicyEngineStatus,
  StatusComplete,
  StatusInProgress,
  StatusInputValidationError,
  StatusSubmitted,
  StatusUnknown,
  type Task,
  TaskManager,
  validateRequest,
} from "./models.ts";
import { WorkflowExecutor } from "./workflow.ts";
import { Debug, Info, LogError } from "./logger.ts";

const DEFAULT_WEBHOOK_WORKFLOW = `
name: 'Webhook Workflow'
on:
  push:
    branches:
    - main

jobs:
  default:
    runs-on: self-hosted
    steps:
    - run: echo "Webhook received"
`;

/** Build the Hono app and its backing task manager. */
export function createApp(): { app: Hono; taskManager: TaskManager } {
  const taskManager = new TaskManager();
  const app = new Hono();

  app.use("*", cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  }));

  // Request logging.
  app.use("*", async (c, next) => {
    const start = Date.now();
    Debug("request: %s %s", c.req.method, c.req.path);
    await next();
    Debug("response: %s %s completed in %dms", c.req.method, c.req.path, Date.now() - start);
  });

  app.get("/health", (c) => c.json({ status: "ok" }));

  app.get("/rate_limit", (c) =>
    c.json({
      resources: {
        core: {
          limit: 5000,
          remaining: 4999,
          reset: Math.floor(Date.now() / 1000) + 3600,
        },
      },
    }));

  app.post("/request/create", async (c) => {
    let request: PolicyEngineRequest;
    try {
      request = await c.req.json();
    } catch (err) {
      return validationError(c, "Failed to parse request JSON", err as Error);
    }
    try {
      validateRequest(request);
    } catch (err) {
      return validationError(c, "Invalid request", err as Error);
    }

    const taskID = crypto.randomUUID();
    const task = taskManager.createTask(taskID);
    Info("task created: id=%s", taskID);

    executeWorkflowTask(taskManager, task, request); // fire and forget

    const response: PolicyEngineStatus = {
      status: StatusSubmitted,
      detail: { id: taskID },
    };
    return c.json(response);
  });

  app.get("/request/status/:id", (c) => {
    const requestID = c.req.param("id");
    const task = taskManager.getTask(requestID);
    if (!task) {
      return c.json({ status: StatusUnknown, detail: { id: requestID } });
    }

    let response: PolicyEngineStatus;
    switch (task.status) {
      case "PENDING":
        response = {
          status: StatusInProgress,
          detail: { id: requestID, status_updates: {} },
        };
        break;
      case "SUCCESS":
      case "FAILURE": {
        try {
          response = JSON.parse(task.result) as PolicyEngineStatus;
          if (response.detail && typeof response.detail === "object") {
            (response.detail as Record<string, unknown>)["id"] = requestID;
          }
        } catch {
          response = {
            status: StatusComplete,
            detail: {
              id: requestID,
              exit_status: task.status === "FAILURE" ? "failure" : "success",
            },
          };
        }
        break;
      }
      default:
        response = { status: StatusUnknown, detail: { id: requestID } };
    }
    return c.json(response);
  });

  app.get("/request/console_output/:id", (c) => {
    const requestID = c.req.param("id");
    const task = taskManager.getTask(requestID);
    if (!task) return c.text("Task not found", 404);

    if (task.status === "SUCCESS" || task.status === "FAILURE") {
      try {
        const result = JSON.parse(task.result) as PolicyEngineStatus;
        return c.text(result.console_output ?? "");
      } catch {
        return c.text(task.getConsoleOutput());
      }
    }
    return c.text(task.getConsoleOutput());
  });

  app.get("/request/console_output_stream/:id", (c) => {
    const requestID = c.req.param("id");
    const task = taskManager.getTask(requestID);
    if (!task) return c.text("Task not found", 404);

    return streamSSE(c, async (stream) => {
      // Send everything buffered so far.
      for (const line of [...task.consoleOutput]) {
        await stream.writeSSE({ data: line });
      }
      if (isDone(task)) {
        await stream.writeSSE({ event: "done", data: task.status });
        return;
      }

      // Subscribe to new lines.
      const queue: string[] = [];
      let notify: (() => void) | null = null;
      const unsubscribe = task.subscribe((line) => {
        queue.push(line);
        notify?.();
      });

      try {
        while (true) {
          while (queue.length > 0) {
            await stream.writeSSE({ data: queue.shift()! });
          }
          if (isDone(task)) {
            await stream.writeSSE({ event: "done", data: task.status });
            return;
          }
          // Wait for a new line or a 1s keepalive tick.
          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, 1000);
            notify = () => {
              clearTimeout(timer);
              resolve();
            };
          });
          notify = null;
          if (queue.length === 0) {
            await stream.writeSSE({ data: "", event: "keepalive" });
          }
        }
      } finally {
        unsubscribe();
      }
    });
  });

  app.post("/webhook/github", async (c) => {
    const eventType = c.req.header("X-GitHub-Event");
    const deliveryID = c.req.header("X-GitHub-Delivery");

    if (eventType !== "push" && eventType !== "pull_request") {
      return c.json({ message: "Event type not supported" });
    }

    let event: GitHubWebhookEvent;
    try {
      event = await c.req.json();
    } catch (err) {
      return validationError(c, "Failed to parse webhook event", err as Error);
    }

    const workflow = event.sender?.webhook_workflow || DEFAULT_WEBHOOK_WORKFLOW;
    const request: PolicyEngineRequest = {
      context: {
        config: {
          env: {
            GITHUB_ACTOR: event.sender?.login ?? "",
            GITHUB_REPOSITORY: event.repository?.full_name ?? "",
          },
        },
      },
      workflow,
    };

    const taskID = deliveryID || crypto.randomUUID();
    const task = taskManager.createTask(taskID);
    Info("webhook task created: id=%s", taskID);

    executeWorkflowTask(taskManager, task, request);

    return c.json({ status: StatusSubmitted, detail: { id: taskID } });
  });

  return { app, taskManager };
}

/** Execute a workflow as an async task, recording the result on the task. */
async function executeWorkflowTask(
  taskManager: TaskManager,
  task: Task,
  request: PolicyEngineRequest,
): Promise<void> {
  Debug("executing workflow task: id=%s", task.id);
  const executor = new WorkflowExecutor();
  executor.task = task;
  try {
    const status = await executor.executeWorkflow(request);
    const resultJSON = JSON.stringify(status);
    let taskStatus: "SUCCESS" | "FAILURE" = "SUCCESS";
    const detail = status.detail as PolicyEngineComplete | undefined;
    if (detail?.exit_status === "failure") taskStatus = "FAILURE";
    Info("task %s completed: status=%s", task.id, taskStatus);
    taskManager.updateTask(task.id, taskStatus, resultJSON, null);
  } catch (err) {
    LogError("task %s failed: %v", task.id, err);
    taskManager.updateTask(task.id, "FAILURE", "", err as Error);
  }
}

// deno-lint-ignore no-explicit-any
function validationError(c: any, msg: string, err: Error) {
  const response: PolicyEngineStatus = {
    status: StatusInputValidationError,
    detail: [{ msg: `${msg}: ${err.message}`, loc: ["body"], type: "value_error" }],
  };
  return c.json(response, 400);
}

/** True once a task has reached a terminal state. */
function isDone(task: Task): boolean {
  const s: string = task.status;
  return s === "SUCCESS" || s === "FAILURE";
}

/** Parse a bind address into Deno.serve options (TCP host:port or unix path). */
export function parseBind(bind: string): Deno.ServeTcpOptions | Deno.ServeUnixOptions {
  if (bind.startsWith("unix:")) {
    return { path: bind.slice("unix:".length), transport: "unix" };
  }
  const idx = bind.lastIndexOf(":");
  if (idx >= 0) {
    const hostname = bind.slice(0, idx) || "127.0.0.1";
    const port = Number(bind.slice(idx + 1));
    return { hostname, port };
  }
  return { hostname: "127.0.0.1", port: 8080 };
}
