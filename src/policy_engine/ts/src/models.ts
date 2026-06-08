// Models for the policy engine — a TypeScript (Deno) port of the Go
// implementation in ../../common/models.go. Implements GitHub Actions workflow
// evaluation as a policy engine.

/** Exit status of a completed policy engine request. */
export type PolicyEngineCompleteExitStatus = "success" | "failure";

export const ExitStatusSuccess: PolicyEngineCompleteExitStatus = "success";
export const ExitStatusFailure: PolicyEngineCompleteExitStatus = "failure";

/** Status of a policy engine request. */
export type PolicyEngineStatuses =
  | "submitted"
  | "in_progress"
  | "complete"
  | "unknown"
  | "input_validation_error";

export const StatusSubmitted: PolicyEngineStatuses = "submitted";
export const StatusInProgress: PolicyEngineStatuses = "in_progress";
export const StatusComplete: PolicyEngineStatuses = "complete";
export const StatusUnknown: PolicyEngineStatuses = "unknown";
export const StatusInputValidationError: PolicyEngineStatuses = "input_validation_error";

/** A completed policy engine request. */
export interface PolicyEngineComplete {
  id: string;
  exit_status: PolicyEngineCompleteExitStatus;
  outputs?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

/** A submitted policy engine request. */
export interface PolicyEngineSubmitted {
  id: string;
}

/** An in-progress policy engine request. */
export interface PolicyEngineInProgress {
  id: string;
  status_updates?: Record<string, PolicyEngineStatusUpdateJob>;
}

/** An unknown policy engine request. */
export interface PolicyEngineUnknown {
  id: string;
}

/** A step status update. */
export interface PolicyEngineStatusUpdateJobStep {
  status: PolicyEngineStatuses;
  metadata?: Record<string, string>;
  outputs?: Record<string, unknown>;
}

/** A job status update. */
export interface PolicyEngineStatusUpdateJob {
  steps?: Record<string, PolicyEngineStatusUpdateJobStep>;
}

/** An input validation error. */
export interface PolicyEngineInputValidationError {
  msg: string;
  loc: string[];
  type: string;
  url?: string;
  input?: string;
}

/** The full status response. */
export interface PolicyEngineStatus {
  status: PolicyEngineStatuses;
  detail: unknown;
  console_output?: string;
}

/** A step in a workflow job. */
export interface PolicyEngineWorkflowJobStep {
  id?: string;
  if?: unknown;
  name?: string;
  uses?: string;
  shell?: string;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
  run?: string;
}

/** A job in a workflow. */
export interface PolicyEngineWorkflowJob {
  "runs-on"?: unknown;
  steps?: PolicyEngineWorkflowJobStep[];
}

/** A workflow definition. */
export interface PolicyEngineWorkflow {
  name?: string;
  on?: unknown;
  jobs?: Record<string, PolicyEngineWorkflowJob>;
}

/** A request to the policy engine. */
export interface PolicyEngineRequest {
  inputs?: Record<string, unknown>;
  workflow?: unknown;
  context?: Record<string, unknown>;
  stack?: Record<string, unknown>;
}

/** Validate a PolicyEngineRequest. Throws on invalid input. */
export function validateRequest(r: PolicyEngineRequest): void {
  if (r.workflow === undefined || r.workflow === null) {
    throw new Error("workflow is required");
  }
}

/** Sender of a GitHub webhook event. */
export interface GitHubWebhookEventSender {
  login: string;
  webhook_workflow?: string;
}

/** Repository in a GitHub webhook event. */
export interface GitHubWebhookEventRepository {
  full_name: string;
}

/** A GitHub webhook event. */
export interface GitHubWebhookEvent {
  after?: string;
  sender?: GitHubWebhookEventSender;
  repository?: GitHubWebhookEventRepository;
}

/** An annotation in a GitHub check suite. */
export interface GitHubCheckSuiteAnnotation {
  path?: string;
  annotation_level?: string;
  title?: string;
  message?: string;
  raw_details?: string;
  start_line?: number;
  end_line?: number;
}

export type TaskState = "PENDING" | "SUCCESS" | "FAILURE";

/**
 * An async task for workflow execution. Console output is buffered and
 * broadcast to subscribers (used by the SSE stream endpoint).
 */
export class Task {
  id: string;
  status: TaskState = "PENDING";
  result = "";
  error: Error | null = null;
  createdAt: Date;
  updatedAt: Date;
  consoleOutput: string[] = [];
  private subscribers = new Set<(line: string) => void>();

  constructor(id: string) {
    this.id = id;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  /** Append a line of console output and notify subscribers. */
  appendConsoleOutput(line: string): void {
    this.consoleOutput.push(line);
    for (const sub of this.subscribers) {
      try {
        sub(line);
      } catch {
        // Skip failed subscribers
      }
    }
  }

  /** All console output collected so far, joined by newlines. */
  getConsoleOutput(): string {
    return this.consoleOutput.join("\n");
  }

  /** Register a subscriber for new console output lines. */
  subscribe(fn: (line: string) => void): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }
}

/** Manages async tasks. */
export class TaskManager {
  private tasks = new Map<string, Task>();

  createTask(id: string): Task {
    const task = new Task(id);
    this.tasks.set(id, task);
    return task;
  }

  getTask(id: string): Task | undefined {
    return this.tasks.get(id);
  }

  updateTask(id: string, status: TaskState, result: string, error: Error | null): void {
    const task = this.tasks.get(id);
    if (task) {
      task.status = status;
      task.result = result;
      task.error = error;
      task.updatedAt = new Date();
    }
  }
}

/** Holds the context for executing a workflow. */
export class WorkflowExecutionContext {
  inputs: Record<string, unknown> = {};
  env: Record<string, unknown> = {};
  secrets: Record<string, string> = {};
  outputs: Record<string, Record<string, unknown>> = {};
  annotations: Record<string, GitHubCheckSuiteAnnotation[]> = {};
  workspace = "";
  tempDir = "";
  cacheDir = "";
  toolCacheDir = ""; // RUNNER_TOOL_CACHE
  homeDir = ""; // Ephemeral HOME
  shell = "bash -xe";
  error: Error | null = null;
  consoleOutput: string[] = [];
}
