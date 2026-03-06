// Package policy_engine implements GitHub Actions workflow evaluation as a policy engine.
// This is a Go port of the Python policy_engine.py.
package common

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// PolicyEngineCompleteExitStatus represents the exit status of a completed policy engine request.
type PolicyEngineCompleteExitStatus string

const (
	ExitStatusSuccess PolicyEngineCompleteExitStatus = "success"
	ExitStatusFailure PolicyEngineCompleteExitStatus = "failure"
)

// PolicyEngineStatus represents the status of a policy engine request.
type PolicyEngineStatuses string

const (
	StatusSubmitted            PolicyEngineStatuses = "submitted"
	StatusInProgress           PolicyEngineStatuses = "in_progress"
	StatusComplete             PolicyEngineStatuses = "complete"
	StatusUnknown              PolicyEngineStatuses = "unknown"
	StatusInputValidationError PolicyEngineStatuses = "input_validation_error"
)

// PolicyEngineComplete represents a completed policy engine request.
type PolicyEngineComplete struct {
	ID          string                         `json:"id"`
	ExitStatus  PolicyEngineCompleteExitStatus `json:"exit_status"`
	Outputs     map[string]interface{}         `json:"outputs,omitempty"`
	Annotations map[string]interface{}         `json:"annotations,omitempty"`
}

// PolicyEngineSubmitted represents a submitted policy engine request.
type PolicyEngineSubmitted struct {
	ID string `json:"id"`
}

// PolicyEngineInProgress represents an in-progress policy engine request.
type PolicyEngineInProgress struct {
	ID            string                                   `json:"id"`
	StatusUpdates map[string]PolicyEngineStatusUpdateJob   `json:"status_updates,omitempty"`
}

// PolicyEngineUnknown represents an unknown policy engine request.
type PolicyEngineUnknown struct {
	ID string `json:"id"`
}

// PolicyEngineStatusUpdateJobStep represents a step status update.
type PolicyEngineStatusUpdateJobStep struct {
	Status   PolicyEngineStatuses   `json:"status"`
	Metadata map[string]string      `json:"metadata,omitempty"`
	Outputs  map[string]interface{} `json:"outputs,omitempty"`
}

// PolicyEngineStatusUpdateJob represents a job status update.
type PolicyEngineStatusUpdateJob struct {
	Steps map[string]PolicyEngineStatusUpdateJobStep `json:"steps,omitempty"`
}

// PolicyEngineInputValidationError represents an input validation error.
type PolicyEngineInputValidationError struct {
	Msg   string   `json:"msg"`
	Loc   []string `json:"loc"`
	Type  string   `json:"type"`
	URL   string   `json:"url,omitempty"`
	Input string   `json:"input,omitempty"`
}

// PolicyEngineStatusDetail is an interface for status details.
type PolicyEngineStatusDetail interface {
	GetID() string
}

func (p PolicyEngineComplete) GetID() string   { return p.ID }
func (p PolicyEngineSubmitted) GetID() string  { return p.ID }
func (p PolicyEngineInProgress) GetID() string { return p.ID }
func (p PolicyEngineUnknown) GetID() string    { return p.ID }

// PolicyEngineStatus represents the full status response.
type PolicyEngineStatus struct {
	Status        PolicyEngineStatuses `json:"status"`
	Detail        interface{}          `json:"detail"`
	ConsoleOutput string               `json:"console_output,omitempty"`
}

// PolicyEngineWorkflowJobStep represents a step in a workflow job.
type PolicyEngineWorkflowJobStep struct {
	ID          string                 `json:"id,omitempty" yaml:"id,omitempty"`
	IfCondition interface{}            `json:"if_condition,omitempty" yaml:"if,omitempty"`
	Name        string                 `json:"name,omitempty" yaml:"name,omitempty"`
	Uses        string                 `json:"uses,omitempty" yaml:"uses,omitempty"`
	Shell       string                 `json:"shell,omitempty" yaml:"shell,omitempty"`
	WithInputs  map[string]interface{} `json:"with_inputs,omitempty" yaml:"with,omitempty"`
	Env         map[string]interface{} `json:"env,omitempty" yaml:"env,omitempty"`
	Run         string                 `json:"run,omitempty" yaml:"run,omitempty"`
}

// PolicyEngineWorkflowJob represents a job in a workflow.
type PolicyEngineWorkflowJob struct {
	RunsOn interface{}                   `json:"runs_on,omitempty" yaml:"runs-on,omitempty"`
	Steps  []PolicyEngineWorkflowJobStep `json:"steps,omitempty" yaml:"steps,omitempty"`
}

// PolicyEngineWorkflow represents a workflow definition.
type PolicyEngineWorkflow struct {
	Name string                             `json:"name,omitempty" yaml:"name,omitempty"`
	On   interface{}                        `json:"on,omitempty" yaml:"on,omitempty"`
	Jobs map[string]PolicyEngineWorkflowJob `json:"jobs,omitempty" yaml:"jobs,omitempty"`
}

// PolicyEngineRequest represents a request to the policy engine.
type PolicyEngineRequest struct {
	Inputs   map[string]interface{} `json:"inputs,omitempty"`
	Workflow interface{}            `json:"workflow,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty"`
	Stack    map[string]interface{} `json:"stack,omitempty"`
}

// GitHubWebhookEventSender represents the sender of a GitHub webhook event.
type GitHubWebhookEventSender struct {
	Login           string `json:"login"`
	WebhookWorkflow string `json:"webhook_workflow,omitempty"`
}

// GitHubWebhookEventRepository represents a repository in a GitHub webhook event.
type GitHubWebhookEventRepository struct {
	FullName string `json:"full_name"`
}

// GitHubWebhookEvent represents a GitHub webhook event.
type GitHubWebhookEvent struct {
	After      string                        `json:"after,omitempty"`
	Sender     *GitHubWebhookEventSender     `json:"sender,omitempty"`
	Repository *GitHubWebhookEventRepository `json:"repository,omitempty"`
}

// GitHubCheckSuiteAnnotation represents an annotation in a GitHub check suite.
type GitHubCheckSuiteAnnotation struct {
	Path            string `json:"path,omitempty"`
	AnnotationLevel string `json:"annotation_level,omitempty"`
	Title           string `json:"title,omitempty"`
	Message         string `json:"message,omitempty"`
	RawDetails      string `json:"raw_details,omitempty"`
	StartLine       int    `json:"start_line,omitempty"`
	EndLine         int    `json:"end_line,omitempty"`
}

// Task represents an async task for workflow execution.
type Task struct {
	ID            string
	Status        string
	Result        string
	Error         error
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ConsoleOutput []string
	consoleMu     sync.RWMutex
	subscribers   []chan string
	subscriberMu  sync.Mutex
}

// AppendConsoleOutput appends a line of console output and notifies subscribers.
func (t *Task) AppendConsoleOutput(line string) {
	t.consoleMu.Lock()
	t.ConsoleOutput = append(t.ConsoleOutput, line)
	t.consoleMu.Unlock()

	t.subscriberMu.Lock()
	defer t.subscriberMu.Unlock()
	for _, ch := range t.subscribers {
		select {
		case ch <- line:
		default:
			// Skip slow subscribers
		}
	}
}

// GetConsoleOutput returns all console output collected so far.
func (t *Task) GetConsoleOutput() string {
	t.consoleMu.RLock()
	defer t.consoleMu.RUnlock()
	return strings.Join(t.ConsoleOutput, "\n")
}

// Subscribe returns a channel that receives new console output lines.
// Call Unsubscribe with the returned channel when done.
func (t *Task) Subscribe() chan string {
	ch := make(chan string, 64)
	t.subscriberMu.Lock()
	t.subscribers = append(t.subscribers, ch)
	t.subscriberMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (t *Task) Unsubscribe(ch chan string) {
	t.subscriberMu.Lock()
	defer t.subscriberMu.Unlock()
	for i, sub := range t.subscribers {
		if sub == ch {
			t.subscribers = append(t.subscribers[:i], t.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

// TaskManager manages async tasks.
type TaskManager struct {
	tasks map[string]*Task
	mu    sync.RWMutex
}

// NewTaskManager creates a new task manager.
func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks: make(map[string]*Task),
	}
}

// CreateTask creates a new task and returns its ID.
func (tm *TaskManager) CreateTask(id string) *Task {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	task := &Task{
		ID:            id,
		Status:        "PENDING",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ConsoleOutput: []string{},
	}
	tm.tasks[id] = task
	return task
}

// GetTask retrieves a task by ID.
func (tm *TaskManager) GetTask(id string) (*Task, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	task, ok := tm.tasks[id]
	return task, ok
}

// UpdateTask updates a task's status and result.
func (tm *TaskManager) UpdateTask(id string, status string, result string, err error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if task, ok := tm.tasks[id]; ok {
		task.Status = status
		task.Result = result
		task.Error = err
		task.UpdatedAt = time.Now()
	}
}

// WorkflowExecutionContext holds the context for executing a workflow.
type WorkflowExecutionContext struct {
	Inputs        map[string]interface{}
	Env           map[string]interface{}
	Secrets       map[string]string
	Outputs       map[string]map[string]interface{}
	Annotations   map[string][]GitHubCheckSuiteAnnotation
	Workspace     string
	TempDir       string
	CacheDir      string
	ToolCacheDir  string // RUNNER_TOOL_CACHE: where actions/tool-cache stores downloads
	HomeDir       string // Ephemeral HOME to prevent writes to real ~
	Shell         string
	Error         error
	ConsoleOutput []string
}

// NewWorkflowExecutionContext creates a new workflow execution context.
func NewWorkflowExecutionContext() *WorkflowExecutionContext {
	return &WorkflowExecutionContext{
		Inputs:       make(map[string]interface{}),
		Env:          make(map[string]interface{}),
		Secrets:      make(map[string]string),
		Outputs:      make(map[string]map[string]interface{}),
		Annotations:  make(map[string][]GitHubCheckSuiteAnnotation),
		Shell:        "bash -xe",
		ConsoleOutput: []string{},
	}
}

// MarshalJSON implements custom JSON marshaling for PolicyEngineStatus.
func (s PolicyEngineStatus) MarshalJSON() ([]byte, error) {
	type Alias PolicyEngineStatus
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(&s),
	})
}

// String returns a string representation of the status.
func (s PolicyEngineStatuses) String() string {
	return string(s)
}

// String returns a string representation of the exit status.
func (e PolicyEngineCompleteExitStatus) String() string {
	return string(e)
}

// Validate validates the PolicyEngineRequest.
func (r *PolicyEngineRequest) Validate() error {
	if r.Workflow == nil {
		return fmt.Errorf("workflow is required")
	}
	return nil
}
