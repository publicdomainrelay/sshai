package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPolicyEngineCompleteExitStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   PolicyEngineCompleteExitStatus
		expected string
	}{
		{"Success", ExitStatusSuccess, "success"},
		{"Failure", ExitStatusFailure, "failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.status.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.status.String())
			}
		})
	}
}

func TestPolicyEngineStatuses(t *testing.T) {
	tests := []struct {
		name     string
		status   PolicyEngineStatuses
		expected string
	}{
		{"Submitted", StatusSubmitted, "submitted"},
		{"InProgress", StatusInProgress, "in_progress"},
		{"Complete", StatusComplete, "complete"},
		{"Unknown", StatusUnknown, "unknown"},
		{"InputValidationError", StatusInputValidationError, "input_validation_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.status.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.status.String())
			}
		})
	}
}

func TestPolicyEngineCompleteJSON(t *testing.T) {
	complete := PolicyEngineComplete{
		ID:         "test-id-123",
		ExitStatus: ExitStatusSuccess,
		Outputs: map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
		Annotations: map[string]interface{}{
			"error": []string{"error1", "error2"},
		},
	}

	data, err := json.Marshal(complete)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded PolicyEngineComplete
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != complete.ID {
		t.Errorf("ID mismatch: expected %s, got %s", complete.ID, decoded.ID)
	}
	if decoded.ExitStatus != complete.ExitStatus {
		t.Errorf("ExitStatus mismatch: expected %s, got %s", complete.ExitStatus, decoded.ExitStatus)
	}
}

func TestPolicyEngineStatusJSON(t *testing.T) {
	status := PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:         "test-id",
			ExitStatus: ExitStatusSuccess,
		},
		ConsoleOutput: "Hello World\n",
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify the JSON contains expected fields
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded["status"] != "complete" {
		t.Errorf("status mismatch: expected complete, got %v", decoded["status"])
	}
	if decoded["console_output"] != "Hello World\n" {
		t.Errorf("console_output mismatch: expected 'Hello World\\n', got %v", decoded["console_output"])
	}
}

func TestPolicyEngineRequestValidate(t *testing.T) {
	tests := []struct {
		name      string
		request   PolicyEngineRequest
		expectErr bool
	}{
		{
			name: "ValidRequest",
			request: PolicyEngineRequest{
				Workflow: map[string]interface{}{
					"jobs": map[string]interface{}{},
				},
			},
			expectErr: false,
		},
		{
			name: "ValidRequestWithInputs",
			request: PolicyEngineRequest{
				Inputs: map[string]interface{}{
					"key": "value",
				},
				Workflow: "name: test",
			},
			expectErr: false,
		},
		{
			name: "MissingWorkflow",
			request: PolicyEngineRequest{
				Inputs: map[string]interface{}{},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.expectErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestPolicyEngineWorkflowJobStepJSON(t *testing.T) {
	step := PolicyEngineWorkflowJobStep{
		ID:   "step-1",
		Name: "Test Step",
		Run:  "echo hello",
		Env: map[string]interface{}{
			"VAR1": "value1",
		},
		WithInputs: map[string]interface{}{
			"input1": "input_value",
		},
	}

	data, err := json.Marshal(step)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded PolicyEngineWorkflowJobStep
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != step.ID {
		t.Errorf("ID mismatch: expected %s, got %s", step.ID, decoded.ID)
	}
	if decoded.Name != step.Name {
		t.Errorf("Name mismatch: expected %s, got %s", step.Name, decoded.Name)
	}
	if decoded.Run != step.Run {
		t.Errorf("Run mismatch: expected %s, got %s", step.Run, decoded.Run)
	}
}

func TestGitHubWebhookEventJSON(t *testing.T) {
	event := GitHubWebhookEvent{
		After: "abc123",
		Sender: &GitHubWebhookEventSender{
			Login:           "testuser",
			WebhookWorkflow: "name: test\njobs: {}",
		},
		Repository: &GitHubWebhookEventRepository{
			FullName: "owner/repo",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded GitHubWebhookEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.After != event.After {
		t.Errorf("After mismatch: expected %s, got %s", event.After, decoded.After)
	}
	if decoded.Sender.Login != event.Sender.Login {
		t.Errorf("Sender.Login mismatch: expected %s, got %s", event.Sender.Login, decoded.Sender.Login)
	}
	if decoded.Repository.FullName != event.Repository.FullName {
		t.Errorf("Repository.FullName mismatch: expected %s, got %s", event.Repository.FullName, decoded.Repository.FullName)
	}
}

func TestTaskManager(t *testing.T) {
	tm := NewTaskManager()

	t.Run("CreateTask", func(t *testing.T) {
		task := tm.CreateTask("task-1")
		if task.ID != "task-1" {
			t.Errorf("expected ID task-1, got %s", task.ID)
		}
		if task.Status != "PENDING" {
			t.Errorf("expected status PENDING, got %s", task.Status)
		}
	})

	t.Run("GetTask", func(t *testing.T) {
		task, ok := tm.GetTask("task-1")
		if !ok {
			t.Error("expected to find task")
		}
		if task.ID != "task-1" {
			t.Errorf("expected ID task-1, got %s", task.ID)
		}
	})

	t.Run("GetNonExistentTask", func(t *testing.T) {
		_, ok := tm.GetTask("non-existent")
		if ok {
			t.Error("expected to not find task")
		}
	})

	t.Run("UpdateTask", func(t *testing.T) {
		tm.UpdateTask("task-1", "SUCCESS", "result data", nil)
		task, _ := tm.GetTask("task-1")
		if task.Status != "SUCCESS" {
			t.Errorf("expected status SUCCESS, got %s", task.Status)
		}
		if task.Result != "result data" {
			t.Errorf("expected result 'result data', got %s", task.Result)
		}
	})

	t.Run("UpdateTaskWithError", func(t *testing.T) {
		tm.CreateTask("task-2")
		testErr := &testError{message: "test error"}
		tm.UpdateTask("task-2", "FAILURE", "", testErr)

		task, _ := tm.GetTask("task-2")
		if task.Status != "FAILURE" {
			t.Errorf("expected status FAILURE, got %s", task.Status)
		}
		if task.Error == nil {
			t.Error("expected error to be set")
		}
	})
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestWorkflowExecutionContext(t *testing.T) {
	ctx := NewWorkflowExecutionContext()

	t.Run("DefaultValues", func(t *testing.T) {
		if ctx.Shell != "bash -xe" {
			t.Errorf("expected default shell 'bash -xe', got %s", ctx.Shell)
		}
		if ctx.Inputs == nil {
			t.Error("Inputs should be initialized")
		}
		if ctx.Env == nil {
			t.Error("Env should be initialized")
		}
		if ctx.Secrets == nil {
			t.Error("Secrets should be initialized")
		}
		if ctx.Outputs == nil {
			t.Error("Outputs should be initialized")
		}
		if ctx.Annotations == nil {
			t.Error("Annotations should be initialized")
		}
	})

	t.Run("SetInputs", func(t *testing.T) {
		ctx.Inputs["key"] = "value"
		if ctx.Inputs["key"] != "value" {
			t.Error("failed to set input")
		}
	})

	t.Run("SetEnv", func(t *testing.T) {
		ctx.Env["VAR"] = "value"
		if ctx.Env["VAR"] != "value" {
			t.Error("failed to set env")
		}
	})
}

func TestGitHubCheckSuiteAnnotation(t *testing.T) {
	annotation := GitHubCheckSuiteAnnotation{
		Path:            "src/main.go",
		AnnotationLevel: "error",
		Title:           "Test Error",
		Message:         "This is a test error",
		RawDetails:      "raw details here",
		StartLine:       10,
		EndLine:         15,
	}

	data, err := json.Marshal(annotation)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded GitHubCheckSuiteAnnotation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Path != annotation.Path {
		t.Errorf("Path mismatch: expected %s, got %s", annotation.Path, decoded.Path)
	}
	if decoded.AnnotationLevel != annotation.AnnotationLevel {
		t.Errorf("AnnotationLevel mismatch: expected %s, got %s", annotation.AnnotationLevel, decoded.AnnotationLevel)
	}
	if decoded.StartLine != annotation.StartLine {
		t.Errorf("StartLine mismatch: expected %d, got %d", annotation.StartLine, decoded.StartLine)
	}
}

func TestPolicyEngineStatusDetailInterface(t *testing.T) {
	tests := []struct {
		name     string
		detail   PolicyEngineStatusDetail
		expected string
	}{
		{
			name: "Complete",
			detail: PolicyEngineComplete{
				ID:         "complete-id",
				ExitStatus: ExitStatusSuccess,
			},
			expected: "complete-id",
		},
		{
			name: "Submitted",
			detail: PolicyEngineSubmitted{
				ID: "submitted-id",
			},
			expected: "submitted-id",
		},
		{
			name: "InProgress",
			detail: PolicyEngineInProgress{
				ID: "progress-id",
			},
			expected: "progress-id",
		},
		{
			name: "Unknown",
			detail: PolicyEngineUnknown{
				ID: "unknown-id",
			},
			expected: "unknown-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.detail.GetID() != tt.expected {
				t.Errorf("expected ID %s, got %s", tt.expected, tt.detail.GetID())
			}
		})
	}
}

func TestTaskTimestamps(t *testing.T) {
	tm := NewTaskManager()

	before := time.Now()
	task := tm.CreateTask("timestamp-test")
	after := time.Now()

	if task.CreatedAt.Before(before) || task.CreatedAt.After(after) {
		t.Error("CreatedAt should be between before and after")
	}
	if task.UpdatedAt.Before(before) || task.UpdatedAt.After(after) {
		t.Error("UpdatedAt should be between before and after")
	}

	// Update and check UpdatedAt changes
	time.Sleep(time.Millisecond)
	beforeUpdate := time.Now()
	tm.UpdateTask("timestamp-test", "SUCCESS", "", nil)
	afterUpdate := time.Now()

	task, _ = tm.GetTask("timestamp-test")
	if task.UpdatedAt.Before(beforeUpdate) || task.UpdatedAt.After(afterUpdate) {
		t.Error("UpdatedAt should have been updated")
	}
}

func TestPolicyEngineInputValidationError(t *testing.T) {
	err := PolicyEngineInputValidationError{
		Msg:   "Invalid field",
		Loc:   []string{"body", "workflow"},
		Type:  "value_error",
		URL:   "https://example.com/docs",
		Input: "bad input",
	}

	data, err2 := json.Marshal(err)
	if err2 != nil {
		t.Fatalf("failed to marshal: %v", err2)
	}

	var decoded PolicyEngineInputValidationError
	if err2 := json.Unmarshal(data, &decoded); err2 != nil {
		t.Fatalf("failed to unmarshal: %v", err2)
	}

	if decoded.Msg != err.Msg {
		t.Errorf("Msg mismatch: expected %s, got %s", err.Msg, decoded.Msg)
	}
	if len(decoded.Loc) != len(err.Loc) {
		t.Errorf("Loc length mismatch: expected %d, got %d", len(err.Loc), len(decoded.Loc))
	}
}
