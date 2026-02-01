package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestCLIClientCreate(t *testing.T) {
	client := NewClient("http://localhost:8080", 30*time.Second)

	workflow := "name: Test CLI\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo hello"
	request := &PolicyEngineRequest{
		Workflow: workflow,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	ctx := context.Background()
	status, err := client.CreateRequest(ctx, request)
	// Expect connection error since no server is running
	if err == nil {
		t.Error("expected connection error")
		return
	}

	if status != nil && status.Status != StatusSubmitted {
		t.Errorf("expected status submitted, got %s", status.Status)
	}

	// Check that detail has ID if we got a response
	if status != nil {
		detail, ok := status.Detail.(PolicyEngineSubmitted)
		if ok && detail.ID == "" {
			t.Error("expected non-empty task ID")
		}
	}
}

func TestCLIClientStatus(t *testing.T) {
	client := NewClient("http://localhost:8080", 30*time.Second)

	// Test with non-existent task ID
	ctx := context.Background()
	status, err := client.GetStatus(ctx, "non-existent-task")
	// Expect connection error since no server is running
	if err == nil {
		t.Error("expected connection error")
		return
	}

	if status != nil && status.Status != StatusUnknown {
		t.Errorf("expected status unknown, got %s", status.Status)
	}
}

func TestCLIClientConsoleOutput(t *testing.T) {
	client := NewClient("http://localhost:8080", 30*time.Second)

	// Test with non-existent task ID
	ctx := context.Background()
	_, err := client.GetConsoleOutput(ctx, "non-existent-task")
	// Expect connection error since no server is running
	if err == nil {
		t.Error("expected connection error")
		return
	}
}

func TestCLILoadWorkflowFromFile(t *testing.T) {
	// Test with non-existent file
	_, err := LoadWorkflowFromFile("non-existent.yml")
	if err == nil {
		t.Error("expected error for non-existent file")
	}

	// Create a temporary workflow file for testing
	workflowYAML := "name: test\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo hello"
	tmpFile := t.TempDir() + "/test_workflow.yml"
	err = os.WriteFile(tmpFile, []byte(workflowYAML), 0644)
	if err != nil {
		t.Fatalf("failed to create temp workflow file: %v", err)
	}

	// Test with valid file
	workflow, err := LoadWorkflowFromFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse workflow file: %v", err)
	}

	if workflow == nil {
		t.Error("expected workflow to be parsed")
	}
}

func TestCLIFormatOutput(t *testing.T) {
	status := &PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:         "test-id",
			ExitStatus: ExitStatusSuccess,
		},
		ConsoleOutput: "test output",
	}

	// Test JSON format
	jsonOutput, err := FormatOutput(status, "json")
	if err != nil {
		t.Fatalf("failed to format as JSON: %v", err)
	}

	var parsedStatus PolicyEngineStatus
	if err := json.Unmarshal([]byte(jsonOutput), &parsedStatus); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if parsedStatus.Status != status.Status {
		t.Error("JSON output should preserve status")
	}

	// Test YAML format
	yamlOutput, err := FormatOutput(status, "yaml")
	if err != nil {
		t.Fatalf("failed to format as YAML: %v", err)
	}

	if yamlOutput == "" {
		t.Error("YAML output should not be empty")
	}

	// Test invalid format
	_, err = FormatOutput(status, "invalid")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestCLIWaitForCompletion(t *testing.T) {
	client := NewClient("http://localhost:8080", 1*time.Second)

	// This should timeout for non-existent task
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.WaitForCompletion(ctx, "non-existent-task", 100*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
}
