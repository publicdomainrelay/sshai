package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080", 30*time.Second)

	if client.endpoint != "http://localhost:8080" {
		t.Errorf("expected endpoint http://localhost:8080, got %s", client.endpoint)
	}

	if client.timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", client.timeout)
	}

	if client.httpClient == nil {
		t.Error("httpClient should be initialized")
	}
}

func TestClientCreateRequest(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/request/create" {
			t.Errorf("expected path /request/create, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected method POST, got %s", r.Method)
		}

		response := PolicyEngineStatus{
			Status: StatusSubmitted,
			Detail: PolicyEngineSubmitted{
				ID: "test-task-id",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	request := &PolicyEngineRequest{
		Workflow: "name: test",
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
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	if status.Status != StatusSubmitted {
		t.Errorf("expected status submitted, got %s", status.Status)
	}
}

func TestClientCreateRequestError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	request := &PolicyEngineRequest{
		Workflow: "name: test",
	}

	ctx := context.Background()
	_, err := client.CreateRequest(ctx, request)
	if err == nil {
		t.Error("expected error for bad request")
	}
}

func TestClientGetStatus(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/request/status/test-task-id" {
			t.Errorf("expected path /request/status/test-task-id, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected method GET, got %s", r.Method)
		}

		response := PolicyEngineStatus{
			Status: StatusComplete,
			Detail: PolicyEngineComplete{
				ID:         "test-task-id",
				ExitStatus: ExitStatusSuccess,
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	ctx := context.Background()
	status, err := client.GetStatus(ctx, "test-task-id")
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}
}

func TestClientGetStatusError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	ctx := context.Background()
	_, err := client.GetStatus(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestClientGetConsoleOutput(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/request/console_output/test-task-id" {
			t.Errorf("expected path /request/console_output/test-task-id, got %s", r.URL.Path)
		}

		w.Write([]byte("Hello World\nTest output"))
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	ctx := context.Background()
	output, err := client.GetConsoleOutput(ctx, "test-task-id")
	if err != nil {
		t.Fatalf("GetConsoleOutput failed: %v", err)
	}

	if output != "Hello World\nTest output" {
		t.Errorf("expected 'Hello World\\nTest output', got %s", output)
	}
}

func TestClientWaitForCompletion(t *testing.T) {
	callCount := 0

	// Create a mock server that returns pending first, then complete
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		var response PolicyEngineStatus
		if callCount < 3 {
			response = PolicyEngineStatus{
				Status: StatusInProgress,
				Detail: PolicyEngineInProgress{
					ID: "test-task-id",
				},
			}
		} else {
			response = PolicyEngineStatus{
				Status: StatusComplete,
				Detail: PolicyEngineComplete{
					ID:         "test-task-id",
					ExitStatus: ExitStatusSuccess,
				},
			}
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	ctx := context.Background()
	status, err := client.WaitForCompletion(ctx, "test-task-id", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForCompletion failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	if callCount < 3 {
		t.Errorf("expected at least 3 calls, got %d", callCount)
	}
}

func TestClientWaitForCompletionTimeout(t *testing.T) {
	// Create a mock server that always returns pending
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := PolicyEngineStatus{
			Status: StatusInProgress,
			Detail: PolicyEngineInProgress{
				ID: "test-task-id",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.WaitForCompletion(ctx, "test-task-id", 10*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestLoadWorkflowFromFile(t *testing.T) {
	// Create a temp workflow file
	tmpDir, err := os.MkdirTemp("", "workflow-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	workflowContent := `name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "hello"
`
	workflowPath := filepath.Join(tmpDir, "workflow.yml")
	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow file: %v", err)
	}

	workflow, err := LoadWorkflowFromFile(workflowPath)
	if err != nil {
		t.Fatalf("LoadWorkflowFromFile failed: %v", err)
	}

	workflowMap, ok := workflow.(map[string]interface{})
	if !ok {
		t.Fatal("expected workflow to be a map")
	}

	if workflowMap["name"] != "Test Workflow" {
		t.Errorf("expected name 'Test Workflow', got %v", workflowMap["name"])
	}
}

func TestLoadWorkflowFromFileNotFound(t *testing.T) {
	_, err := LoadWorkflowFromFile("/non/existent/path.yml")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadWorkflowFromFileInvalidYAML(t *testing.T) {
	// Create a temp file with invalid YAML
	tmpDir, err := os.MkdirTemp("", "workflow-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	workflowPath := filepath.Join(tmpDir, "invalid.yml")
	if err := os.WriteFile(workflowPath, []byte("{{{{invalid yaml"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = LoadWorkflowFromFile(workflowPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestFormatOutputJSON(t *testing.T) {
	data := map[string]interface{}{
		"key":   "value",
		"count": 42,
	}

	output, err := FormatOutput(data, "json")
	if err != nil {
		t.Fatalf("FormatOutput failed: %v", err)
	}

	// Parse back to verify
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	if parsed["key"] != "value" {
		t.Errorf("expected key=value, got %v", parsed["key"])
	}
}

func TestFormatOutputYAML(t *testing.T) {
	data := map[string]interface{}{
		"key": "value",
	}

	output, err := FormatOutput(data, "yaml")
	if err != nil {
		t.Fatalf("FormatOutput failed: %v", err)
	}

	if output == "" {
		t.Error("expected non-empty output")
	}

	// Check it contains expected content
	if !contains(output, "key: value") {
		t.Errorf("expected output to contain 'key: value', got: %s", output)
	}
}

func TestFormatOutputUnsupported(t *testing.T) {
	data := map[string]interface{}{
		"key": "value",
	}

	_, err := FormatOutput(data, "xml")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestClientStreamConsoleOutput(t *testing.T) {
	// Create a mock SSE server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/request/console_output_stream/") {
			t.Errorf("expected path prefix /request/console_output_stream/, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("expected ResponseWriter to implement Flusher")
			return
		}

		fmt.Fprintf(w, "data: hello world\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "data: second line\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "event: done\ndata: SUCCESS\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	client := NewClient(server.URL, 30*time.Second)

	var buf bytes.Buffer
	ctx := context.Background()
	err := client.StreamConsoleOutput(ctx, "test-task-id", &buf)
	if err != nil {
		t.Fatalf("StreamConsoleOutput failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "hello world") {
		t.Errorf("expected output to contain 'hello world', got: %s", output)
	}
	if !strings.Contains(output, "second line") {
		t.Errorf("expected output to contain 'second line', got: %s", output)
	}
}

func TestClientIntegrationWithConsoleOutput(t *testing.T) {
	// Full integration: create -> wait -> get console output
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	policyServer := NewServer(":0")
	ts := httptest.NewServer(policyServer.mux)
	defer ts.Close()

	client := NewClient(ts.URL, 60*time.Second)

	request := &PolicyEngineRequest{
		Workflow: `
name: Client Console Output Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "client output test"
`,
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
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	detail := status.Detail.(map[string]interface{})
	taskID := detail["id"].(string)

	// Wait for completion
	finalStatus, err := client.WaitForCompletion(ctx, taskID, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForCompletion failed: %v", err)
	}

	if finalStatus.Status != StatusComplete {
		t.Fatalf("expected status complete, got %s", finalStatus.Status)
	}

	// Now get console output
	output, err := client.GetConsoleOutput(ctx, taskID)
	if err != nil {
		t.Fatalf("GetConsoleOutput failed: %v", err)
	}

	if !strings.Contains(output, "client output test") {
		t.Errorf("expected console output to contain 'client output test', got: %s", output)
	}
}

func TestClientWithMockGitHubServer(t *testing.T) {
	// Create mock GitHub server
	mockGH := NewMockGitHubServer()
	defer mockGH.Close()

	// Setup app and installation
	mockGH.SetupApp(12345, "test-app", "Test App")
	mockGH.AddInstallation(1, "testorg", "Organization")

	// Test getting installations
	resp, err := http.Get(mockGH.URL + "/app/installations")
	if err != nil {
		t.Fatalf("failed to get installations: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var installations []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&installations)

	if len(installations) != 1 {
		t.Errorf("expected 1 installation, got %d", len(installations))
	}

	if installations[0]["account"].(map[string]interface{})["login"] != "testorg" {
		t.Errorf("expected login testorg, got %v", installations[0]["account"])
	}
}

func TestClientCreateCheckRun(t *testing.T) {
	// Create mock GitHub server
	mockGH := NewMockGitHubServer()
	defer mockGH.Close()

	mockGH.AddRepository("testorg/testrepo", false)

	// Create a check run
	checkRunData := map[string]interface{}{
		"name":        "Test Check",
		"head_sha":    "abc123",
		"status":      "in_progress",
		"external_id": "ext-123",
	}

	body, _ := json.Marshal(checkRunData)
	resp, err := http.Post(
		mockGH.URL+"/repos/testorg/testrepo/check-runs",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("failed to create check run: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var checkRun MockGitHubCheckRun
	json.NewDecoder(resp.Body).Decode(&checkRun)

	if checkRun.Name != "Test Check" {
		t.Errorf("expected name 'Test Check', got %s", checkRun.Name)
	}

	if checkRun.ID == 0 {
		t.Error("expected non-zero check run ID")
	}
}

func TestClientCreateStatus(t *testing.T) {
	// Create mock GitHub server
	mockGH := NewMockGitHubServer()
	defer mockGH.Close()

	mockGH.AddRepository("testorg/testrepo", false)

	// Create a commit status
	statusData := map[string]interface{}{
		"state":       "success",
		"target_url":  "http://example.com",
		"description": "Build passed",
		"context":     "ci/build",
	}

	body, _ := json.Marshal(statusData)
	resp, err := http.Post(
		mockGH.URL+"/repos/testorg/testrepo/statuses/abc123",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("failed to create status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify status was created
	statuses := mockGH.GetStatuses("testorg/testrepo", "abc123")
	if len(statuses) != 1 {
		t.Errorf("expected 1 status, got %d", len(statuses))
	}

	if statuses[0].State != "success" {
		t.Errorf("expected state 'success', got %s", statuses[0].State)
	}
}

func TestClientIntegration(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	// Create the policy engine server
	policyServer := NewServer(":0")

	// Start the server
	ts := httptest.NewServer(policyServer.mux)
	defer ts.Close()

	// Create client
	client := NewClient(ts.URL, 60*time.Second)

	// Submit a workflow
	request := &PolicyEngineRequest{
		Workflow: `
name: Client Integration Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "client integration test"
`,
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
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	if status.Status != StatusSubmitted {
		t.Fatalf("expected status submitted, got %s", status.Status)
	}

	detail := status.Detail.(map[string]interface{})
	taskID := detail["id"].(string)

	// Wait for completion
	finalStatus, err := client.WaitForCompletion(ctx, taskID, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForCompletion failed: %v", err)
	}

	if finalStatus.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", finalStatus.Status)
	}
}
