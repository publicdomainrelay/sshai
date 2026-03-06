package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// tempSockPath returns a short, random socket path under /tmp suitable for
// macOS (which limits Unix socket paths to ~104 bytes).
func tempSockPath(prefix string) string {
	return fmt.Sprintf("/tmp/%s-%d.sock", prefix, rand.Int63())
}

func TestServerHealth(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)

	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %s", body["status"])
	}
}

func TestServerRateLimit(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodGet, "/rate_limit", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	resources, ok := body["resources"].(map[string]interface{})
	if !ok {
		t.Fatal("expected resources in response")
	}

	core, ok := resources["core"].(map[string]interface{})
	if !ok {
		t.Fatal("expected core in resources")
	}

	if core["limit"].(float64) != 5000 {
		t.Errorf("expected limit=5000, got %v", core["limit"])
	}
}

func TestServerRequestCreate(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer(":0")

	request := PolicyEngineRequest{
		Workflow: `
name: Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "test"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/request/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var status PolicyEngineStatus
	json.NewDecoder(resp.Body).Decode(&status)

	if status.Status != StatusSubmitted {
		t.Errorf("expected status submitted, got %s", status.Status)
	}

	detail, ok := status.Detail.(map[string]interface{})
	if !ok {
		t.Fatal("expected detail to be a map")
	}

	if detail["id"] == "" {
		t.Error("expected non-empty task ID")
	}
}

func TestServerRequestCreateMethodNotAllowed(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodGet, "/request/create", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestServerRequestCreateInvalidJSON(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodPost, "/request/create", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestServerRequestCreateMissingWorkflow(t *testing.T) {
	server := NewServer(":0")

	request := PolicyEngineRequest{
		Inputs: map[string]interface{}{
			"key": "value",
		},
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/request/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestServerRequestStatus(t *testing.T) {
	server := NewServer(":0")

	// Create a task
	task := server.taskManager.CreateTask("test-task-123")

	req := httptest.NewRequest(http.MethodGet, "/request/status/test-task-123", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var status PolicyEngineStatus
	json.NewDecoder(resp.Body).Decode(&status)

	// Task is pending, so should be in_progress
	if status.Status != StatusInProgress {
		t.Errorf("expected status in_progress, got %s", status.Status)
	}

	_ = task // Use task
}

func TestServerRequestStatusCompleted(t *testing.T) {
	server := NewServer(":0")

	// Create and complete a task
	server.taskManager.CreateTask("completed-task")
	resultJSON, _ := json.Marshal(PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:         "completed-task",
			ExitStatus: ExitStatusSuccess,
		},
	})
	server.taskManager.UpdateTask("completed-task", "SUCCESS", string(resultJSON), nil)

	req := httptest.NewRequest(http.MethodGet, "/request/status/completed-task", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var status PolicyEngineStatus
	json.NewDecoder(resp.Body).Decode(&status)

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}
}

func TestServerRequestStatusUnknown(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodGet, "/request/status/non-existent-task", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var status PolicyEngineStatus
	json.NewDecoder(resp.Body).Decode(&status)

	if status.Status != StatusUnknown {
		t.Errorf("expected status unknown, got %s", status.Status)
	}
}

func TestServerRequestStatusMethodNotAllowed(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodPost, "/request/status/test-id", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestServerRequestStatusMissingID(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodGet, "/request/status/", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestServerRequestConsoleOutput(t *testing.T) {
	server := NewServer(":0")

	// Create and complete a task with console output
	server.taskManager.CreateTask("output-task")
	resultJSON, _ := json.Marshal(PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:         "output-task",
			ExitStatus: ExitStatusSuccess,
		},
		ConsoleOutput: "Hello World\nTest output",
	})
	server.taskManager.UpdateTask("output-task", "SUCCESS", string(resultJSON), nil)

	req := httptest.NewRequest(http.MethodGet, "/request/console_output/output-task", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello World\nTest output" {
		t.Errorf("expected 'Hello World\\nTest output', got %s", string(body))
	}
}

func TestServerRequestConsoleOutputPending(t *testing.T) {
	server := NewServer(":0")

	// Create a pending task
	server.taskManager.CreateTask("pending-task")

	req := httptest.NewRequest(http.MethodGet, "/request/console_output/pending-task", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// In-progress tasks now return 200 with whatever output is available so far
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("expected empty output for pending task, got: %s", string(body))
	}
}

func TestServerGitHubWebhook(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer(":0")

	event := GitHubWebhookEvent{
		After: "abc123",
		Sender: &GitHubWebhookEventSender{
			Login: "testuser",
			WebhookWorkflow: `
name: Webhook Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "webhook"
`,
		},
		Repository: &GitHubWebhookEventRepository{
			FullName: "owner/repo",
		},
	}

	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", "test-delivery-id")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var status PolicyEngineStatus
	json.NewDecoder(resp.Body).Decode(&status)

	if status.Status != StatusSubmitted {
		t.Errorf("expected status submitted, got %s", status.Status)
	}
}

func TestServerGitHubWebhookUnsupportedEvent(t *testing.T) {
	server := NewServer(":0")

	event := map[string]interface{}{
		"action": "created",
	}

	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "issues")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Unsupported events should return OK with a message
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestServerGitHubWebhookMethodNotAllowed(t *testing.T) {
	server := NewServer(":0")

	req := httptest.NewRequest(http.MethodGet, "/webhook/github", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestServerCORSMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected CORS header Access-Control-Allow-Origin: *")
	}
	if resp.Header.Get("Access-Control-Allow-Methods") != "GET, POST, OPTIONS" {
		t.Error("expected CORS header Access-Control-Allow-Methods")
	}
}

func TestServerCORSMiddlewareOptions(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not be called"))
	})

	corsHandler := CORSMiddleware(handler)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for OPTIONS, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		t.Error("OPTIONS request should not have body")
	}
}

func TestServerLoggingMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	loggingHandler := LoggingMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	loggingHandler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestServerIntegration(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer(":0")

	// Submit a workflow
	request := PolicyEngineRequest{
		Workflow: `
name: Integration Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "integration test"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/request/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create request failed: %d %s", resp.StatusCode, string(respBody))
	}

	var createStatus PolicyEngineStatus
	json.Unmarshal(respBody, &createStatus)

	detail := createStatus.Detail.(map[string]interface{})
	taskID := detail["id"].(string)

	// Poll for completion
	var finalStatus PolicyEngineStatus
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)

		req = httptest.NewRequest(http.MethodGet, "/request/status/"+taskID, nil)
		w = httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		resp = w.Result()
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		json.Unmarshal(respBody, &finalStatus)

		if finalStatus.Status == StatusComplete {
			break
		}
	}

	if finalStatus.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", finalStatus.Status)
	}
}

func TestServerIntegrationWithConsoleOutput(t *testing.T) {
	// Full integration: create workflow -> poll for completion -> get console output
	// This mirrors the Python test_read_main flow.
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer(":0")

	request := PolicyEngineRequest{
		Inputs: map[string]interface{}{
			"repo_name": "scitt-community/scitt-api-emulator",
		},
		Workflow: `
name: Console Output Integration Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "Hello World"
    - run: echo "Integration test complete"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "scitt-community/scitt-api-emulator",
					"GITHUB_API":        "https://api.github.com/",
					"GITHUB_ACTOR":      "testuser",
					"GITHUB_ACTOR_ID":   "1234567",
				},
			},
		},
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/request/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create request failed: %d %s", resp.StatusCode, string(respBody))
	}

	var createStatus PolicyEngineStatus
	json.Unmarshal(respBody, &createStatus)

	if createStatus.Status != StatusSubmitted {
		t.Fatalf("expected status submitted, got %s", createStatus.Status)
	}

	detail := createStatus.Detail.(map[string]interface{})
	taskID := detail["id"].(string)

	// Poll for completion
	var finalStatus PolicyEngineStatus
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)

		req = httptest.NewRequest(http.MethodGet, "/request/status/"+taskID, nil)
		w = httptest.NewRecorder()
		server.mux.ServeHTTP(w, req)

		resp = w.Result()
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		json.Unmarshal(respBody, &finalStatus)
		if finalStatus.Status == StatusComplete {
			break
		}
	}

	if finalStatus.Status != StatusComplete {
		t.Fatalf("expected status complete, got %s", finalStatus.Status)
	}

	// Now get console output via the endpoint
	req = httptest.NewRequest(http.MethodGet, "/request/console_output/"+taskID, nil)
	w = httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	resp = w.Result()
	consoleBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("console output request failed: %d", resp.StatusCode)
	}

	consoleOutput := string(consoleBody)
	if !strings.Contains(consoleOutput, "Hello World") {
		t.Errorf("expected console output to contain 'Hello World', got: %s", consoleOutput)
	}
	if !strings.Contains(consoleOutput, "Integration test complete") {
		t.Errorf("expected console output to contain 'Integration test complete', got: %s", consoleOutput)
	}
}

func TestServerGitHubWebhookFullFlow(t *testing.T) {
	// Full flow: webhook -> poll for completion -> verify result
	// This mirrors the Python test_github_app_gidgethub_github_webhook flow.
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer(":0")

	event := GitHubWebhookEvent{
		After: "a1b70ee3b0343adc24e3b75314262e43f5c79cc2",
		Sender: &GitHubWebhookEventSender{
			Login: "pdxjohnny",
			WebhookWorkflow: `
name: Webhook Workflow Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "webhook executed successfully"
`,
		},
		Repository: &GitHubWebhookEventRepository{
			FullName: "pdxjohnny/scitt-api-emulator",
		},
	}

	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", "42")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook request failed: %d %s", resp.StatusCode, string(respBody))
	}

	var submitStatus PolicyEngineStatus
	json.Unmarshal(respBody, &submitStatus)

	if submitStatus.Status != StatusSubmitted {
		t.Fatalf("expected status submitted, got %s", submitStatus.Status)
	}

	submitDetail := submitStatus.Detail.(map[string]interface{})
	taskID := submitDetail["id"].(string)

	// Poll for completion
	var finalStatus PolicyEngineStatus
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)

		req = httptest.NewRequest(http.MethodGet, "/request/status/"+taskID, nil)
		w = httptest.NewRecorder()
		server.mux.ServeHTTP(w, req)

		resp = w.Result()
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		json.Unmarshal(respBody, &finalStatus)
		if finalStatus.Status == StatusComplete {
			break
		}
	}

	if finalStatus.Status != StatusComplete {
		t.Fatalf("expected status complete, got %s", finalStatus.Status)
	}

	// Verify the detail contains a successful exit status
	finalDetail, ok := finalStatus.Detail.(map[string]interface{})
	if !ok {
		t.Fatal("expected detail to be a map")
	}
	if finalDetail["exit_status"] != "success" {
		t.Errorf("expected exit_status success, got %v", finalDetail["exit_status"])
	}

	// Get console output
	req = httptest.NewRequest(http.MethodGet, "/request/console_output/"+taskID, nil)
	w = httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	resp = w.Result()
	consoleBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	consoleOutput := string(consoleBody)
	if !strings.Contains(consoleOutput, "webhook executed successfully") {
		t.Errorf("expected console output to contain 'webhook executed successfully', got: %s", consoleOutput)
	}
}

func TestServerConsoleOutputStreamEndpoint(t *testing.T) {
	server := NewServer(":0")

	// Create and complete a task with console output on the task object
	task := server.taskManager.CreateTask("stream-task")
	task.AppendConsoleOutput("line 1")
	task.AppendConsoleOutput("line 2")

	resultJSON, _ := json.Marshal(PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:         "stream-task",
			ExitStatus: ExitStatusSuccess,
		},
		ConsoleOutput: "line 1\nline 2",
	})
	server.taskManager.UpdateTask("stream-task", "SUCCESS", string(resultJSON), nil)

	req := httptest.NewRequest(http.MethodGet, "/request/console_output_stream/stream-task", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %s", resp.Header.Get("Content-Type"))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if !strings.Contains(bodyStr, "data: line 1") {
		t.Errorf("expected SSE data 'line 1' in response, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "data: line 2") {
		t.Errorf("expected SSE data 'line 2' in response, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "event: done") {
		t.Errorf("expected SSE 'done' event in response, got: %s", bodyStr)
	}
}

func TestServerWithMockGitHub(t *testing.T) {
	// Create mock GitHub server
	mockGH := NewMockGitHubServer()
	defer mockGH.Close()

	// Setup app and installation
	mockGH.SetupApp(12345, "test-app", "Test App")
	mockGH.AddInstallation(1, "testorg", "Organization")
	mockGH.AddRepository("testorg/testrepo", false)

	// Verify the mock server is working
	resp, err := http.Get(mockGH.URL + "/rate_limit")
	if err != nil {
		t.Fatalf("failed to connect to mock GitHub server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["resources"] == nil {
		t.Error("expected resources in response")
	}
}

func TestServerGitHubWebhookWithDefaultWorkflow(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer(":0")

	// Event without webhook_workflow - should use default
	event := GitHubWebhookEvent{
		After: "abc123",
		Sender: &GitHubWebhookEventSender{
			Login: "testuser",
		},
		Repository: &GitHubWebhookEventRepository{
			FullName: "owner/repo",
		},
	}

	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
}

func TestNewServer(t *testing.T) {
	server := NewServer("127.0.0.1:8080")

	if server.taskManager == nil {
		t.Error("taskManager should be initialized")
	}

	if server.mux == nil {
		t.Error("mux should be initialized")
	}

	if server.httpServer == nil {
		t.Error("httpServer should be initialized")
	}

	if server.httpServer.Addr != "127.0.0.1:8080" {
		t.Errorf("expected addr 127.0.0.1:8080, got %s", server.httpServer.Addr)
	}
}

func TestServerSendValidationError(t *testing.T) {
	server := NewServer(":0")

	w := httptest.NewRecorder()
	server.sendValidationError(w, "test message", &testError{message: "test error"})

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	var status PolicyEngineStatus
	json.NewDecoder(resp.Body).Decode(&status)

	if status.Status != StatusInputValidationError {
		t.Errorf("expected status input_validation_error, got %s", status.Status)
	}
}

func TestServerListenRandomPort(t *testing.T) {
	server := NewServer("127.0.0.1:0")

	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	boundAddr := server.BoundAddr()
	if boundAddr == "127.0.0.1:0" {
		t.Error("expected bound address to have a real port, got 127.0.0.1:0")
	}
	if !strings.HasPrefix(boundAddr, "127.0.0.1:") {
		t.Errorf("expected bound address to start with 127.0.0.1:, got %s", boundAddr)
	}
	t.Logf("bound to %s", boundAddr)
}

func TestServerPortFile(t *testing.T) {
	// Start server on random port, verify the bound address can be written to a file.
	server := NewServer("127.0.0.1:0")

	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	portFile := t.TempDir() + "/port"
	boundAddr := server.BoundAddr()
	if err := os.WriteFile(portFile, []byte(boundAddr), 0644); err != nil {
		t.Fatalf("failed to write port file: %v", err)
	}

	contents, err := os.ReadFile(portFile)
	if err != nil {
		t.Fatalf("failed to read port file: %v", err)
	}
	if string(contents) != boundAddr {
		t.Errorf("port file contents %q != bound addr %q", string(contents), boundAddr)
	}
}

func TestServerRandomPortEndToEnd(t *testing.T) {
	// Full flow: bind to :0, discover port, hit health endpoint via real HTTP.
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	server := NewServer("127.0.0.1:0")
	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	go server.Serve(ln)
	defer server.Shutdown(context.Background())

	endpoint := "http://" + server.BoundAddr()
	client := NewClient(endpoint, 5*time.Second)

	// Hit health endpoint
	resp, err := client.httpClient.Get(endpoint + "/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServerUnixSocket(t *testing.T) {
	sockPath := tempSockPath("pe-basic")
	defer os.Remove(sockPath)
	server := NewServer(sockPath)

	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen on unix socket failed: %v", err)
	}

	go server.Serve(ln)
	defer server.Shutdown(context.Background())

	boundAddr := server.BoundAddr()
	if !strings.HasPrefix(boundAddr, "unix:") {
		t.Errorf("expected bound addr to start with unix:, got %s", boundAddr)
	}

	// Connect via the client using unix: endpoint
	client := NewClient("unix:"+sockPath, 5*time.Second)
	resp, err := client.httpClient.Get("http://localhost/health")
	if err != nil {
		t.Fatalf("health check via unix socket failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %s", body["status"])
	}
}

func TestServerUnixSocketFullWorkflow(t *testing.T) {
	// Full end-to-end: unix socket server + client create + status + output.
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	// Use /tmp for short path (macOS has ~104 byte limit on socket paths).
	sockPath := tempSockPath("pe-wf")
	defer os.Remove(sockPath)
	server := NewServer(sockPath)

	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	go server.Serve(ln)
	defer server.Shutdown(context.Background())

	client := NewClient("unix:"+sockPath, 30*time.Second)
	ctx := context.Background()

	// Submit a workflow
	request := &PolicyEngineRequest{
		Workflow: `
name: Unix Socket Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "UNIX_SOCKET_WORKS=yes"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := client.CreateRequest(ctx, request)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	if status.Status != StatusSubmitted {
		t.Fatalf("expected status submitted, got %s", status.Status)
	}

	// Extract task ID
	detail, ok := status.Detail.(map[string]interface{})
	if !ok {
		t.Fatal("expected detail to be a map")
	}
	taskID := detail["id"].(string)

	// Wait for completion
	finalStatus, err := client.WaitForCompletion(ctx, taskID, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForCompletion failed: %v", err)
	}

	if finalStatus.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", finalStatus.Status)
	}

	// Get console output
	output, err := client.GetConsoleOutput(ctx, taskID)
	if err != nil {
		t.Fatalf("GetConsoleOutput failed: %v", err)
	}

	if !strings.Contains(output, "UNIX_SOCKET_WORKS=yes") {
		t.Errorf("expected 'UNIX_SOCKET_WORKS=yes' in output, got: %s", output)
	}
}

func TestServerUnixSocketWithPrefix(t *testing.T) {
	// Test unix:// prefix variant.
	sockPath := tempSockPath("pe-pfx")
	defer os.Remove(sockPath)
	server := NewServer("unix://" + sockPath)

	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	go server.Serve(ln)
	defer server.Shutdown(context.Background())

	client := NewClient("unix://"+sockPath, 5*time.Second)
	resp, err := client.httpClient.Get("http://localhost/health")
	if err != nil {
		t.Fatalf("health check via unix:// socket failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIsUnixSocket(t *testing.T) {
	tests := []struct {
		bind     string
		wantPath string
		wantOk   bool
	}{
		{"/tmp/pe.sock", "/tmp/pe.sock", true},
		{"unix:///tmp/pe.sock", "/tmp/pe.sock", true},
		{"unix:/tmp/pe.sock", "/tmp/pe.sock", true},
		{"127.0.0.1:8080", "", false},
		{":8080", "", false},
		{":0", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.bind, func(t *testing.T) {
			path, ok := isUnixSocket(tt.bind)
			if ok != tt.wantOk {
				t.Errorf("isUnixSocket(%q) ok = %v, want %v", tt.bind, ok, tt.wantOk)
			}
			if path != tt.wantPath {
				t.Errorf("isUnixSocket(%q) path = %q, want %q", tt.bind, path, tt.wantPath)
			}
		})
	}
}
