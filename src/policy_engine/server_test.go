package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

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

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", resp.StatusCode)
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
