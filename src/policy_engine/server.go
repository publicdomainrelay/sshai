package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Server represents the policy engine HTTP server.
type Server struct {
	taskManager  *TaskManager
	httpServer   *http.Server
	mux          *http.ServeMux
	mu           sync.RWMutex
	shutdownChan chan struct{}
}

// NewServer creates a new policy engine server.
func NewServer(bind string) *Server {
	mux := http.NewServeMux()
	server := &Server{
		taskManager:  NewTaskManager(),
		mux:          mux,
		shutdownChan: make(chan struct{}),
		httpServer: &http.Server{
			Addr:    bind,
			Handler: mux,
		},
	}

	// Register routes
	mux.HandleFunc("/request/create", server.handleRequestCreate)
	mux.HandleFunc("/request/status/", server.handleRequestStatus)
	mux.HandleFunc("/request/console_output/", server.handleRequestConsoleOutput)
	mux.HandleFunc("/webhook/github", server.handleGitHubWebhook)
	mux.HandleFunc("/rate_limit", server.handleRateLimit)
	mux.HandleFunc("/health", server.handleHealth)

	return server
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	log.Printf("Starting policy engine API server on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.shutdownChan)
	return s.httpServer.Shutdown(ctx)
}

// handleHealth handles health check requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleRateLimit handles rate limit requests (for GitHub API compatibility).
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"resources": map[string]interface{}{
			"core": map[string]int{
				"limit":     5000,
				"remaining": 4999,
				"reset":     int(time.Now().Add(time.Hour).Unix()),
			},
		},
	})
}

// handleRequestCreate handles POST /request/create.
func (s *Server) handleRequestCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendValidationError(w, "Failed to read request body", err)
		return
	}
	defer r.Body.Close()

	var request PolicyEngineRequest
	if err := json.Unmarshal(body, &request); err != nil {
		s.sendValidationError(w, "Failed to parse request JSON", err)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		s.sendValidationError(w, "Invalid request", err)
		return
	}

	// Create task
	taskID := uuid.New().String()
	task := s.taskManager.CreateTask(taskID)

	// Execute workflow asynchronously
	go s.executeWorkflowTask(task, &request)

	// Return submitted status
	response := PolicyEngineStatus{
		Status: StatusSubmitted,
		Detail: PolicyEngineSubmitted{
			ID: taskID,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRequestStatus handles GET /request/status/{request_id}.
func (s *Server) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract request ID from path
	path := strings.TrimPrefix(r.URL.Path, "/request/status/")
	requestID := strings.TrimSuffix(path, "/")

	if requestID == "" {
		http.Error(w, "Request ID is required", http.StatusBadRequest)
		return
	}

	task, ok := s.taskManager.GetTask(requestID)
	if !ok {
		// Return unknown status
		response := PolicyEngineStatus{
			Status: StatusUnknown,
			Detail: PolicyEngineUnknown{
				ID: requestID,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	var response PolicyEngineStatus

	switch task.Status {
	case "PENDING":
		response = PolicyEngineStatus{
			Status: StatusInProgress,
			Detail: PolicyEngineInProgress{
				ID:            requestID,
				StatusUpdates: make(map[string]PolicyEngineStatusUpdateJob),
			},
		}
	case "SUCCESS", "FAILURE":
		// Parse the result
		var result PolicyEngineStatus
		if err := json.Unmarshal([]byte(task.Result), &result); err != nil {
			// Return a generic complete status if parsing fails
			exitStatus := ExitStatusSuccess
			if task.Status == "FAILURE" {
				exitStatus = ExitStatusFailure
			}
			response = PolicyEngineStatus{
				Status: StatusComplete,
				Detail: PolicyEngineComplete{
					ID:         requestID,
					ExitStatus: exitStatus,
				},
			}
		} else {
			response = result
			// Update the ID in detail
			if detail, ok := response.Detail.(map[string]interface{}); ok {
				detail["id"] = requestID
			}
		}
	default:
		response = PolicyEngineStatus{
			Status: StatusUnknown,
			Detail: PolicyEngineUnknown{
				ID: requestID,
			},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRequestConsoleOutput handles GET /request/console_output/{request_id}.
func (s *Server) handleRequestConsoleOutput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract request ID from path
	path := strings.TrimPrefix(r.URL.Path, "/request/console_output/")
	requestID := strings.TrimSuffix(path, "/")

	if requestID == "" {
		http.Error(w, "Request ID is required", http.StatusBadRequest)
		return
	}

	task, ok := s.taskManager.GetTask(requestID)
	if !ok {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	if task.Status != "SUCCESS" && task.Status != "FAILURE" {
		http.Error(w, "Task not complete", http.StatusNoContent)
		return
	}

	// Parse the result to get console output
	var result PolicyEngineStatus
	if err := json.Unmarshal([]byte(task.Result), &result); err != nil {
		http.Error(w, "Failed to parse result", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(result.ConsoleOutput))
}

// handleGitHubWebhook handles POST /webhook/github.
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get event type from header
	eventType := r.Header.Get("X-GitHub-Event")
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	// Only handle push and pull_request events
	if eventType != "push" && eventType != "pull_request" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Event type not supported"})
		return
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendValidationError(w, "Failed to read request body", err)
		return
	}
	defer r.Body.Close()

	var event GitHubWebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		s.sendValidationError(w, "Failed to parse webhook event", err)
		return
	}

	// Build request from webhook event
	workflow := event.Sender.WebhookWorkflow
	if workflow == "" {
		// Use default workflow
		workflow = `
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
`
	}

	request := PolicyEngineRequest{
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_ACTOR":      event.Sender.Login,
					"GITHUB_REPOSITORY": event.Repository.FullName,
				},
			},
		},
		Workflow: workflow,
	}

	// Create task
	taskID := deliveryID
	if taskID == "" {
		taskID = uuid.New().String()
	}
	task := s.taskManager.CreateTask(taskID)

	// Execute workflow asynchronously
	go s.executeWorkflowTask(task, &request)

	// Return submitted status
	response := PolicyEngineStatus{
		Status: StatusSubmitted,
		Detail: PolicyEngineSubmitted{
			ID: taskID,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// executeWorkflowTask executes a workflow as an async task.
func (s *Server) executeWorkflowTask(task *Task, request *PolicyEngineRequest) {
	ctx := context.Background()

	executor := NewWorkflowExecutor()
	status, err := executor.ExecuteWorkflow(ctx, request)

	if err != nil {
		s.taskManager.UpdateTask(task.ID, "FAILURE", "", err)
		return
	}

	// Serialize the status
	resultJSON, err := json.Marshal(status)
	if err != nil {
		s.taskManager.UpdateTask(task.ID, "FAILURE", "", err)
		return
	}

	taskStatus := "SUCCESS"
	if detail, ok := status.Detail.(PolicyEngineComplete); ok {
		if detail.ExitStatus == ExitStatusFailure {
			taskStatus = "FAILURE"
		}
	}

	s.taskManager.UpdateTask(task.ID, taskStatus, string(resultJSON), nil)
}

// sendValidationError sends a validation error response.
func (s *Server) sendValidationError(w http.ResponseWriter, msg string, err error) {
	response := PolicyEngineStatus{
		Status: StatusInputValidationError,
		Detail: []PolicyEngineInputValidationError{
			{
				Msg:  fmt.Sprintf("%s: %v", msg, err),
				Loc:  []string{"body"},
				Type: "value_error",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)
}

// CORSMiddleware adds CORS headers to responses.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs incoming requests.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("%s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}
