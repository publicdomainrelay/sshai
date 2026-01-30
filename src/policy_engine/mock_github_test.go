package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MockGitHubServer provides a minimal GitHub API implementation for testing.
type MockGitHubServer struct {
	*httptest.Server
	mu sync.RWMutex

	// Configured data
	App           *MockGitHubApp
	Installations []*MockGitHubInstallation
	Repositories  map[string]*MockGitHubRepository
	CheckRuns     map[int64]*MockGitHubCheckRun
	Statuses      map[string][]*MockGitHubStatus
	Comments      map[string][]*MockGitHubComment

	// Request tracking for assertions
	Requests []*MockGitHubRequest

	// Counters
	nextCheckRunID int64
	nextStatusID   int64
	nextCommentID  int64
}

// MockGitHubApp represents a GitHub App configuration.
type MockGitHubApp struct {
	ID         int64
	Slug       string
	Name       string
	PrivateKey *rsa.PrivateKey
}

// MockGitHubInstallation represents a GitHub App installation.
type MockGitHubInstallation struct {
	ID          int64
	Account     MockGitHubAccount
	AccessToken string
	ExpiresAt   time.Time
}

// MockGitHubAccount represents a GitHub account (user or org).
type MockGitHubAccount struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

// MockGitHubRepository represents a GitHub repository.
type MockGitHubRepository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Owner    MockGitHubAccount `json:"owner"`
	Private  bool   `json:"private"`
}

// MockGitHubCheckRun represents a GitHub check run.
type MockGitHubCheckRun struct {
	ID          int64                  `json:"id"`
	Name        string                 `json:"name"`
	HeadSHA     string                 `json:"head_sha"`
	Status      string                 `json:"status"`
	Conclusion  string                 `json:"conclusion,omitempty"`
	StartedAt   string                 `json:"started_at,omitempty"`
	CompletedAt string                 `json:"completed_at,omitempty"`
	ExternalID  string                 `json:"external_id,omitempty"`
	Output      map[string]interface{} `json:"output,omitempty"`
}

// MockGitHubStatus represents a GitHub commit status.
type MockGitHubStatus struct {
	ID          int64  `json:"id"`
	State       string `json:"state"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	Context     string `json:"context"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// MockGitHubComment represents a GitHub commit comment.
type MockGitHubComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	CommitID  string `json:"commit_id"`
	CreatedAt string `json:"created_at"`
}

// MockGitHubRequest tracks a request made to the mock server.
type MockGitHubRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    string
}

// NewMockGitHubServer creates a new mock GitHub server.
func NewMockGitHubServer() *MockGitHubServer {
	mock := &MockGitHubServer{
		Repositories:   make(map[string]*MockGitHubRepository),
		CheckRuns:      make(map[int64]*MockGitHubCheckRun),
		Statuses:       make(map[string][]*MockGitHubStatus),
		Comments:       make(map[string][]*MockGitHubComment),
		Requests:       make([]*MockGitHubRequest, 0),
		nextCheckRunID: 1,
		nextStatusID:   1,
		nextCommentID:  1,
	}

	mux := http.NewServeMux()
	mock.setupRoutes(mux)
	mock.Server = httptest.NewServer(mux)

	return mock
}

// setupRoutes configures all the mock API routes.
func (m *MockGitHubServer) setupRoutes(mux *http.ServeMux) {
	// App endpoints
	mux.HandleFunc("/app", m.handleApp)
	mux.HandleFunc("/app/installations", m.handleAppInstallations)
	mux.HandleFunc("/app/installations/", m.handleAppInstallationAccess)

	// Rate limit
	mux.HandleFunc("/rate_limit", m.handleRateLimit)

	// Repository endpoints
	mux.HandleFunc("/repos/", m.handleRepos)
}

// handleApp returns app information.
func (m *MockGitHubServer) handleApp(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	if m.App == nil {
		http.Error(w, "App not configured", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":   m.App.ID,
		"slug": m.App.Slug,
		"name": m.App.Name,
	})
}

// handleAppInstallations returns list of app installations.
func (m *MockGitHubServer) handleAppInstallations(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	installations := make([]map[string]interface{}, 0)
	for _, inst := range m.Installations {
		installations = append(installations, map[string]interface{}{
			"id":      inst.ID,
			"account": inst.Account,
		})
	}

	json.NewEncoder(w).Encode(installations)
}

// handleAppInstallationAccess handles installation access token requests.
func (m *MockGitHubServer) handleAppInstallationAccess(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	// Extract installation ID from path: /app/installations/{id}/access_tokens
	path := r.URL.Path
	if !strings.HasSuffix(path, "/access_tokens") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	instIDStr := parts[3]
	instID, err := strconv.ParseInt(instIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid installation ID", http.StatusBadRequest)
		return
	}

	// Find installation
	var installation *MockGitHubInstallation
	for _, inst := range m.Installations {
		if inst.ID == instID {
			installation = inst
			break
		}
	}

	if installation == nil {
		http.Error(w, "Installation not found", http.StatusNotFound)
		return
	}

	// Generate access token
	token := fmt.Sprintf("ghs_mock_token_%d_%d", instID, time.Now().UnixNano())
	expiresAt := time.Now().Add(time.Hour)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

// handleRateLimit returns rate limit information.
func (m *MockGitHubServer) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"resources": map[string]interface{}{
			"core": map[string]interface{}{
				"limit":     5000,
				"remaining": 4999,
				"reset":     time.Now().Add(time.Hour).Unix(),
			},
		},
	})
}

// handleRepos handles repository-related endpoints.
func (m *MockGitHubServer) handleRepos(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	path := strings.TrimPrefix(r.URL.Path, "/repos/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 {
		http.Error(w, "Invalid repository path", http.StatusBadRequest)
		return
	}

	repoFullName := parts[0] + "/" + parts[1]
	action := ""
	if len(parts) > 2 {
		action = parts[2]
	}

	switch action {
	case "check-runs":
		m.handleCheckRuns(w, r, repoFullName)
	case "statuses":
		if len(parts) > 3 {
			m.handleStatuses(w, r, repoFullName, parts[3])
		} else {
			http.Error(w, "SHA required", http.StatusBadRequest)
		}
	case "commits":
		if len(parts) > 4 && parts[4] == "comments" {
			m.handleCommitComments(w, r, repoFullName, parts[3])
		} else {
			http.Error(w, "Not found", http.StatusNotFound)
		}
	case "contents":
		if len(parts) > 3 {
			m.handleContents(w, r, repoFullName, strings.Join(parts[3:], "/"))
		} else {
			http.Error(w, "Path required", http.StatusBadRequest)
		}
	case "zipball", "tarball":
		m.handleArchive(w, r, repoFullName, action)
	default:
		// Return repository info
		m.handleRepository(w, r, repoFullName)
	}
}

// handleRepository returns repository information.
func (m *MockGitHubServer) handleRepository(w http.ResponseWriter, r *http.Request, repoFullName string) {
	m.mu.RLock()
	repo, ok := m.Repositories[repoFullName]
	m.mu.RUnlock()

	if !ok {
		// Return a default repo
		parts := strings.Split(repoFullName, "/")
		repo = &MockGitHubRepository{
			ID:       1,
			FullName: repoFullName,
			Name:     parts[1],
			Owner: MockGitHubAccount{
				ID:    1,
				Login: parts[0],
				Type:  "Organization",
			},
		}
	}

	json.NewEncoder(w).Encode(repo)
}

// handleCheckRuns handles check run endpoints.
func (m *MockGitHubServer) handleCheckRuns(w http.ResponseWriter, r *http.Request, repoFullName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodPost:
		// Create check run
		var req struct {
			Name       string                 `json:"name"`
			HeadSHA    string                 `json:"head_sha"`
			Status     string                 `json:"status"`
			ExternalID string                 `json:"external_id"`
			StartedAt  string                 `json:"started_at"`
			Output     map[string]interface{} `json:"output"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		checkRun := &MockGitHubCheckRun{
			ID:         m.nextCheckRunID,
			Name:       req.Name,
			HeadSHA:    req.HeadSHA,
			Status:     req.Status,
			ExternalID: req.ExternalID,
			StartedAt:  req.StartedAt,
			Output:     req.Output,
		}
		m.CheckRuns[m.nextCheckRunID] = checkRun
		m.nextCheckRunID++

		json.NewEncoder(w).Encode(checkRun)

	case http.MethodPatch:
		// Update check run - extract ID from path
		path := r.URL.Path
		parts := strings.Split(path, "/")
		if len(parts) < 5 {
			http.Error(w, "Check run ID required", http.StatusBadRequest)
			return
		}
		checkRunID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
		if err != nil {
			http.Error(w, "Invalid check run ID", http.StatusBadRequest)
			return
		}

		checkRun, ok := m.CheckRuns[checkRunID]
		if !ok {
			http.Error(w, "Check run not found", http.StatusNotFound)
			return
		}

		var req struct {
			Name        string                 `json:"name"`
			Status      string                 `json:"status"`
			Conclusion  string                 `json:"conclusion"`
			CompletedAt string                 `json:"completed_at"`
			Output      map[string]interface{} `json:"output"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Name != "" {
			checkRun.Name = req.Name
		}
		if req.Status != "" {
			checkRun.Status = req.Status
		}
		if req.Conclusion != "" {
			checkRun.Conclusion = req.Conclusion
		}
		if req.CompletedAt != "" {
			checkRun.CompletedAt = req.CompletedAt
		}
		if req.Output != nil {
			checkRun.Output = req.Output
		}

		json.NewEncoder(w).Encode(checkRun)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStatuses handles commit status endpoints.
func (m *MockGitHubServer) handleStatuses(w http.ResponseWriter, r *http.Request, repoFullName, sha string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := repoFullName + "/" + sha

	switch r.Method {
	case http.MethodPost:
		var req struct {
			State       string `json:"state"`
			TargetURL   string `json:"target_url"`
			Description string `json:"description"`
			Context     string `json:"context"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		now := time.Now().Format(time.RFC3339)
		status := &MockGitHubStatus{
			ID:          m.nextStatusID,
			State:       req.State,
			TargetURL:   req.TargetURL,
			Description: req.Description,
			Context:     req.Context,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		m.Statuses[key] = append(m.Statuses[key], status)
		m.nextStatusID++

		json.NewEncoder(w).Encode(status)

	case http.MethodGet:
		statuses := m.Statuses[key]
		if statuses == nil {
			statuses = make([]*MockGitHubStatus, 0)
		}
		json.NewEncoder(w).Encode(statuses)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCommitComments handles commit comment endpoints.
func (m *MockGitHubServer) handleCommitComments(w http.ResponseWriter, r *http.Request, repoFullName, sha string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := repoFullName + "/" + sha

	switch r.Method {
	case http.MethodPost:
		var req struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		comment := &MockGitHubComment{
			ID:        m.nextCommentID,
			Body:      req.Body,
			CommitID:  sha,
			CreatedAt: time.Now().Format(time.RFC3339),
		}
		m.Comments[key] = append(m.Comments[key], comment)
		m.nextCommentID++

		json.NewEncoder(w).Encode(comment)

	case http.MethodGet:
		comments := m.Comments[key]
		if comments == nil {
			comments = make([]*MockGitHubComment, 0)
		}
		json.NewEncoder(w).Encode(comments)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleContents handles repository content endpoints.
func (m *MockGitHubServer) handleContents(w http.ResponseWriter, r *http.Request, repoFullName, path string) {
	// Return a mock action.yml for action downloads
	if strings.HasSuffix(path, "action.yml") || strings.HasSuffix(path, "action.yaml") {
		content := `name: Mock Action
description: A mock action for testing
runs:
  using: composite
  steps:
  - run: echo "Mock action executed"
    shell: bash
`
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":     "file",
			"encoding": "base64",
			"content":  content,
			"name":     "action.yml",
			"path":     path,
		})
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleArchive handles archive download endpoints.
func (m *MockGitHubServer) handleArchive(w http.ResponseWriter, r *http.Request, repoFullName, archiveType string) {
	// This would normally redirect to the actual archive
	// For testing, we just return a minimal response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("mock archive content"))
}

// recordRequest records a request for later assertions.
func (m *MockGitHubServer) recordRequest(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req := &MockGitHubRequest{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header.Clone(),
	}
	m.Requests = append(m.Requests, req)
}

// GetRequests returns all recorded requests.
func (m *MockGitHubServer) GetRequests() []*MockGitHubRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Requests
}

// GetCheckRuns returns all check runs.
func (m *MockGitHubServer) GetCheckRuns() map[int64]*MockGitHubCheckRun {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.CheckRuns
}

// GetStatuses returns statuses for a repo/sha.
func (m *MockGitHubServer) GetStatuses(repoFullName, sha string) []*MockGitHubStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Statuses[repoFullName+"/"+sha]
}

// SetupApp configures the mock GitHub App.
func (m *MockGitHubServer) SetupApp(appID int64, slug, name string) error {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	m.App = &MockGitHubApp{
		ID:         appID,
		Slug:       slug,
		Name:       name,
		PrivateKey: privateKey,
	}

	return nil
}

// GetPrivateKeyPEM returns the app's private key in PEM format.
func (m *MockGitHubServer) GetPrivateKeyPEM() string {
	if m.App == nil || m.App.PrivateKey == nil {
		return ""
	}

	privDER := x509.MarshalPKCS1PrivateKey(m.App.PrivateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})
	return string(privPEM)
}

// AddInstallation adds an installation to the mock server.
func (m *MockGitHubServer) AddInstallation(id int64, login, accountType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Installations = append(m.Installations, &MockGitHubInstallation{
		ID: id,
		Account: MockGitHubAccount{
			ID:    id,
			Login: login,
			Type:  accountType,
		},
	})
}

// AddRepository adds a repository to the mock server.
func (m *MockGitHubServer) AddRepository(fullName string, private bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	parts := strings.Split(fullName, "/")
	m.Repositories[fullName] = &MockGitHubRepository{
		ID:       int64(len(m.Repositories) + 1),
		FullName: fullName,
		Name:     parts[1],
		Owner: MockGitHubAccount{
			ID:    1,
			Login: parts[0],
			Type:  "Organization",
		},
		Private: private,
	}
}

// Reset clears all recorded data.
func (m *MockGitHubServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Requests = make([]*MockGitHubRequest, 0)
	m.CheckRuns = make(map[int64]*MockGitHubCheckRun)
	m.Statuses = make(map[string][]*MockGitHubStatus)
	m.Comments = make(map[string][]*MockGitHubComment)
	m.nextCheckRunID = 1
	m.nextStatusID = 1
	m.nextCommentID = 1
}
