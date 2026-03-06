package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Client represents a policy engine API client.
type Client struct {
	endpoint   string
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new policy engine client.
// The endpoint can be an HTTP URL (http://host:port) or a Unix socket
// path prefixed with "unix:" or "unix://", e.g. "unix:///tmp/pe.sock"
// or "unix:/tmp/pe.sock".
func NewClient(endpoint string, timeout time.Duration) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	// Normalise the endpoint for unix sockets.
	resolvedEndpoint := endpoint
	if sockPath, ok := parseUnixEndpoint(endpoint); ok {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", sockPath, timeout)
		}
		// When using a unix socket the HTTP host is irrelevant; use a
		// placeholder so http.Client builds valid URLs.
		resolvedEndpoint = "http://localhost"
	}

	return &Client{
		endpoint: resolvedEndpoint,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		timeout: timeout,
	}
}

// parseUnixEndpoint returns the socket path if endpoint is a unix socket
// reference ("unix:///path", "unix:/path"), and false otherwise.
func parseUnixEndpoint(endpoint string) (string, bool) {
	if strings.HasPrefix(endpoint, "unix://") {
		return strings.TrimPrefix(endpoint, "unix://"), true
	}
	if strings.HasPrefix(endpoint, "unix:") {
		return strings.TrimPrefix(endpoint, "unix:"), true
	}
	return "", false
}

// CreateRequest sends a workflow execution request to the policy engine.
func (c *Client) CreateRequest(ctx context.Context, request *PolicyEngineRequest) (*PolicyEngineStatus, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/request/create", c.endpoint)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var status PolicyEngineStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &status, nil
}

// GetStatus retrieves the status of a workflow execution request.
func (c *Client) GetStatus(ctx context.Context, taskID string) (*PolicyEngineStatus, error) {
	url := fmt.Sprintf("%s/request/status/%s", c.endpoint, taskID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var status PolicyEngineStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &status, nil
}

// GetConsoleOutput retrieves the console output of a completed workflow.
func (c *Client) GetConsoleOutput(ctx context.Context, taskID string) (string, error) {
	url := fmt.Sprintf("%s/request/console_output/%s", c.endpoint, taskID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// StreamConsoleOutput streams console output from the SSE endpoint to the given writer.
func (c *Client) StreamConsoleOutput(ctx context.Context, taskID string, w io.Writer) error {
	url := fmt.Sprintf("%s/request/console_output_stream/%s", c.endpoint, taskID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read SSE stream
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// Process complete SSE messages
			for {
				idx := bytes.Index(buf, []byte("\n\n"))
				if idx < 0 {
					break
				}
				message := string(buf[:idx])
				buf = buf[idx+2:]

				// Parse SSE message
				for _, line := range strings.Split(message, "\n") {
					if strings.HasPrefix(line, "event: done") {
						return nil
					}
					if strings.HasPrefix(line, "data: ") {
						data := strings.TrimPrefix(line, "data: ")
						fmt.Fprintln(w, data)
					}
					// Ignore comments (keepalive)
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

// WaitForCompletion polls for status until the task is complete.
func (c *Client) WaitForCompletion(ctx context.Context, taskID string, pollInterval time.Duration) (*PolicyEngineStatus, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		status, err := c.GetStatus(ctx, taskID)
		if err != nil {
			return nil, err
		}

		if status.Status != StatusInProgress {
			return status, nil
		}

		time.Sleep(pollInterval)
	}
}

// LoadWorkflowFromFile loads a workflow from a YAML file.
func LoadWorkflowFromFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file: %w", err)
	}

	var workflow interface{}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, fmt.Errorf("failed to parse workflow YAML: %w", err)
	}

	return workflow, nil
}

// FormatOutput formats the output for display.
func FormatOutput(data interface{}, format string) (string, error) {
	switch format {
	case "json":
		output, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return string(output), nil
	case "yaml":
		output, err := yaml.Marshal(data)
		if err != nil {
			return "", fmt.Errorf("failed to marshal YAML: %w", err)
		}
		return string(output), nil
	default:
		return "", fmt.Errorf("unsupported output format: %s", format)
	}
}
