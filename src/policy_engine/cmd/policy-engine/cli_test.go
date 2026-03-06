package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"policy_engine/common"
)

func TestCLIClientCreate(t *testing.T) {
	client := common.NewClient("http://localhost:8080", 30*time.Second)

	workflow := "name: Test CLI\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo hello"
	request := &common.PolicyEngineRequest{
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

	if status != nil && status.Status != common.StatusSubmitted {
		t.Errorf("expected status submitted, got %s", status.Status)
	}

	// Check that detail has ID if we got a response
	if status != nil {
		detail, ok := status.Detail.(common.PolicyEngineSubmitted)
		if ok && detail.ID == "" {
			t.Error("expected non-empty task ID")
		}
	}
}

func TestCLIClientStatus(t *testing.T) {
	client := common.NewClient("http://localhost:8080", 30*time.Second)

	// Test with non-existent task ID
	ctx := context.Background()
	status, err := client.GetStatus(ctx, "non-existent-task")
	// Expect connection error since no server is running
	if err == nil {
		t.Error("expected connection error")
		return
	}

	if status != nil && status.Status != common.StatusUnknown {
		t.Errorf("expected status unknown, got %s", status.Status)
	}
}

func TestCLIClientConsoleOutput(t *testing.T) {
	client := common.NewClient("http://localhost:8080", 30*time.Second)

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
	_, err := common.LoadWorkflowFromFile("non-existent.yml")
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
	workflow, err := common.LoadWorkflowFromFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse workflow file: %v", err)
	}

	if workflow == nil {
		t.Error("expected workflow to be parsed")
	}
}

func TestCLIFormatOutput(t *testing.T) {
	status := &common.PolicyEngineStatus{
		Status: common.StatusComplete,
		Detail: common.PolicyEngineComplete{
			ID:         "test-id",
			ExitStatus: common.ExitStatusSuccess,
		},
		ConsoleOutput: "test output",
	}

	// Test JSON format
	jsonOutput, err := common.FormatOutput(status, "json")
	if err != nil {
		t.Fatalf("failed to format as JSON: %v", err)
	}

	var parsedStatus common.PolicyEngineStatus
	if err := json.Unmarshal([]byte(jsonOutput), &parsedStatus); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if parsedStatus.Status != status.Status {
		t.Error("JSON output should preserve status")
	}

	// Test YAML format
	yamlOutput, err := common.FormatOutput(status, "yaml")
	if err != nil {
		t.Fatalf("failed to format as YAML: %v", err)
	}

	if yamlOutput == "" {
		t.Error("YAML output should not be empty")
	}

	// Test invalid format
	_, err = common.FormatOutput(status, "invalid")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestCLIClientOutputCommand(t *testing.T) {
	client := common.NewClient("http://localhost:8080", 30*time.Second)

	// Test with non-existent task ID
	ctx := context.Background()
	_, err := client.GetConsoleOutput(ctx, "non-existent-task")
	// Expect connection error since no server is running
	if err == nil {
		t.Error("expected connection error")
		return
	}
}

func TestCLIClientStreamOutput(t *testing.T) {
	client := common.NewClient("http://localhost:8080", 1*time.Second)

	// Test with non-existent server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var buf bytes.Buffer
	err := client.StreamConsoleOutput(ctx, "non-existent-task", &buf)
	// Expect connection error since no server is running
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestCLIWaitForCompletion(t *testing.T) {
	client := common.NewClient("http://localhost:8080", 1*time.Second)

	// This should timeout for non-existent task
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.WaitForCompletion(ctx, "non-existent-task", 100*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
}

// buildTestBinary compiles the policy_engine binary into a temp directory
// and returns its absolute path.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "policy_engine")
	// Build from module root so the package path resolves correctly.
	modRoot := filepath.Join("..", "..")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/policy-engine/")
	cmd.Dir = modRoot
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}
	return binPath
}

// extractHelpExample returns the lines between startMarker and endMarker from
// rootCmd.Long, with the 2-space indent that the help text uses for example
// blocks stripped. Markers are matched as prefixes after trimming whitespace.
// The startMarker line IS included; the endMarker line is NOT.
func extractHelpExample(t *testing.T, startMarker, endMarker string) string {
	t.Helper()
	lines := strings.Split(rootCmd.Long, "\n")
	var out []string
	capturing := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !capturing {
			if strings.HasPrefix(trimmed, startMarker) {
				capturing = true
				out = append(out, strings.TrimPrefix(line, "  "))
			}
			continue
		}
		if endMarker != "" && strings.HasPrefix(trimmed, endMarker) {
			break
		}
		out = append(out, strings.TrimPrefix(line, "  "))
	}
	if len(out) == 0 {
		t.Fatalf("extractHelpExample: no lines between %q and %q", startMarker, endMarker)
	}
	return strings.Join(out, "\n")
}

// TestIntegrationCLIHelpExample pulls the TCP example directly from
// rootCmd.Long (the same variable backing --help), executes it as a bash
// script, and verifies the workflow ran to completion.
// If the help text and the actual CLI diverge, this test breaks.
func TestIntegrationCLIHelpExample(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	for _, dep := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(dep); err != nil {
			t.Skipf("%s not available", dep)
		}
	}

	bin := buildTestBinary(t)
	workDir := t.TempDir()

	// Pull the TCP example straight from the help variable.
	example := extractHelpExample(t, "# 1.", "Unix socket example")
	t.Logf("extracted TCP example:\n%s", example)

	// Replace the binary name with the built test binary.
	example = strings.ReplaceAll(example, "policy_engine", bin)

	// Build a runnable script.
	script := fmt.Sprintf("set -euo pipefail\ncd %q\n\n%s\n", workDir, example)

	// Inject process cleanup after the backgrounded server.
	script = strings.Replace(script,
		"--port-file .port &\n",
		"--port-file .port &\nPE_PID=$!\ntrap \"kill $PE_PID 2>/dev/null; wait $PE_PID 2>/dev/null\" EXIT\n",
		1)

	// Add a bounded timeout to the wait loop so the test can't hang.
	script = strings.Replace(script,
		"while [ ! -s .port ]; do sleep 0.1; done",
		"i=0; while [ ! -s .port ]; do sleep 0.1; i=$((i+1)); if [ \"$i\" -gt 100 ]; then echo TIMEOUT >&2; exit 1; fi; done",
		1)

	t.Logf("final script:\n%s", script)

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = workDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("script failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	out := stdout.String()
	t.Logf("stdout:\n%s", out)

	combined := out + stderr.String()

	if !strings.Contains(combined, "Hello from the policy engine!") {
		t.Errorf("expected 'Hello from the policy engine!' in output")
	}
	if !strings.Contains(combined, "Output from previous step:") {
		t.Errorf("expected 'Output from previous step:' in output")
	}
	// Last command is --output-format yaml, so stdout should contain YAML status.
	if !strings.Contains(out, "status: complete") || !strings.Contains(out, "exit_status: success") {
		// Also accept JSON from the earlier --wait call.
		if !strings.Contains(out, `"status":"complete"`) && !strings.Contains(out, `"status": "complete"`) {
			t.Errorf("expected completion status in stdout:\n%s", out)
		}
	}
}

// TestIntegrationCLIUnixSocketExample pulls the Unix socket example directly
// from rootCmd.Long, creates the workflow file from the TCP example's heredoc,
// executes the script, and verifies the workflow ran to completion.
func TestIntegrationCLIUnixSocketExample(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	for _, dep := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(dep); err != nil {
			t.Skipf("%s not available", dep)
		}
	}

	bin := buildTestBinary(t)
	workDir := t.TempDir()

	// The Unix example references my_workflow.yml which is created in the
	// TCP example's heredoc. Extract it from rootCmd.Long.
	tcpExample := extractHelpExample(t, "# 1.", "Unix socket example")
	heredocStart := strings.Index(tcpExample, "<<'EOF'\n")
	heredocEnd := strings.Index(tcpExample, "\nEOF")
	if heredocStart < 0 || heredocEnd < 0 {
		t.Fatalf("could not find workflow heredoc in TCP example:\n%s", tcpExample)
	}
	workflowYAML := tcpExample[heredocStart+len("<<'EOF'\n") : heredocEnd]
	if err := os.WriteFile(filepath.Join(workDir, "my_workflow.yml"), []byte(workflowYAML), 0644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	// Pull the Unix socket example.
	example := extractHelpExample(t, "# Start on a Unix socket", "You can also use")
	t.Logf("extracted unix example:\n%s", example)

	// Replace binary name and randomize the socket path.
	example = strings.ReplaceAll(example, "policy_engine", bin)
	sockPath := fmt.Sprintf("/tmp/pe-cli-%d.sock", rand.Int63())
	example = strings.ReplaceAll(example, "/tmp/pe.sock", sockPath)

	script := fmt.Sprintf("set -euo pipefail\ncd %q\n\n%s\n", workDir, example)

	script = strings.Replace(script,
		"--port-file .port &\n",
		fmt.Sprintf("--port-file .port &\nPE_PID=$!\ntrap \"kill $PE_PID 2>/dev/null; wait $PE_PID 2>/dev/null; rm -f %s\" EXIT\n", sockPath),
		1)

	script = strings.Replace(script,
		"while [ ! -s .port ]; do sleep 0.1; done",
		"i=0; while [ ! -s .port ]; do sleep 0.1; i=$((i+1)); if [ \"$i\" -gt 100 ]; then echo TIMEOUT >&2; exit 1; fi; done",
		1)

	t.Logf("final script:\n%s", script)

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = workDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("script failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	out := stdout.String()
	t.Logf("stdout:\n%s", out)

	combined := out + stderr.String()

	if !strings.Contains(combined, "Hello from the policy engine!") {
		t.Errorf("expected 'Hello from the policy engine!' in output")
	}
	if !strings.Contains(combined, "Output from previous step:") {
		t.Errorf("expected 'Output from previous step:' in output")
	}
}
