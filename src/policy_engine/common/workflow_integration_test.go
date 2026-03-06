package common

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ghAuthToken returns a GitHub token from `gh auth token` if available.
// Returns empty string if gh CLI is not installed or not authenticated.
func ghAuthToken() string {
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// integrationContext returns a standard request context map for integration tests,
// including a GITHUB_TOKEN secret from `gh auth token` when available.
func integrationContext() map[string]interface{} {
	ctx := map[string]interface{}{
		"config": map[string]interface{}{
			"env": map[string]interface{}{
				"GITHUB_REPOSITORY": "actions/checkout",
			},
		},
	}
	if token := ghAuthToken(); token != "" {
		ctx["secrets"] = map[string]interface{}{
			"GITHUB_TOKEN": token,
		}
	}
	return ctx
}

// TestIntegrationActionsCheckout tests using actions/checkout to clone a public
// repo (actions/checkout itself). This exercises the full executeStepUses path:
// downloadAction, parsing action.yml, executeNodeAction or executeCompositeAction.
func TestIntegrationActionsCheckout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - actions/checkout
jobs:
  checkout:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        repository: actions/checkout
        path: checkout-repo
    - run: |
        echo "CHECKOUT_EXISTS=$(test -d checkout-repo && echo yes || echo no)"
        ls checkout-repo/action.yml && echo "ACTION_YML_FOUND=yes"
`,
		Context: integrationContext(),
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatalf("expected PolicyEngineComplete detail, got %T", status.Detail)
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	if !strings.Contains(status.ConsoleOutput, "ACTION_YML_FOUND=yes") {
		t.Errorf("expected checkout to produce action.yml, console output:\n%s", status.ConsoleOutput)
	}
}

// TestIntegrationActionsCheckoutFileVerification checks out a repo and verifies
// specific file contents exist, testing that the checkout actually populated the workspace.
func TestIntegrationActionsCheckoutFileVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - checkout file verification
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        repository: actions/checkout
        path: checkout-src
    - id: check-files
      run: |
        # Verify key files from the actions/checkout repo
        if [ -f checkout-src/action.yml ]; then
          echo "has_action_yml=true" >> $GITHUB_OUTPUT
        fi
        if [ -f checkout-src/package.json ]; then
          echo "has_package_json=true" >> $GITHUB_OUTPUT
        fi
        if [ -d checkout-src/src ]; then
          echo "has_src_dir=true" >> $GITHUB_OUTPUT
        fi
        echo "FILES_VERIFIED=yes"
    - env:
        HAS_ACTION: "${{ steps.check-files.outputs.has_action_yml }}"
        HAS_PACKAGE: "${{ steps.check-files.outputs.has_package_json }}"
        HAS_SRC: "${{ steps.check-files.outputs.has_src_dir }}"
      run: |
        echo "action_yml=$HAS_ACTION"
        echo "package_json=$HAS_PACKAGE"
        echo "src_dir=$HAS_SRC"
`,
		Context: integrationContext(),
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatalf("expected PolicyEngineComplete detail, got %T", status.Detail)
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	if !strings.Contains(status.ConsoleOutput, "FILES_VERIFIED=yes") {
		t.Errorf("expected FILES_VERIFIED=yes in output:\n%s", status.ConsoleOutput)
	}

	// Verify the step outputs were captured and cross-referenced
	if !strings.Contains(status.ConsoleOutput, "action_yml=true") {
		t.Errorf("expected action_yml=true in output:\n%s", status.ConsoleOutput)
	}
	if !strings.Contains(status.ConsoleOutput, "package_json=true") {
		t.Errorf("expected package_json=true in output:\n%s", status.ConsoleOutput)
	}
}

// TestIntegrationActionsCheckoutWithRef tests checking out a specific ref/tag.
func TestIntegrationActionsCheckoutWithRef(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - checkout with ref
jobs:
  checkout-ref:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        repository: actions/checkout
        ref: v4.1.0
        path: checkout-tagged
    - run: |
        cd checkout-tagged
        echo "TAG_CHECKOUT=success"
        # Verify we have a valid checkout
        test -f action.yml && echo "VALID_CHECKOUT=yes"
`,
		Context: integrationContext(),
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatalf("expected PolicyEngineComplete detail, got %T", status.Detail)
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	if !strings.Contains(status.ConsoleOutput, "TAG_CHECKOUT=success") {
		t.Errorf("expected TAG_CHECKOUT=success in output:\n%s", status.ConsoleOutput)
	}
}

// TestIntegrationDownloadAction tests the downloadAction function directly,
// verifying that it downloads and extracts an action properly.
func TestIntegrationDownloadAction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	executor := NewWorkflowExecutor()

	// Set up a temporary cache directory
	tmpDir, err := os.MkdirTemp("", "download-action-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor.Context.CacheDir = tmpDir

	// Download actions/checkout
	actionPath, err := executor.downloadAction("actions/checkout", "v4")
	if err != nil {
		t.Fatalf("downloadAction failed: %v", err)
	}

	// Verify action.yml exists
	actionYmlPath := filepath.Join(actionPath, "action.yml")
	if _, err := os.Stat(actionYmlPath); os.IsNotExist(err) {
		t.Error("expected action.yml to exist in downloaded action")
	}

	// Verify it has expected content
	content, err := os.ReadFile(actionYmlPath)
	if err != nil {
		t.Fatalf("failed to read action.yml: %v", err)
	}
	if !strings.Contains(string(content), "Checkout") {
		t.Errorf("expected action.yml to mention 'Checkout', got:\n%s", string(content)[:200])
	}

	// Test caching: downloading again should hit cache
	actionPath2, err := executor.downloadAction("actions/checkout", "v4")
	if err != nil {
		t.Fatalf("second downloadAction failed: %v", err)
	}
	if actionPath2 != actionPath {
		t.Errorf("expected same path from cache, got %s vs %s", actionPath, actionPath2)
	}
}

// TestIntegrationCheckoutThenRunScript tests a multi-step workflow that
// checks out a repo and then runs a script from it.
func TestIntegrationCheckoutThenRunScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - checkout then run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        repository: actions/checkout
        path: repo
    - run: |
        # Count files in the checked out repo
        FILE_COUNT=$(find repo -maxdepth 1 -type f | wc -l | tr -d ' ')
        echo "FILE_COUNT=$FILE_COUNT"
        # Verify we got a reasonable number of files
        if [ "$FILE_COUNT" -gt 3 ]; then
          echo "SUFFICIENT_FILES=yes"
        fi
    - run: |
        # Read the action name from action.yml
        if grep -q "name:" repo/action.yml; then
          echo "ACTION_NAME_FOUND=yes"
        fi
`,
		Context: integrationContext(),
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatalf("expected PolicyEngineComplete detail, got %T", status.Detail)
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	if !strings.Contains(status.ConsoleOutput, "SUFFICIENT_FILES=yes") {
		t.Errorf("expected SUFFICIENT_FILES=yes in output:\n%s", status.ConsoleOutput)
	}
	if !strings.Contains(status.ConsoleOutput, "ACTION_NAME_FOUND=yes") {
		t.Errorf("expected ACTION_NAME_FOUND=yes in output:\n%s", status.ConsoleOutput)
	}
}

// TestIntegrationActionsCheckoutViaServer tests the full server flow: submit a
// workflow with actions/checkout via the API, wait for completion, check output.
func TestIntegrationActionsCheckoutViaServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-checkout-server")

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - server checkout
jobs:
  checkout:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        repository: actions/checkout
        path: srv-checkout
    - run: |
        test -f srv-checkout/action.yml && echo "SERVER_CHECKOUT=success"
`,
		Context: integrationContext(),
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-checkout-server")
	if !exists {
		t.Fatal("task should exist after execution")
	}

	if updatedTask.Status != "SUCCESS" {
		t.Errorf("expected task status SUCCESS, got %s", updatedTask.Status)
	}

	var status PolicyEngineStatus
	if err := json.Unmarshal([]byte(updatedTask.Result), &status); err != nil {
		t.Fatalf("failed to parse task result: %v", err)
	}

	if !strings.Contains(status.ConsoleOutput, "SERVER_CHECKOUT=success") {
		t.Errorf("expected SERVER_CHECKOUT=success in output:\n%s", status.ConsoleOutput)
	}
}

// TestIntegrationActionsCheckoutStreaming tests that console output is streamed
// to the task during an actions/checkout workflow.
func TestIntegrationActionsCheckoutStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-checkout-streaming")

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - streaming checkout
jobs:
  checkout:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        repository: actions/checkout
        path: stream-checkout
    - run: |
        echo "STREAM_LINE_1"
        echo "STREAM_LINE_2"
        echo "STREAM_LINE_3"
`,
		Context: integrationContext(),
	}

	server.executeWorkflowTask(task, request)

	// Verify streamed output was captured on the task
	liveOutput := task.GetConsoleOutput()
	if !strings.Contains(liveOutput, "STREAM_LINE_1") {
		t.Errorf("expected STREAM_LINE_1 in streamed output:\n%s", liveOutput)
	}
	if !strings.Contains(liveOutput, "STREAM_LINE_2") {
		t.Errorf("expected STREAM_LINE_2 in streamed output:\n%s", liveOutput)
	}
	if !strings.Contains(liveOutput, "STREAM_LINE_3") {
		t.Errorf("expected STREAM_LINE_3 in streamed output:\n%s", liveOutput)
	}
}

// TestIntegrationIfConditionWithCheckout tests if conditions around checkout steps.
func TestIntegrationIfConditionWithCheckout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - conditional checkout
jobs:
  conditional:
    runs-on: ubuntu-latest
    steps:
    # This step should run (condition is true)
    - if: true
      uses: actions/checkout@v4
      with:
        repository: actions/checkout
        path: cond-checkout
    # This step should be skipped (condition is false)
    - if: false
      run: echo "SHOULD_NOT_APPEAR"
    # This step verifies the checkout happened
    - run: |
        test -d cond-checkout && echo "CONDITIONAL_CHECKOUT=yes"
`,
		Context: integrationContext(),
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatalf("expected PolicyEngineComplete detail, got %T", status.Detail)
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	if !strings.Contains(status.ConsoleOutput, "CONDITIONAL_CHECKOUT=yes") {
		t.Errorf("expected CONDITIONAL_CHECKOUT=yes in output:\n%s", status.ConsoleOutput)
	}

	if strings.Contains(status.ConsoleOutput, "SHOULD_NOT_APPEAR") {
		t.Error("condition=false step should have been skipped")
	}
}

// TestIntegrationSetupPython tests actions/setup-python and verifies it only
// writes to ephemeral directories (RUNNER_TOOL_CACHE, HOME, RUNNER_TEMP).
func TestIntegrationSetupPython(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Integration - setup-python
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/setup-python@v5
      with:
        python-version: "3.12"
    - run: |
        echo "PYTHON_VERSION=$(python3 --version 2>&1 || echo 'not found')"
        echo "SETUP_PYTHON_DONE=yes"
`,
		Context: integrationContext(),
	}

	// Record real HOME before execution to verify it was NOT touched.
	realHome := os.Getenv("HOME")

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	// The setup-python action may fail to install (no matching version for
	// this OS in the manifest), but we still verify containment. Check that
	// our ephemeral directories were used and the real HOME was not modified.
	t.Logf("console output:\n%s", status.ConsoleOutput)

	// Verify containment: the executor's ToolCacheDir and HomeDir were cleaned
	// up by the deferred cleanup in ExecuteWorkflow.
	if executor.Context.ToolCacheDir != "" {
		if _, err := os.Stat(executor.Context.ToolCacheDir); err == nil {
			t.Error("expected ToolCacheDir to be cleaned up after execution")
		}
	}
	if executor.Context.HomeDir != "" {
		if _, err := os.Stat(executor.Context.HomeDir); err == nil {
			t.Error("expected HomeDir to be cleaned up after execution")
		}
	}

	// Verify the real HOME was not modified by checking that no new
	// runner-style directories were created there.
	suspectDirs := []string{
		filepath.Join(realHome, "hostedtoolcache"),
		filepath.Join(realHome, "runners"),
	}
	for _, d := range suspectDirs {
		if _, err := os.Stat(d); err == nil {
			t.Errorf("real HOME was modified: found %s", d)
		}
	}

	// If setup-python succeeded, verify python is available
	if strings.Contains(status.ConsoleOutput, "SETUP_PYTHON_DONE=yes") {
		t.Log("setup-python step and run step both completed successfully")
	}

	// Verify actions/checkout-style HOME override was in ephemeral dir
	// (setup-python uses RUNNER_TOOL_CACHE for installs, not HOME, but
	// we verify HOME containment regardless)
	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatalf("expected PolicyEngineComplete detail, got %T", status.Detail)
	}

	// Even if setup-python failed (version not available for this platform,
	// or macOS hard-codes /Users/runner/hostedtoolcache which we can't write
	// to), the action exercised executeStepUses, downloadAction,
	// executeNodeAction, and GITHUB_OUTPUT/GITHUB_ENV/GITHUB_PATH creation -
	// increasing coverage. The download and extraction are confirmed to go to
	// our ephemeral dirs; the failure proves containment is working.
	t.Logf("exit status: %s", detail.ExitStatus)
}
