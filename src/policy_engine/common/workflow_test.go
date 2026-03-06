package common

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseWorkflowFromString(t *testing.T) {
	workflowYAML := `
name: Test Workflow
on:
  push:
    branches:
    - main

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "Hello"
`
	workflow, err := ParseWorkflow(workflowYAML)
	if err != nil {
		t.Fatalf("failed to parse workflow: %v", err)
	}

	if workflow.Name != "Test Workflow" {
		t.Errorf("expected name 'Test Workflow', got %s", workflow.Name)
	}

	if len(workflow.Jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(workflow.Jobs))
	}

	job, ok := workflow.Jobs["test"]
	if !ok {
		t.Fatal("expected job 'test' to exist")
	}

	if len(job.Steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(job.Steps))
	}

	if job.Steps[0].Run != `echo "Hello"` {
		t.Errorf("expected run 'echo \"Hello\"', got %s", job.Steps[0].Run)
	}
}

func TestParseWorkflowFromMap(t *testing.T) {
	workflowMap := map[string]interface{}{
		"name": "Map Workflow",
		"jobs": map[string]interface{}{
			"build": map[string]interface{}{
				"runs-on": "ubuntu-latest",
				"steps": []interface{}{
					map[string]interface{}{
						"run": "echo test",
					},
				},
			},
		},
	}

	workflow, err := ParseWorkflow(workflowMap)
	if err != nil {
		t.Fatalf("failed to parse workflow: %v", err)
	}

	if workflow.Name != "Map Workflow" {
		t.Errorf("expected name 'Map Workflow', got %s", workflow.Name)
	}
}

func TestParseWorkflowFromStruct(t *testing.T) {
	workflow := PolicyEngineWorkflow{
		Name: "Struct Workflow",
		Jobs: map[string]PolicyEngineWorkflowJob{
			"test": {
				Steps: []PolicyEngineWorkflowJobStep{
					{Run: "echo hello"},
				},
			},
		},
	}

	parsed, err := ParseWorkflow(workflow)
	if err != nil {
		t.Fatalf("failed to parse workflow: %v", err)
	}

	if parsed.Name != workflow.Name {
		t.Errorf("expected name %s, got %s", workflow.Name, parsed.Name)
	}
}

func TestParseWorkflowInvalidInput(t *testing.T) {
	_, err := ParseWorkflow(12345)
	if err == nil {
		t.Error("expected error for invalid input type")
	}
}

func TestNewWorkflowExecutor(t *testing.T) {
	executor := NewWorkflowExecutor()

	if executor.Context == nil {
		t.Error("Context should be initialized")
	}

	if executor.Context.Shell != "bash -xe" {
		t.Errorf("expected default shell 'bash -xe', got %s", executor.Context.Shell)
	}
}

func TestEvaluateCondition(t *testing.T) {
	executor := NewWorkflowExecutor()

	tests := []struct {
		name      string
		condition interface{}
		expected  bool
	}{
		{"BoolTrue", true, true},
		{"BoolFalse", false, false},
		{"IntOne", 1, true},
		{"IntZero", 0, false},
		{"StringTrue", "true", true},
		{"StringFalse", "false", false},
		{"String1", "1", true},
		{"String0", "0", false},
		{"EmptyString", "", true},
		{"NilCondition", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := executor.evaluateCondition(tt.condition)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBuildStepEnv(t *testing.T) {
	executor := NewWorkflowExecutor()
	executor.Context.Env["EXISTING_VAR"] = "existing_value"
	executor.Context.Workspace = "/tmp/workspace"
	executor.Context.TempDir = "/tmp/temp"
	executor.Context.ToolCacheDir = "/tmp/toolcache"
	executor.Context.HomeDir = "/tmp/fakehome"

	step := &PolicyEngineWorkflowJobStep{
		Env: map[string]interface{}{
			"NEW_VAR": "new_value",
		},
		WithInputs: map[string]interface{}{
			"input_key": "input_value",
		},
	}

	env := executor.buildStepEnv(step)

	if env["EXISTING_VAR"] != "existing_value" {
		t.Errorf("expected EXISTING_VAR=existing_value, got %s", env["EXISTING_VAR"])
	}
	if env["NEW_VAR"] != "new_value" {
		t.Errorf("expected NEW_VAR=new_value, got %s", env["NEW_VAR"])
	}
	if env["INPUT_INPUT_KEY"] != "input_value" {
		t.Errorf("expected INPUT_INPUT_KEY=input_value, got %s", env["INPUT_INPUT_KEY"])
	}
	if env["GITHUB_WORKSPACE"] != "/tmp/workspace" {
		t.Errorf("expected GITHUB_WORKSPACE=/tmp/workspace, got %s", env["GITHUB_WORKSPACE"])
	}
	if env["RUNNER_TOOL_CACHE"] != "/tmp/toolcache" {
		t.Errorf("expected RUNNER_TOOL_CACHE=/tmp/toolcache, got %s", env["RUNNER_TOOL_CACHE"])
	}
	if env["AGENT_TOOLSDIRECTORY"] != "/tmp/toolcache" {
		t.Errorf("expected AGENT_TOOLSDIRECTORY=/tmp/toolcache, got %s", env["AGENT_TOOLSDIRECTORY"])
	}
	if env["HOME"] != "/tmp/fakehome" {
		t.Errorf("expected HOME=/tmp/fakehome, got %s", env["HOME"])
	}
}

func TestEvaluateExpression(t *testing.T) {
	executor := NewWorkflowExecutor()
	executor.Context.Env["GITHUB_ACTOR"] = "testuser"
	executor.Context.Env["GITHUB_REPOSITORY"] = "owner/repo"
	executor.Context.Inputs["repo_name"] = "test-repo"

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "NoExpression",
			expr:     "plain text",
			expected: "plain text",
		},
		{
			name:     "GitHubActor",
			expr:     "${{ github.actor }}",
			expected: "testuser",
		},
		{
			name:     "GitHubRepository",
			expr:     "${{ github.repository }}",
			expected: "owner/repo",
		},
		{
			name:     "InputValue",
			expr:     "${{ inputs.repo_name }}",
			expected: "test-repo",
		},
		{
			name:     "MixedExpression",
			expr:     "Hello ${{ github.actor }}!",
			expected: "Hello testuser!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := executor.evaluateExpression(tt.expr)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestResolvePropertyPath(t *testing.T) {
	executor := NewWorkflowExecutor()

	data := map[string]interface{}{
		"github": map[string]interface{}{
			"actor":      "testuser",
			"repository": "owner/repo",
		},
		"steps": map[string]interface{}{
			"step1": map[string]interface{}{
				"outputs": map[string]interface{}{
					"result": "success",
				},
			},
		},
	}

	// Test top level (returns a map, so just check it's not nil)
	t.Run("TopLevel", func(t *testing.T) {
		result := executor.resolvePropertyPath("github", data)
		if result == nil {
			t.Error("expected non-nil result for top level")
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Error("expected result to be a map")
		}
		if resultMap["actor"] != "testuser" {
			t.Errorf("expected actor=testuser in result")
		}
	})

	// Test nested path
	t.Run("Nested", func(t *testing.T) {
		result := executor.resolvePropertyPath("github.actor", data)
		if result != "testuser" {
			t.Errorf("expected testuser, got %v", result)
		}
	})

	// Test deep nested path
	t.Run("DeepNested", func(t *testing.T) {
		result := executor.resolvePropertyPath("steps.step1.outputs.result", data)
		if result != "success" {
			t.Errorf("expected success, got %v", result)
		}
	})

	// Test non-existent path
	t.Run("NonExistent", func(t *testing.T) {
		result := executor.resolvePropertyPath("github.nonexistent", data)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	// Test invalid path
	t.Run("InvalidPath", func(t *testing.T) {
		result := executor.resolvePropertyPath("invalid.path.here", data)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})
}

func TestBuildGitHubContext(t *testing.T) {
	executor := NewWorkflowExecutor()
	executor.Context.Env["GITHUB_ACTOR"] = "testuser"
	executor.Context.Env["GITHUB_ACTOR_ID"] = "12345"
	executor.Context.Env["GITHUB_REPOSITORY"] = "owner/repo"
	executor.Context.Inputs["key"] = "value"

	ctx := executor.buildGitHubContext()

	if ctx["actor"] != "testuser" {
		t.Errorf("expected actor=testuser, got %v", ctx["actor"])
	}
	if ctx["actor_id"] != "12345" {
		t.Errorf("expected actor_id=12345, got %v", ctx["actor_id"])
	}
	if ctx["repository"] != "owner/repo" {
		t.Errorf("expected repository=owner/repo, got %v", ctx["repository"])
	}

	event, ok := ctx["event"].(map[string]interface{})
	if !ok {
		t.Fatal("expected event to be a map")
	}
	inputs, ok := event["inputs"].(map[string]interface{})
	if !ok {
		t.Fatal("expected event.inputs to be a map")
	}
	if inputs["key"] != "value" {
		t.Errorf("expected inputs.key=value, got %v", inputs["key"])
	}
}

func TestParseGitHubActionsOutputs(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected map[string]string
	}{
		{
			name:     "SimpleKeyValue",
			content:  "key=value",
			expected: map[string]string{"key": "value"},
		},
		{
			name:     "MultipleKeyValues",
			content:  "key1=value1\nkey2=value2",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "HeredocStyle",
			content:  "key<<EOF\nline1\nline2\nEOF",
			expected: map[string]string{"key": "line1\nline2"},
		},
		{
			name:     "EmptyValue",
			content:  "key=",
			expected: map[string]string{"key": ""},
		},
		{
			name:     "EmptyContent",
			content:  "",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseGitHubActionsOutputs(tt.content)
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%s, got %s=%s", k, v, k, result[k])
				}
			}
		})
	}
}

func TestParseAnnotations(t *testing.T) {
	executor := NewWorkflowExecutor()

	output := `Starting build...
::error file=main.go,line=10::Syntax error
::warning::This is a warning
::notice title=Info::This is a notice
Build complete.`

	executor.parseAnnotations(output)

	if len(executor.Context.Annotations["error"]) != 1 {
		t.Errorf("expected 1 error annotation, got %d", len(executor.Context.Annotations["error"]))
	}
	if len(executor.Context.Annotations["warning"]) != 1 {
		t.Errorf("expected 1 warning annotation, got %d", len(executor.Context.Annotations["warning"]))
	}
	if len(executor.Context.Annotations["notice"]) != 1 {
		t.Errorf("expected 1 notice annotation, got %d", len(executor.Context.Annotations["notice"]))
	}

	errorAnnotation := executor.Context.Annotations["error"][0]
	if errorAnnotation.Path != "main.go" {
		t.Errorf("expected error path=main.go, got %s", errorAnnotation.Path)
	}
	if errorAnnotation.Message != "Syntax error" {
		t.Errorf("expected error message='Syntax error', got %s", errorAnnotation.Message)
	}
}

func TestExecuteWorkflowSimple(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Simple Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "Hello World"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
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
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s", detail.ExitStatus)
	}

	if !strings.Contains(status.ConsoleOutput, "Hello World") {
		t.Errorf("expected console output to contain 'Hello World', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowWithOutputs(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Output Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - id: step1
      run: |
        echo "result=success" >> $GITHUB_OUTPUT
        echo "Step 1 complete"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	// Check that outputs were captured
	if executor.Context.Outputs["step1"] == nil {
		t.Error("expected step1 outputs to be captured")
	}
}

func TestExecuteWorkflowBetweenStepOutputPassing(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	// Step 1 writes multiple outputs via GITHUB_OUTPUT file,
	// Step 2 reads them via ${{ steps.producer.outputs.* }} expressions.
	request := &PolicyEngineRequest{
		Inputs: map[string]interface{}{
			"greeting": "hello",
		},
		Workflow: `
name: Between Step Output Passing Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - id: producer
      env:
        MSG: "${{ inputs.greeting }}"
      run: |
        echo "message=$MSG" >> $GITHUB_OUTPUT
        echo "count=42" >> $GITHUB_OUTPUT
    - id: consumer
      env:
        RECEIVED_MSG: "${{ steps.producer.outputs.message }}"
        RECEIVED_COUNT: "${{ steps.producer.outputs.count }}"
      run: |
        echo "GOT_MSG=$RECEIVED_MSG"
        echo "GOT_COUNT=$RECEIVED_COUNT"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
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
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s", detail.ExitStatus)
	}

	// Verify step 1 outputs were captured
	if executor.Context.Outputs["producer"] == nil {
		t.Fatal("expected producer outputs to be captured")
	}
	producerOutputs, ok := executor.Context.Outputs["producer"]["outputs"].(map[string]string)
	if !ok {
		t.Fatalf("expected producer outputs to be map[string]string, got %T", executor.Context.Outputs["producer"]["outputs"])
	}
	if producerOutputs["message"] != "hello" {
		t.Errorf("expected producer output message=hello, got %s", producerOutputs["message"])
	}
	if producerOutputs["count"] != "42" {
		t.Errorf("expected producer output count=42, got %s", producerOutputs["count"])
	}

	// Verify step 2 received the outputs from step 1
	if !strings.Contains(status.ConsoleOutput, "GOT_MSG=hello") {
		t.Errorf("expected output to contain 'GOT_MSG=hello', got: %s", status.ConsoleOutput)
	}
	if !strings.Contains(status.ConsoleOutput, "GOT_COUNT=42") {
		t.Errorf("expected output to contain 'GOT_COUNT=42', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowWithGitHubEnvBetweenSteps(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	// Step 1 writes to GITHUB_ENV, Step 2 should see the new env var.
	request := &PolicyEngineRequest{
		Workflow: `
name: GITHUB_ENV Between Steps Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - id: set-env
      run: echo "DYNAMIC_VAR=from_step1" >> $GITHUB_ENV
    - run: echo "DYNAMIC_VAR=$DYNAMIC_VAR"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	// Verify GITHUB_ENV was parsed and applied to the execution context
	if executor.Context.Env["DYNAMIC_VAR"] != "from_step1" {
		t.Errorf("expected DYNAMIC_VAR=from_step1 in context env, got %v", executor.Context.Env["DYNAMIC_VAR"])
	}

	// Verify step 2 saw the env var propagated
	if !strings.Contains(status.ConsoleOutput, "DYNAMIC_VAR=from_step1") {
		t.Errorf("expected output to contain 'DYNAMIC_VAR=from_step1', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowWithEnv(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Env Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - env:
        MY_VAR: my_value
      run: echo "MY_VAR=$MY_VAR"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if !strings.Contains(status.ConsoleOutput, "MY_VAR=my_value") {
		t.Errorf("expected output to contain 'MY_VAR=my_value', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowFailure(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Failure Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: exit 1
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("ExecuteWorkflow should not return error, got: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusFailure {
		t.Errorf("expected exit status failure, got %s", detail.ExitStatus)
	}
}

func TestExecuteWorkflowWithAnnotations(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Workflow: `
name: Annotation Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: |
        echo "::error file=test.go,line=5::Test error"
        echo "::warning::Test warning"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatal("expected PolicyEngineComplete detail")
	}

	annotations := detail.Annotations
	if annotations == nil {
		t.Fatal("expected annotations to be set")
	}

	errors, ok := annotations["error"].([]GitHubCheckSuiteAnnotation)
	if !ok || len(errors) != 1 {
		t.Errorf("expected 1 error annotation, got %v", annotations["error"])
	}
}

func TestMapToEnvSlice(t *testing.T) {
	env := map[string]string{
		"VAR1": "value1",
		"VAR2": "value2",
	}

	slice := mapToEnvSlice(env)

	// Check that our custom vars are present
	found := 0
	for _, e := range slice {
		if e == "VAR1=value1" || e == "VAR2=value2" {
			found++
		}
	}

	if found != 2 {
		t.Errorf("expected to find both custom env vars, found %d", found)
	}
}

func TestInitializeContext(t *testing.T) {
	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Inputs: map[string]interface{}{
			"key": "value",
		},
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
			"secrets": map[string]interface{}{
				"API_KEY": "secret123",
			},
		},
	}

	err := executor.initializeContext(request)
	if err != nil {
		t.Fatalf("initializeContext failed: %v", err)
	}

	if executor.Context.Inputs["key"] != "value" {
		t.Errorf("expected input key=value")
	}

	if executor.Context.Env["GITHUB_REPOSITORY"] != "test/repo" {
		t.Errorf("expected env GITHUB_REPOSITORY=test/repo")
	}

	if executor.Context.Secrets["API_KEY"] != "secret123" {
		t.Errorf("expected secret API_KEY=secret123")
	}

	if executor.Context.Workspace == "" {
		t.Error("expected workspace to be set")
	}

	if executor.Context.ToolCacheDir == "" {
		t.Error("expected tool cache dir to be set")
	}

	if executor.Context.HomeDir == "" {
		t.Error("expected home dir to be set")
	}

	// Cleanup
	if executor.Context.Workspace != "" {
		os.RemoveAll(executor.Context.Workspace)
	}
	if executor.Context.ToolCacheDir != "" {
		os.RemoveAll(executor.Context.ToolCacheDir)
	}
	if executor.Context.HomeDir != "" {
		os.RemoveAll(executor.Context.HomeDir)
	}
}

func TestCreateSuccessStatus(t *testing.T) {
	executor := NewWorkflowExecutor()
	executor.Context.ConsoleOutput = []string{"line1", "line2"}
	executor.Context.Annotations["error"] = []GitHubCheckSuiteAnnotation{
		{Message: "test error"},
	}

	status := executor.createSuccessStatus()

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s", detail.ExitStatus)
	}

	if status.ConsoleOutput != "line1\nline2" {
		t.Errorf("expected console output 'line1\\nline2', got %s", status.ConsoleOutput)
	}
}

func TestCreateErrorStatus(t *testing.T) {
	executor := NewWorkflowExecutor()

	testErr := &testError{message: "test error message"}
	status := executor.createErrorStatus(testErr)

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(PolicyEngineComplete)
	if !ok {
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusFailure {
		t.Errorf("expected exit status failure, got %s", detail.ExitStatus)
	}

	errors, ok := detail.Annotations["error"].([]string)
	if !ok || len(errors) != 1 {
		t.Errorf("expected 1 error in annotations")
	}
	if errors[0] != "test error message" {
		t.Errorf("expected error message 'test error message', got %s", errors[0])
	}
}

func TestFindBinary(t *testing.T) {
	// Test finding a common binary
	bashPath := findBinary("bash")
	if bashPath == "" {
		t.Skip("bash not found in PATH")
	}

	if !strings.Contains(bashPath, "bash") {
		t.Errorf("expected path to contain 'bash', got %s", bashPath)
	}

	// Test non-existent binary
	nonExistent := findBinary("nonexistent-binary-12345")
	if nonExistent != "" {
		t.Errorf("expected empty string for non-existent binary, got %s", nonExistent)
	}
}

func TestExecuteWorkflowWithInputs(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	request := &PolicyEngineRequest{
		Inputs: map[string]interface{}{
			"greeting": "Hello",
			"name":     "World",
		},
		Workflow: `
name: Input Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "${{ inputs.greeting }} ${{ inputs.name }}"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	status, err := executor.ExecuteWorkflow(ctx, request)
	if err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}

	if !strings.Contains(status.ConsoleOutput, "Hello World") {
		t.Errorf("expected output to contain 'Hello World', got: %s", status.ConsoleOutput)
	}
}

func TestUnzipFunction(t *testing.T) {
	// Skip if unzip is not available
	if _, err := os.Stat("/usr/bin/unzip"); os.IsNotExist(err) {
		t.Skip("unzip command not available")
	}

	// Skip if zip is not available
	if _, err := os.Stat("/usr/bin/zip"); os.IsNotExist(err) {
		t.Skip("zip command not available")
	}

	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "unzip-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create content to zip
	contentDir := filepath.Join(tmpDir, "content")
	os.MkdirAll(contentDir, 0755)
	os.WriteFile(filepath.Join(contentDir, "test.txt"), []byte("test content"), 0644)

	// Create zip file
	zipPath := filepath.Join(tmpDir, "test.zip")
	cmd := exec.Command("zip", "-r", zipPath, "content")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}

	// Extract zip
	extractDir := filepath.Join(tmpDir, "extracted")
	os.MkdirAll(extractDir, 0755)
	if err := unzip(zipPath, extractDir); err != nil {
		t.Fatalf("unzip failed: %v", err)
	}

	// Verify extracted content
	extractedFile := filepath.Join(extractDir, "content", "test.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}

	if string(content) != "test content" {
		t.Errorf("expected 'test content', got %s", string(content))
	}
}

func TestExecuteCompositeActionViaLocalPath(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	// Get absolute path to our test composite action fixture
	testActionDir, err := filepath.Abs("../test/workflows/local-composite-action")
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	// Use the test fixture via absolute path
	request := &PolicyEngineRequest{
		Workflow: fmt.Sprintf(`
name: Local Composite Action Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: %s
      with:
        greeting: Hi
        name: Tester
    - run: echo "AFTER_COMPOSITE=yes"
`, testActionDir),
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
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
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	// Verify composite action steps ran with the provided inputs
	if !strings.Contains(status.ConsoleOutput, "COMPOSITE_GREETING=Hi Tester") {
		t.Errorf("expected 'COMPOSITE_GREETING=Hi Tester' in output, got:\n%s", status.ConsoleOutput)
	}
	if !strings.Contains(status.ConsoleOutput, "COMPOSITE_ACTION_PATH=") {
		t.Errorf("expected COMPOSITE_ACTION_PATH to be set, got:\n%s", status.ConsoleOutput)
	}
	if !strings.Contains(status.ConsoleOutput, "COMPOSITE_STEP_THREE=done") {
		t.Errorf("expected 'COMPOSITE_STEP_THREE=done' in output, got:\n%s", status.ConsoleOutput)
	}
	// Verify the step after the composite action also ran
	if !strings.Contains(status.ConsoleOutput, "AFTER_COMPOSITE=yes") {
		t.Errorf("expected 'AFTER_COMPOSITE=yes' in output, got:\n%s", status.ConsoleOutput)
	}
}

func TestExecuteCompositeActionDirect(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	// This test exercises the executeCompositeAction code path directly
	// by creating a workflow that uses a local composite action.
	// We set up the workspace to contain the action directory ourselves.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	// Create a temp workspace
	tmpDir, err := os.MkdirTemp("", "composite-direct-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create local composite action inside workspace
	actionDir := filepath.Join(tmpDir, "my-composite")
	if err := os.MkdirAll(actionDir, 0755); err != nil {
		t.Fatalf("failed to create action dir: %v", err)
	}
	actionYml := `name: 'Test Composite'
description: 'Test composite action'
inputs:
  message:
    description: 'Message to echo'
    default: 'default-msg'
runs:
  using: 'composite'
  steps:
    - run: echo "COMPOSITE_MSG=$INPUT_MESSAGE"
      shell: bash
    - run: echo "COMPOSITE_SECOND_STEP=executed"
      shell: bash
`
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0644); err != nil {
		t.Fatalf("failed to write action.yml: %v", err)
	}

	// Use absolute path to the local action
	request := &PolicyEngineRequest{
		Workflow: fmt.Sprintf(`
name: Direct Composite Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: %s
      with:
        message: hello-composite
    - run: echo "POST_COMPOSITE=success"
`, actionDir),
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
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
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	// Verify composite action steps ran
	if !strings.Contains(status.ConsoleOutput, "COMPOSITE_MSG=hello-composite") {
		t.Errorf("expected composite action to echo message, got:\n%s", status.ConsoleOutput)
	}
	if !strings.Contains(status.ConsoleOutput, "COMPOSITE_SECOND_STEP=executed") {
		t.Errorf("expected composite action second step to run, got:\n%s", status.ConsoleOutput)
	}
	// Verify step after composite also ran
	if !strings.Contains(status.ConsoleOutput, "POST_COMPOSITE=success") {
		t.Errorf("expected post-composite step to run, got:\n%s", status.ConsoleOutput)
	}
}

func TestExecuteCompositeActionWithDefaults(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	// Create a temp workspace with a local composite action
	tmpDir, err := os.MkdirTemp("", "composite-defaults-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	actionDir := filepath.Join(tmpDir, "default-action")
	if err := os.MkdirAll(actionDir, 0755); err != nil {
		t.Fatalf("failed to create action dir: %v", err)
	}
	actionYml := `name: 'Default Inputs Composite'
description: 'Tests default input handling in composite actions'
inputs:
  color:
    description: 'A color'
    default: 'blue'
  size:
    description: 'A size'
    default: 'medium'
runs:
  using: 'composite'
  steps:
    - run: echo "COLOR=$INPUT_COLOR SIZE=$INPUT_SIZE"
      shell: bash
`
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0644); err != nil {
		t.Fatalf("failed to write action.yml: %v", err)
	}

	// Don't provide any inputs - defaults should be used
	request := &PolicyEngineRequest{
		Workflow: fmt.Sprintf(`
name: Composite Defaults Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: %s
    - uses: %s
      with:
        color: red
`, actionDir, actionDir),
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
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
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	// First invocation: both defaults should be used
	if !strings.Contains(status.ConsoleOutput, "COLOR=blue SIZE=medium") {
		t.Errorf("expected defaults 'COLOR=blue SIZE=medium', got:\n%s", status.ConsoleOutput)
	}

	// Second invocation: color overridden, size default
	if !strings.Contains(status.ConsoleOutput, "COLOR=red SIZE=medium") {
		t.Errorf("expected 'COLOR=red SIZE=medium', got:\n%s", status.ConsoleOutput)
	}
}

func TestExecuteCompositeActionWithEnvOverrides(t *testing.T) {
	// Skip if bash is not available
	if _, err := os.Stat("/bin/bash"); os.IsNotExist(err) {
		t.Skip("bash not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	executor := NewWorkflowExecutor()

	tmpDir, err := os.MkdirTemp("", "composite-env-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	actionDir := filepath.Join(tmpDir, "env-action")
	if err := os.MkdirAll(actionDir, 0755); err != nil {
		t.Fatalf("failed to create action dir: %v", err)
	}

	// Composite action with per-step env overrides
	actionYml := `name: 'Env Override Composite'
description: 'Tests env override in composite action steps'
runs:
  using: 'composite'
  steps:
    - run: echo "STEP1_FOO=$FOO"
      shell: bash
      env:
        FOO: bar
    - run: echo "STEP2_FOO=${FOO:-unset}"
      shell: bash
`
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0644); err != nil {
		t.Fatalf("failed to write action.yml: %v", err)
	}

	request := &PolicyEngineRequest{
		Workflow: fmt.Sprintf(`
name: Composite Env Override Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: %s
`, actionDir),
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
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
		t.Fatal("expected PolicyEngineComplete detail")
	}

	if detail.ExitStatus != ExitStatusSuccess {
		t.Errorf("expected exit status success, got %s\nconsole output:\n%s", detail.ExitStatus, status.ConsoleOutput)
	}

	// Step 1 should see the env override
	if !strings.Contains(status.ConsoleOutput, "STEP1_FOO=bar") {
		t.Errorf("expected 'STEP1_FOO=bar' in output, got:\n%s", status.ConsoleOutput)
	}
	// Step 2 should NOT have FOO since it wasn't set at that level
	if !strings.Contains(status.ConsoleOutput, "STEP2_FOO=unset") {
		t.Errorf("expected 'STEP2_FOO=unset' in output, got:\n%s", status.ConsoleOutput)
	}
}
