package common

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestExecuteWorkflowTaskBasic(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-basic")

	request := &PolicyEngineRequest{
		Workflow: "name: Basic Test\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo hello",
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-basic")
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

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	if !strings.Contains(status.ConsoleOutput, "hello") {
		t.Errorf("expected console output to contain 'hello', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowTaskFailure(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-failure")

	request := &PolicyEngineRequest{
		Workflow: "name: Failure Test\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: exit 1",
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-failure")
	if !exists {
		t.Fatal("task should exist after execution")
	}

	if updatedTask.Status != "FAILURE" {
		t.Errorf("expected task status FAILURE, got %s", updatedTask.Status)
	}
}

func TestExecuteWorkflowTaskMultipleJobs(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-multiple-jobs")

	request := &PolicyEngineRequest{
		Workflow: "name: Multiple Jobs Test\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo Building\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo Testing\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo Deploying",
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-multiple-jobs")
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

	output := status.ConsoleOutput
	if !strings.Contains(output, "Building") {
		t.Error("expected output to contain 'Building'")
	}
	if !strings.Contains(output, "Testing") {
		t.Error("expected output to contain 'Testing'")
	}
	if !strings.Contains(output, "Deploying") {
		t.Error("expected output to contain 'Deploying'")
	}
}

func TestExecuteWorkflowTaskWithStepOutputCrossReference(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-step-outputs")

	// This mirrors the Python test_read_main parameterized workflow:
	// Step 1 writes to GITHUB_OUTPUT, Step 2 reads it via ${{ steps.*.outputs.* }}
	request := &PolicyEngineRequest{
		Inputs: map[string]interface{}{
			"repo_name": "scitt-community/scitt-api-emulator",
		},
		Workflow: `
name: Step Output Cross Reference Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - id: greeting-step
      env:
        REPO_NAME: "${{ inputs.repo_name }}"
      run: echo "hello=$REPO_NAME" >> $GITHUB_OUTPUT
    - id: verify-step
      env:
        GREETING: "${{ steps.greeting-step.outputs.hello }}"
      run: echo "GREETING=$GREETING"
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

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-step-outputs")
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

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	// Verify step 2 saw the output from step 1
	if !strings.Contains(status.ConsoleOutput, "GREETING=scitt-community/scitt-api-emulator") {
		t.Errorf("expected output to contain 'GREETING=scitt-community/scitt-api-emulator', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowTaskWithExpressions(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-expressions")

	// Test expression evaluation similar to Python test_evaluate_using_javascript
	request := &PolicyEngineRequest{
		Workflow: `
name: Expression Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: echo "${{ github.actor }} ${{ github.repository }}"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "owner/repo",
					"GITHUB_ACTOR":      "aliceoa",
					"GITHUB_ACTOR_ID":   "1234567",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-expressions")
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

	if !strings.Contains(status.ConsoleOutput, "aliceoa owner/repo") {
		t.Errorf("expected output to contain 'aliceoa owner/repo', got: %s", status.ConsoleOutput)
	}
}

func TestExecuteWorkflowTaskWithAnnotations(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-annotations")

	request := &PolicyEngineRequest{
		Workflow: `
name: Annotation Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: |
        echo "::error file=app.js,line=42::Syntax error"
        echo "::warning::Deprecated function used"
        echo "::notice title=Info::This is a notice"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-annotations")
	if !exists {
		t.Fatal("task should exist after execution")
	}

	var status PolicyEngineStatus
	if err := json.Unmarshal([]byte(updatedTask.Result), &status); err != nil {
		t.Fatalf("failed to parse task result: %v", err)
	}

	if status.Status != StatusComplete {
		t.Errorf("expected status complete, got %s", status.Status)
	}

	detail, ok := status.Detail.(map[string]interface{})
	if !ok {
		t.Fatal("expected detail to be a map")
	}
	annotations, ok := detail["annotations"].(map[string]interface{})
	if !ok {
		t.Fatal("expected annotations in detail")
	}
	if annotations["error"] == nil {
		t.Error("expected error annotations")
	}
	if annotations["warning"] == nil {
		t.Error("expected warning annotations")
	}
	if annotations["notice"] == nil {
		t.Error("expected notice annotations")
	}
}

func TestExecuteWorkflowTaskStreamingOutput(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-streaming")

	request := &PolicyEngineRequest{
		Workflow: `
name: Streaming Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: |
        echo "line1"
        echo "line2"
        echo "line3"
`,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	// Verify that console output was accumulated on the task
	liveOutput := task.GetConsoleOutput()
	if !strings.Contains(liveOutput, "line1") {
		t.Errorf("expected live output to contain 'line1', got: %s", liveOutput)
	}
	if !strings.Contains(liveOutput, "line2") {
		t.Errorf("expected live output to contain 'line2', got: %s", liveOutput)
	}
	if !strings.Contains(liveOutput, "line3") {
		t.Errorf("expected live output to contain 'line3', got: %s", liveOutput)
	}
}

func TestExecuteWorkflowTaskWithEnv(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	server := NewServer(":0")
	task := server.taskManager.CreateTask("test-env")

	request := &PolicyEngineRequest{
		Workflow: "name: Environment Test\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - env:\n        STEP_VAR: step_value\n      run: echo STEP_VAR=$STEP_VAR\n    - run: echo GITHUB_REPOSITORY=$GITHUB_REPOSITORY",
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": "test/repo",
				},
			},
		},
	}

	server.executeWorkflowTask(task, request)

	updatedTask, exists := server.taskManager.GetTask("test-env")
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

	output := status.ConsoleOutput
	if !strings.Contains(output, "STEP_VAR=step_value") {
		t.Error("expected output to contain 'STEP_VAR=step_value'")
	}
	if !strings.Contains(output, "GITHUB_REPOSITORY=test/repo") {
		t.Error("expected output to contain 'GITHUB_REPOSITORY=test/repo'")
	}
}
