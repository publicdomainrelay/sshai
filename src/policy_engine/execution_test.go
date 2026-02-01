package main

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
