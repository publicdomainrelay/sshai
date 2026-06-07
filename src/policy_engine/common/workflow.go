package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// ParseWorkflow parses a workflow from various input types.
func ParseWorkflow(input interface{}) (*PolicyEngineWorkflow, error) {
	switch v := input.(type) {
	case string:
		// Try to parse as YAML
		var workflow PolicyEngineWorkflow
		if err := yaml.Unmarshal([]byte(v), &workflow); err != nil {
			return nil, fmt.Errorf("failed to parse workflow YAML: %w", err)
		}
		return &workflow, nil
	case map[string]interface{}:
		// Convert map to YAML then parse
		yamlBytes, err := yaml.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal workflow map: %w", err)
		}
		var workflow PolicyEngineWorkflow
		if err := yaml.Unmarshal(yamlBytes, &workflow); err != nil {
			return nil, fmt.Errorf("failed to parse workflow: %w", err)
		}
		return &workflow, nil
	case *PolicyEngineWorkflow:
		return v, nil
	case PolicyEngineWorkflow:
		return &v, nil
	default:
		return nil, fmt.Errorf("unsupported workflow type: %T", input)
	}
}

// WorkflowExecutor executes workflows.
type WorkflowExecutor struct {
	DenoPath   string
	NodeJSPath string
	Context    *WorkflowExecutionContext
	Task       *Task // optional: if set, console output is streamed to the task
}

// NewWorkflowExecutor creates a new workflow executor.
// Deno is resolved via the deno manager (embedded -> PATH -> download).
func NewWorkflowExecutor() *WorkflowExecutor {
	return &WorkflowExecutor{
		DenoPath:   ResolveDeno(""),
		NodeJSPath: findBinary("node"),
		Context:    NewWorkflowExecutionContext(),
	}
}

// findBinary finds a binary in PATH.
func findBinary(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

// ExecuteWorkflow executes a parsed workflow.
func (e *WorkflowExecutor) ExecuteWorkflow(ctx context.Context, request *PolicyEngineRequest) (*PolicyEngineStatus, error) {
	Info("executing workflow")
	workflow, err := ParseWorkflow(request.Workflow)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}
	Info("workflow parsed: name=%q jobs=%d", workflow.Name, len(workflow.Jobs))

	// Initialize context from request
	if err := e.initializeContext(request); err != nil {
		return nil, fmt.Errorf("failed to initialize context: %w", err)
	}
	Debug("context initialized: workspace=%s", e.Context.Workspace)

	// Clean up ephemeral directories when done.
	// CacheDir is intentionally kept (persists downloaded actions between runs).
	defer func() {
		if e.Context.Workspace != "" {
			os.RemoveAll(e.Context.Workspace)
		}
		if e.Context.ToolCacheDir != "" {
			os.RemoveAll(e.Context.ToolCacheDir)
		}
		if e.Context.HomeDir != "" {
			os.RemoveAll(e.Context.HomeDir)
		}
	}()

	// Execute each job
	for jobName, job := range workflow.Jobs {
		Info("starting job: %s (steps=%d)", jobName, len(job.Steps))
		if err := e.executeJob(ctx, jobName, &job); err != nil {
			LogError("job %s failed: %v", jobName, err)
			// Record error but continue to allow cleanup
			e.Context.Error = err
			return e.createErrorStatus(err), nil
		}
		Info("job %s completed successfully", jobName)
	}

	Info("workflow completed successfully")
	return e.createSuccessStatus(), nil
}

// initializeContext initializes the execution context from the request.
func (e *WorkflowExecutor) initializeContext(request *PolicyEngineRequest) error {
	// Copy inputs
	if request.Inputs != nil {
		for k, v := range request.Inputs {
			e.Context.Inputs[k] = v
		}
	}

	// Set up environment from context config
	if request.Context != nil {
		if config, ok := request.Context["config"].(map[string]interface{}); ok {
			if env, ok := config["env"].(map[string]interface{}); ok {
				for k, v := range env {
					e.Context.Env[k] = v
				}
			}
		}
		if secrets, ok := request.Context["secrets"].(map[string]interface{}); ok {
			for k, v := range secrets {
				if strVal, ok := v.(string); ok {
					e.Context.Secrets[k] = strVal
				}
			}
		}
	}

	// In real GitHub Actions, GITHUB_TOKEN is available as both a secret
	// and an environment variable. Mirror that here so ${{ github.token }}
	// resolves correctly in action input defaults.
	if token, ok := e.Context.Secrets["GITHUB_TOKEN"]; ok && token != "" {
		if _, envSet := e.Context.Env["GITHUB_TOKEN"]; !envSet {
			e.Context.Env["GITHUB_TOKEN"] = token
		}
	}

	// Set up temp and cache directories
	cwd, _ := os.Getwd()
	e.Context.CacheDir = filepath.Join(cwd, ".cache")
	e.Context.TempDir = filepath.Join(cwd, ".tempdir")
	os.MkdirAll(e.Context.CacheDir, 0755)
	os.MkdirAll(e.Context.TempDir, 0755)

	// Create workspace
	workspace, err := os.MkdirTemp(e.Context.TempDir, "workspace-*")
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	e.Context.Workspace = workspace

	// Create ephemeral RUNNER_TOOL_CACHE so that actions like setup-python
	// download/install into a directory we control (not the real system).
	toolCache, err := os.MkdirTemp(e.Context.TempDir, "toolcache-*")
	if err != nil {
		return fmt.Errorf("failed to create tool cache dir: %w", err)
	}
	e.Context.ToolCacheDir = toolCache

	// Create ephemeral HOME so that pip --user, npm, and similar tools
	// never write to the real home directory.
	homeDir, err := os.MkdirTemp(e.Context.TempDir, "home-*")
	if err != nil {
		return fmt.Errorf("failed to create ephemeral home dir: %w", err)
	}
	e.Context.HomeDir = homeDir

	return nil
}

// executeJob executes a single job.
func (e *WorkflowExecutor) executeJob(ctx context.Context, jobName string, job *PolicyEngineWorkflowJob) error {
	for i, step := range job.Steps {
		stepName := fmt.Sprintf("step_%d", i+1)
		if step.ID != "" {
			stepName = step.ID
		} else if step.Name != "" {
			stepName = step.Name
		}

		// Check if condition
		if step.IfCondition != nil {
			shouldRun, err := e.evaluateCondition(step.IfCondition)
			if err != nil {
				return fmt.Errorf("failed to evaluate if condition for step %s: %w", stepName, err)
			}
			if !shouldRun {
				Info("step %s skipped (if condition false)", stepName)
				continue
			}
		}

		Info("starting step: %s", stepName)
		if step.Uses != "" {
			Debug("step %s uses action: %s", stepName, step.Uses)
		} else if step.Run != "" {
			Debug("step %s run script:\n%s", stepName, step.Run)
		}

		// Set shell if specified
		if step.Shell != "" {
			e.Context.Shell = step.Shell
		}

		// Build step environment
		stepEnv := e.buildStepEnv(&step)

		// Emit GitHub Actions group markers so tangled and tooling can render
		// each step as a collapsible section — both snapshot and live SSE stream.
		groupStart := fmt.Sprintf("##[group]%s", stepName)
		e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, groupStart)
		if e.Task != nil {
			e.Task.AppendConsoleOutput(groupStart)
		}

		// Execute step
		var err error
		if step.Uses != "" {
			err = e.executeStepUses(ctx, &step, stepEnv)
		} else if step.Run != "" {
			err = e.executeStepRun(ctx, &step, stepEnv)
		}

		e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, "##[endgroup]")
		if e.Task != nil {
			e.Task.AppendConsoleOutput("##[endgroup]")
		}

		if err != nil {
			LogError("step %s failed: %v", stepName, err)
			e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, fmt.Sprintf("##[error]step %s failed: %v", stepName, err))
			return fmt.Errorf("step %s failed: %w", stepName, err)
		}
		Info("step %s completed", stepName)
	}

	return nil
}

// evaluateCondition evaluates an if condition.
// Matches the Python behavior: bool/int are handled directly, string conditions
// that don't contain ${{ }} are wrapped in ${{ }}, then evaluated.
func (e *WorkflowExecutor) evaluateCondition(condition interface{}) (bool, error) {
	switch v := condition.(type) {
	case bool:
		return v, nil
	case int:
		return v != 0, nil
	case string:
		if v == "" {
			return true, nil
		}
		// Handle simple truthy/falsy values
		trimmed := strings.ToLower(strings.TrimSpace(v))
		if trimmed == "true" || trimmed == "1" {
			return true, nil
		}
		if trimmed == "false" || trimmed == "0" {
			return false, nil
		}
		// Wrap in ${{ }} if not already (matching Python behavior)
		exprStr := v
		if !strings.Contains(exprStr, "${{") {
			exprStr = "${{ " + exprStr + " }}"
		}
		evaluated := e.evaluateExpression(exprStr)
		if strings.Contains(evaluated, "${{") {
			// The expression could not be resolved (e.g. unknown step ID or
			// output). Treat this as an error rather than silently running
			// the step, matching GitHub Actions' fail-closed behavior.
			return false, fmt.Errorf("could not evaluate expression %q", v)
		}
		evaluated = strings.ToLower(strings.TrimSpace(evaluated))
		if evaluated == "__github_actions_always__" {
			return true, nil
		}
		if evaluated == "false" || evaluated == "0" || evaluated == "" || evaluated == "null" || evaluated == "undefined" {
			return false, nil
		}
		return true, nil
	default:
		return true, nil
	}
}

// buildStepEnv builds the environment for a step.
func (e *WorkflowExecutor) buildStepEnv(step *PolicyEngineWorkflowJobStep) map[string]string {
	env := make(map[string]string)

	// Copy from context env
	for k, v := range e.Context.Env {
		env[k] = fmt.Sprintf("%v", v)
	}

	// Add step-specific env
	for k, v := range step.Env {
		evaluated := e.evaluateExpression(fmt.Sprintf("%v", v))
		env[k] = evaluated
	}

	// Add inputs as INPUT_ prefixed env vars
	for k, v := range step.WithInputs {
		evaluated := e.evaluateExpression(fmt.Sprintf("%v", v))
		env["INPUT_"+strings.ToUpper(k)] = evaluated
	}

	// Add workspace paths
	env["GITHUB_WORKSPACE"] = e.Context.Workspace
	env["RUNNER_TEMP"] = e.Context.TempDir

	// Point tool cache and agent tools directory at our ephemeral dir.
	// On macOS, setup-python hard-codes AGENT_TOOLSDIRECTORY to
	// /Users/runner/hostedtoolcache, then copies it to RUNNER_TOOL_CACHE.
	// Setting both ensures actions never escape the sandbox.
	env["RUNNER_TOOL_CACHE"] = e.Context.ToolCacheDir
	env["AGENT_TOOLSDIRECTORY"] = e.Context.ToolCacheDir

	// Use an ephemeral HOME so pip --user, npm config, and similar tools
	// write to a directory we control rather than the real home.
	env["HOME"] = e.Context.HomeDir

	return env
}

// evaluateExpression evaluates GitHub Actions expressions like ${{ ... }}.
// When Deno is available, expressions are evaluated as JavaScript (matching
// the Python implementation). Falls back to simple property-path resolution.
func (e *WorkflowExecutor) evaluateExpression(expr string) string {
	if !strings.Contains(expr, "${{") {
		return expr
	}

	re := regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)

	// Build the full result by replacing each ${{ ... }} occurrence
	result := ""
	startIdx := 0
	for _, loc := range re.FindAllStringIndex(expr, -1) {
		result += expr[startIdx:loc[0]]
		inner := re.FindStringSubmatch(expr[loc[0]:loc[1]])[1]
		inner = strings.TrimSpace(inner)
		evaluated := e.evaluateInnerExpression(inner)
		result += evaluated
		startIdx = loc[1]
	}
	result += expr[startIdx:]

	return result
}

// evaluateInnerExpression evaluates a single expression (the content between ${{ and }}).
// Uses Deno if available, otherwise falls back to simple property-path resolution.
func (e *WorkflowExecutor) evaluateInnerExpression(inner string) string {
	if e.DenoPath != "" {
		result, err := e.evaluateUsingJavaScript(inner)
		if err == nil {
			return result
		}
		// Fall through to simple resolution on error
	}

	// Fallback: simple property-path resolution
	data := map[string]interface{}{
		"github": e.buildGitHubContext(),
		"steps":  e.Context.Outputs,
		"inputs": e.Context.Inputs,
		"env":    e.Context.Env,
	}
	value := e.resolvePropertyPath(inner, data)
	if value != nil {
		return fmt.Sprintf("%v", value)
	}
	return "${{ " + inner + " }}"
}

// evaluateUsingJavaScript evaluates an expression using Deno, matching the
// Python _evaluate_using_javascript implementation. It constructs a JS file
// with the github, runner, steps, and inputs contexts, then evaluates the
// expression and captures the output.
func (e *WorkflowExecutor) evaluateUsingJavaScript(codeBlock string) (string, error) {
	// Build contexts
	githubCtx := e.buildGitHubContext()
	stepsCtx := e.Context.Outputs
	inputsCtx := e.Context.Inputs

	runnerCtx := map[string]interface{}{
		"debug": 1,
	}

	// Transform property accessors: dot notation -> bracket notation
	// This avoids issues with JS reserved words and ensures property access
	// works correctly (matching Python transform_property_accessors).
	transformed := transformPropertyAccessors(codeBlock)

	githubJSON, _ := json.Marshal(githubCtx)
	runnerJSON, _ := json.Marshal(runnerCtx)
	stepsJSON, _ := json.Marshal(stepsCtx)
	inputsJSON, _ := json.Marshal(inputsCtx)

	jsCode := fmt.Sprintf(`function always() { return "__GITHUB_ACTIONS_ALWAYS__"; }
const github = %s;
const runner = %s;
const steps = %s;
const inputs = %s;
const result = (%s);
console.log(result)
`, string(githubJSON), string(runnerJSON), string(stepsJSON), string(inputsJSON), transformed)

	// Write to temp file
	tmpDir := e.Context.TempDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	jsFile, err := os.CreateTemp(tmpDir, "eval-*.js")
	if err != nil {
		return "", fmt.Errorf("failed to create temp JS file: %w", err)
	}
	jsPath := jsFile.Name()
	defer os.Remove(jsPath)

	if _, err := jsFile.WriteString(jsCode); err != nil {
		jsFile.Close()
		return "", fmt.Errorf("failed to write JS file: %w", err)
	}
	jsFile.Close()

	// Run with Deno. Use "deno run" for clean output (no REPL prompts).
	// The --no-prompt flag prevents permission prompts, and we allow read
	// access to the temp dir for the eval file.
	cmd := exec.Command(e.DenoPath, "run", "--no-prompt", jsPath)
	devnull, _ := os.Open(os.DevNull)
	if devnull != nil {
		cmd.Stdin = devnull
		defer devnull.Close()
	}
	if e.Context.Workspace != "" {
		cmd.Dir = e.Context.Workspace
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("deno evaluation failed: %w: %s", err, stderr.String())
	}

	output := strings.TrimSpace(stdout.String())
	return output, nil
}

// transformPropertyAccessors converts dot notation to bracket notation in JS
// code, matching the Python transform_property_accessors function. This avoids
// issues with property access within string literals.
func transformPropertyAccessors(jsCode string) string {
	var result strings.Builder
	i := 0
	for i < len(jsCode) {
		ch := jsCode[i]
		if ch == '"' || ch == '\'' {
			// Inside a string literal: copy through to closing quote
			quote := ch
			result.WriteByte(ch)
			i++
			for i < len(jsCode) {
				result.WriteByte(jsCode[i])
				if jsCode[i] == quote {
					i++
					break
				}
				i++
			}
		} else if ch == '.' {
			// Replace dot with bracket notation
			result.WriteString("['")
			i++
			propStart := i
			for i < len(jsCode) && (isAlphanumeric(jsCode[i]) || jsCode[i] == '_' || jsCode[i] == '-') {
				i++
			}
			result.WriteString(jsCode[propStart:i])
			result.WriteString("']")
		} else {
			result.WriteByte(ch)
			i++
		}
	}
	return result.String()
}

// isAlphanumeric returns true if the byte is a letter or digit.
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// resolvePropertyPath resolves a property path like "github.actor" from data.
func (e *WorkflowExecutor) resolvePropertyPath(path string, data map[string]interface{}) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil
			}
		case map[string]string:
			val, ok := v[part]
			if !ok {
				return nil
			}
			current = val
		default:
			return nil
		}
	}

	return current
}

// buildGitHubContext builds the github context for expression evaluation.
func (e *WorkflowExecutor) buildGitHubContext() map[string]interface{} {
	ctx := make(map[string]interface{})

	// Extract from environment variables
	envMappings := map[string]string{
		"actor":      "GITHUB_ACTOR",
		"actor_id":   "GITHUB_ACTOR_ID",
		"repository": "GITHUB_REPOSITORY",
		"api":        "GITHUB_API",
		"token":      "GITHUB_TOKEN",
	}

	for key, envVar := range envMappings {
		if val, ok := e.Context.Env[envVar]; ok {
			ctx[key] = val
		}
	}

	// Add event inputs
	ctx["event"] = map[string]interface{}{
		"inputs": e.Context.Inputs,
	}

	return ctx
}

// executeStepUses executes a step that uses an action.
func (e *WorkflowExecutor) executeStepUses(ctx context.Context, step *PolicyEngineWorkflowJobStep, env map[string]string) error {
	var actionPath string

	if strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, "/") {
		// Local action path: resolve relative to workspace
		if strings.HasPrefix(step.Uses, "/") {
			actionPath = step.Uses
		} else {
			actionPath = filepath.Join(e.Context.Workspace, step.Uses)
		}
		if _, err := os.Stat(actionPath); os.IsNotExist(err) {
			return fmt.Errorf("local action path does not exist: %s", actionPath)
		}
		Debug("action resolved from local path: %s", actionPath)
	} else if strings.Contains(step.Uses, "@") {
		// Remote action: org/repo@version
		// Resolution order:
		//   1. Repo-supplied: $ACTIONS_DIR/{org/repo}/ (from request context env)
		//   2. PE system bundled: $BUNDLED_ACTIONS_DIR/{org/repo}/
		//   3. Download from GitHub
		parts := strings.SplitN(step.Uses, "@", 2)
		orgRepo := parts[0]
		version := parts[1]

		repoActionsDir := env["ACTIONS_DIR"]
		if repoActionsDir == "" {
			repoActionsDir = filepath.Join(e.Context.Workspace, ".tangled", "actions")
		}
		if repoActionsDir != "" {
			repoLocal := filepath.Join(repoActionsDir, orgRepo)
			if _, err := os.Stat(repoLocal); err == nil {
				actionPath = repoLocal
				Debug("action %s resolved from repo-supplied dir: %s", orgRepo, actionPath)
			}
		}
		if actionPath == "" {
			if bundledDir := os.Getenv("BUNDLED_ACTIONS_DIR"); bundledDir != "" {
				bundledPath := filepath.Join(bundledDir, orgRepo)
				if _, err := os.Stat(bundledPath); err == nil {
					actionPath = bundledPath
					Debug("action %s resolved from bundled dir: %s", orgRepo, actionPath)
				}
			}
		}

		if actionPath == "" {
			Debug("downloading action %s@%s from GitHub", orgRepo, version)
			var err error
			actionPath, err = e.downloadAction(orgRepo, version)
			if err != nil {
				return fmt.Errorf("failed to download action: %w", err)
			}
			Debug("action %s downloaded to: %s", orgRepo, actionPath)
		}
	} else {
		return fmt.Errorf("unsupported uses format (expected org/repo@version or ./path): %s", step.Uses)
	}

	// Read action.yml or action.yaml
	var actionYaml []byte
	actionYamlPath := filepath.Join(actionPath, "action.yml")
	if _, err := os.Stat(actionYamlPath); os.IsNotExist(err) {
		actionYamlPath = filepath.Join(actionPath, "action.yaml")
	}
	actionYaml, err := os.ReadFile(actionYamlPath)
	if err != nil {
		return fmt.Errorf("failed to read action.yml: %w", err)
	}

	var actionDef struct {
		Runs struct {
			Using string `yaml:"using"`
			Main  string `yaml:"main"`
			Steps []struct {
				Run   string            `yaml:"run,omitempty"`
				Shell string            `yaml:"shell,omitempty"`
				Env   map[string]string `yaml:"env,omitempty"`
			} `yaml:"steps,omitempty"`
		} `yaml:"runs"`
		Inputs map[string]struct {
			Default string `yaml:"default,omitempty"`
		} `yaml:"inputs,omitempty"`
	}
	if err := yaml.Unmarshal(actionYaml, &actionDef); err != nil {
		return fmt.Errorf("failed to parse action.yml: %w", err)
	}

	// Add default inputs
	for inputName, inputDef := range actionDef.Inputs {
		envKey := "INPUT_" + strings.ToUpper(inputName)
		if _, exists := env[envKey]; !exists && inputDef.Default != "" {
			env[envKey] = e.evaluateExpression(inputDef.Default)
		}
	}

	env["GITHUB_ACTION_PATH"] = actionPath

	// Execute based on action type
	Debug("executing action type: %s", actionDef.Runs.Using)
	switch {
	case strings.HasPrefix(actionDef.Runs.Using, "node"):
		return e.executeNodeAction(ctx, actionPath, actionDef.Runs.Main, env, step.ID)
	case actionDef.Runs.Using == "composite":
		return e.executeCompositeAction(ctx, actionDef.Runs.Steps, env)
	default:
		return fmt.Errorf("unsupported action type: %s", actionDef.Runs.Using)
	}
}

// downloadAction downloads a GitHub Action to the cache directory.
func (e *WorkflowExecutor) downloadAction(orgRepo, version string) (string, error) {
	extractedPath := filepath.Join(e.Context.CacheDir, orgRepo, "extracted")

	// Check if already downloaded
	if _, err := os.Stat(extractedPath); err == nil {
		return extractedPath, nil
	}

	// Create directories
	downloadDir := filepath.Join(e.Context.CacheDir, orgRepo)
	os.MkdirAll(downloadDir, 0755)

	// Try different download URLs
	urls := []string{
		fmt.Sprintf("https://github.com/%s/archive/refs/tags/%s.zip", orgRepo, version),
		fmt.Sprintf("https://github.com/%s/archive/%s.zip", orgRepo, version),
		fmt.Sprintf("https://github.com/%s/archive/refs/heads/%s.zip", orgRepo, version),
	}

	var downloadErr error
	for _, downloadURL := range urls {
		compressedPath := filepath.Join(downloadDir, "compressed.zip")

		// Download
		req, err := http.NewRequest("GET", downloadURL, nil)
		if err != nil {
			downloadErr = err
			continue
		}

		// Add auth if available
		if token, ok := e.Context.Secrets["GITHUB_TOKEN"]; ok && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			downloadErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			downloadErr = fmt.Errorf("download failed with status: %d", resp.StatusCode)
			continue
		}

		// Save to file
		f, err := os.Create(compressedPath)
		if err != nil {
			resp.Body.Close()
			downloadErr = err
			continue
		}
		_, err = io.Copy(f, resp.Body)
		f.Close()
		resp.Body.Close()

		if err != nil {
			downloadErr = err
			continue
		}

		// Extract zip
		extractedTmpPath := filepath.Join(downloadDir, "extracted_tmp")
		if err := unzip(compressedPath, extractedTmpPath); err != nil {
			downloadErr = err
			continue
		}

		// Find the extracted directory (usually repo-version)
		entries, err := os.ReadDir(extractedTmpPath)
		if err != nil || len(entries) == 0 {
			downloadErr = fmt.Errorf("failed to find extracted directory")
			continue
		}

		// Move to final location
		srcDir := filepath.Join(extractedTmpPath, entries[0].Name())
		if err := os.Rename(srcDir, extractedPath); err != nil {
			downloadErr = err
			continue
		}

		os.RemoveAll(extractedTmpPath)
		os.Remove(compressedPath)

		return extractedPath, nil
	}

	return "", fmt.Errorf("failed to download action from any URL: %w", downloadErr)
}

// unzip extracts a zip file to a destination directory.
func unzip(src, dest string) error {
	// Use system unzip command for simplicity
	cmd := exec.Command("unzip", "-q", "-o", src, "-d", dest)
	return cmd.Run()
}

// executeNodeAction executes a Node.js action using Deno (with Node compat) or node as fallback.
func (e *WorkflowExecutor) executeNodeAction(ctx context.Context, actionPath, main string, env map[string]string, stepID string) error {
	if e.DenoPath == "" && e.NodeJSPath == "" {
		return fmt.Errorf("neither deno nor node.js found in PATH")
	}

	// Create GITHUB_OUTPUT, GITHUB_ENV, GITHUB_PATH, and GITHUB_STATE files
	// so that @actions/core functions (setOutput, exportVariable, addPath,
	// saveState) write to ephemeral files we control.
	type ghFile struct {
		envKey string
		prefix string
	}
	ghFiles := []ghFile{
		{"GITHUB_OUTPUT", "node-output-"},
		{"GITHUB_ENV", "node-env-"},
		{"GITHUB_PATH", "node-path-"},
		{"GITHUB_STATE", "node-state-"},
	}
	for _, gf := range ghFiles {
		f, err := os.CreateTemp(e.Context.TempDir, gf.prefix+"*.txt")
		if err != nil {
			return fmt.Errorf("failed to create %s file: %w", gf.envKey, err)
		}
		env[gf.envKey] = f.Name()
		f.Close()
		defer os.Remove(f.Name())
	}

	mainPath := filepath.Join(actionPath, main)

	var cmd *exec.Cmd
	if e.DenoPath != "" {
		// Many actions are bundled as CommonJS (e.g. ncc-compiled dist/index.js
		// using __dirname/__filename), but Deno treats .js files as ES modules
		// by default, which leaves __dirname undefined. Dropping a
		// package.json with "type": "commonjs" at the action root tells Deno's
		// Node compat layer to load the entry point as CommonJS. Skip this if
		// the action already ships its own package.json.
		actionPkgPath := filepath.Join(actionPath, "package.json")
		if _, err := os.Stat(actionPkgPath); os.IsNotExist(err) {
			os.WriteFile(actionPkgPath, []byte(`{"type":"commonjs"}`), 0644)
		}

		// Deno 2.x has built-in Node.js compat; --allow-all grants the broad
		// permissions that standard GitHub Actions expect.
		cmd = exec.CommandContext(ctx, e.DenoPath, "run", "--allow-all", "--no-prompt", mainPath)
	} else {
		cmd = exec.CommandContext(ctx, e.NodeJSPath, mainPath)
	}
	cmd.Dir = e.Context.Workspace
	cmd.Env = mapToEnvSlice(env)

	output, err := e.runAndStreamOutput(cmd)
	outputStr := output.String()
	e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, outputStr)

	// Parse outputs from GITHUB_OUTPUT file
	if stepID != "" {
		if outputFilePath, ok := env["GITHUB_OUTPUT"]; ok {
			if content, readErr := os.ReadFile(outputFilePath); readErr == nil && len(content) > 0 {
				outputs := parseGitHubActionsOutputs(string(content))
				if e.Context.Outputs[stepID] == nil {
					e.Context.Outputs[stepID] = make(map[string]interface{})
				}
				e.Context.Outputs[stepID]["outputs"] = outputs
			}
		}
	}

	// Apply env updates from GITHUB_ENV file
	if envFilePath, ok := env["GITHUB_ENV"]; ok {
		if content, readErr := os.ReadFile(envFilePath); readErr == nil && len(content) > 0 {
			envUpdates := parseGitHubActionsOutputs(string(content))
			for k, v := range envUpdates {
				e.Context.Env[k] = v
			}
		}
	}

	return err
}

// executeCompositeAction executes a composite action.
func (e *WorkflowExecutor) executeCompositeAction(ctx context.Context, steps []struct {
	Run   string            `yaml:"run,omitempty"`
	Shell string            `yaml:"shell,omitempty"`
	Env   map[string]string `yaml:"env,omitempty"`
}, env map[string]string) error {
	for _, step := range steps {
		if step.Run != "" {
			shell := step.Shell
			if shell == "" {
				shell = e.Context.Shell
			}

			stepEnv := make(map[string]string)
			for k, v := range env {
				stepEnv[k] = v
			}
			for k, v := range step.Env {
				stepEnv[k] = e.evaluateExpression(v)
			}

			if err := e.runShellCommand(ctx, step.Run, shell, stepEnv); err != nil {
				return err
			}
		}
	}
	return nil
}

// executeStepRun executes a run step.
func (e *WorkflowExecutor) executeStepRun(ctx context.Context, step *PolicyEngineWorkflowJobStep, env map[string]string) error {
	// Create temp file for the script
	tmpFile, err := os.CreateTemp(e.Context.TempDir, "run-*.sh")
	if err != nil {
		return fmt.Errorf("failed to create temp script: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Evaluate expressions in the run command
	runScript := e.evaluateExpression(step.Run)

	if _, err := tmpFile.WriteString(runScript); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}
	tmpFile.Close()

	// Create output files for GITHUB_OUTPUT and GITHUB_ENV
	outputFile, err := os.CreateTemp(e.Context.TempDir, "output-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	envFile, err := os.CreateTemp(e.Context.TempDir, "env-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create env file: %w", err)
	}
	defer os.Remove(envFile.Name())
	envFile.Close()

	pathFile, err := os.CreateTemp(e.Context.TempDir, "path-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create path file: %w", err)
	}
	defer os.Remove(pathFile.Name())
	pathFile.Close()

	env["GITHUB_OUTPUT"] = outputFile.Name()
	env["GITHUB_ENV"] = envFile.Name()
	env["GITHUB_PATH"] = pathFile.Name()

	shell := e.Context.Shell
	if step.Shell != "" {
		shell = step.Shell
	}

	if err := e.runShellCommand(ctx, runScript, shell, env); err != nil {
		return err
	}

	// Parse outputs
	if step.ID != "" {
		outputContent, _ := os.ReadFile(outputFile.Name())
		outputs := parseGitHubActionsOutputs(string(outputContent))
		if e.Context.Outputs[step.ID] == nil {
			e.Context.Outputs[step.ID] = make(map[string]interface{})
		}
		e.Context.Outputs[step.ID]["outputs"] = outputs
	}

	// Parse env updates
	envContent, _ := os.ReadFile(envFile.Name())
	envUpdates := parseGitHubActionsOutputs(string(envContent))
	for k, v := range envUpdates {
		e.Context.Env[k] = v
	}

	return nil
}

// runShellCommand runs a shell command.
func (e *WorkflowExecutor) runShellCommand(ctx context.Context, script, shell string, env map[string]string) error {
	Debug("running shell command: shell=%s", shell)
	Trace("script content:\n%s", script)
	// Create temp file for the script
	tmpFile, err := os.CreateTemp(e.Context.TempDir, "script-*")
	if err != nil {
		return fmt.Errorf("failed to create temp script: %w", err)
	}
	scriptPath := tmpFile.Name()
	defer os.Remove(scriptPath)

	if _, err := tmpFile.WriteString(script); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}
	tmpFile.Close()

	// Parse shell command
	shellParts := strings.Fields(shell)
	if len(shellParts) == 0 {
		shellParts = []string{"bash", "-xe"}
	}

	// Replace {0} placeholder with script path
	var args []string
	foundPlaceholder := false
	for _, part := range shellParts {
		if strings.Contains(part, "{0}") {
			args = append(args, strings.Replace(part, "{0}", scriptPath, 1))
			foundPlaceholder = true
		} else {
			args = append(args, part)
		}
	}
	if !foundPlaceholder {
		args = append(args, scriptPath)
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = e.Context.Workspace
	cmd.Env = mapToEnvSlice(env)

	// Stream output line-by-line if task is attached
	output, err := e.runAndStreamOutput(cmd)
	outputStr := output.String()
	e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, outputStr)

	// Parse annotations from output
	e.parseAnnotations(outputStr)

	return err
}

// runAndStreamOutput runs a command, captures output, and streams lines to the task if attached.
func (e *WorkflowExecutor) runAndStreamOutput(cmd *exec.Cmd) (bytes.Buffer, error) {
	var output bytes.Buffer

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return output, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	if err := cmd.Start(); err != nil {
		return output, fmt.Errorf("failed to start command: %w", err)
	}

	// Read output line by line and stream to task
	buf := make([]byte, 4096)
	for {
		n, readErr := stdout.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			output.WriteString(chunk)
			lines := strings.Split(chunk, "\n")
			for _, line := range lines {
				if line != "" {
					Trace("| %s", line)
					if e.Task != nil {
						e.Task.AppendConsoleOutput(line)
					}
				}
			}
		}
		if readErr != nil {
			break
		}
	}

	err = cmd.Wait()
	return output, err
}

// parseGitHubActionsOutputs parses GitHub Actions output format.
func parseGitHubActionsOutputs(content string) map[string]string {
	outputs := make(map[string]string)
	var currentKey string
	var currentDelimiter string
	var currentValue strings.Builder

	for _, line := range strings.Split(content, "\n") {
		if currentDelimiter != "" {
			if strings.HasPrefix(line, currentDelimiter) {
				outputs[currentKey] = strings.TrimSuffix(currentValue.String(), "\n")
				currentKey = ""
				currentDelimiter = ""
				currentValue.Reset()
			} else {
				currentValue.WriteString(line + "\n")
			}
		} else if strings.Contains(line, "<<") && currentKey == "" {
			parts := strings.SplitN(line, "<<", 2)
			currentKey = strings.TrimSpace(parts[0])
			currentDelimiter = strings.TrimSpace(parts[1])
		} else if strings.Contains(line, "=") && currentKey == "" {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}
			outputs[key] = value
		}
	}

	return outputs
}

// parseAnnotations parses GitHub Actions workflow commands for annotations.
func (e *WorkflowExecutor) parseAnnotations(output string) {
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "::") {
			continue
		}

		line = strings.TrimPrefix(line, "::")
		parts := strings.SplitN(line, "::", 2)
		if len(parts) < 1 {
			continue
		}

		levelAndParams := parts[0]
		message := ""
		if len(parts) > 1 {
			message = parts[1]
		}

		// Parse level and parameters
		levelParts := strings.SplitN(levelAndParams, " ", 2)
		level := levelParts[0]

		if level != "error" && level != "warning" && level != "notice" {
			continue
		}

		annotation := GitHubCheckSuiteAnnotation{
			AnnotationLevel: level,
			Message:         message,
			Title:           message,
			RawDetails:      line,
		}

		// Parse parameters if present
		if len(levelParts) > 1 {
			params, _ := url.ParseQuery(strings.ReplaceAll(levelParts[1], ",", "&"))
			// GitHub Actions uses 'file' for the path
			if file := params.Get("file"); file != "" {
				annotation.Path = file
			}
			if path := params.Get("path"); path != "" {
				annotation.Path = path
			}
			if title := params.Get("title"); title != "" {
				annotation.Title = title
			}
			if line := params.Get("line"); line != "" {
				if lineNum, err := strconv.Atoi(line); err == nil {
					annotation.StartLine = lineNum
					annotation.EndLine = lineNum
				}
			}
			if endLine := params.Get("endLine"); endLine != "" {
				if lineNum, err := strconv.Atoi(endLine); err == nil {
					annotation.EndLine = lineNum
				}
			}
		}

		e.Context.Annotations[level] = append(e.Context.Annotations[level], annotation)
	}
}

// parseOutputs parses outputs from command output (for Node actions).
func (e *WorkflowExecutor) parseOutputs(output string) {
	// Node actions typically use core.setOutput which writes to GITHUB_OUTPUT
	// The actual parsing is done in executeStepRun
}

// mapToEnvSlice converts a map to an environment slice.
func mapToEnvSlice(env map[string]string) []string {
	// Start with current environment
	result := os.Environ()
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// createSuccessStatus creates a success status response.
func (e *WorkflowExecutor) createSuccessStatus() *PolicyEngineStatus {
	annotations := make(map[string]interface{})
	for level, annots := range e.Context.Annotations {
		annotations[level] = annots
	}

	return &PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:          "",
			ExitStatus:  ExitStatusSuccess,
			Outputs:     make(map[string]interface{}),
			Annotations: annotations,
		},
		ConsoleOutput: strings.Join(e.Context.ConsoleOutput, "\n"),
	}
}

// createErrorStatus creates an error status response.
func (e *WorkflowExecutor) createErrorStatus(err error) *PolicyEngineStatus {
	annotations := make(map[string]interface{})
	for level, annots := range e.Context.Annotations {
		annotations[level] = annots
	}
	annotations["error"] = []string{err.Error()}

	return &PolicyEngineStatus{
		Status: StatusComplete,
		Detail: PolicyEngineComplete{
			ID:          "",
			ExitStatus:  ExitStatusFailure,
			Outputs:     make(map[string]interface{}),
			Annotations: annotations,
		},
		ConsoleOutput: strings.Join(e.Context.ConsoleOutput, "\n"),
	}
}

// renderTemplate renders a Go template string with the given data.
func renderTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("expr").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
