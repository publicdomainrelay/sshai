package main

import (
	"bytes"
	"context"
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
}

// NewWorkflowExecutor creates a new workflow executor.
func NewWorkflowExecutor() *WorkflowExecutor {
	return &WorkflowExecutor{
		DenoPath:   findBinary("deno"),
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
	workflow, err := ParseWorkflow(request.Workflow)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	// Initialize context from request
	if err := e.initializeContext(request); err != nil {
		return nil, fmt.Errorf("failed to initialize context: %w", err)
	}

	// Execute each job
	for jobName, job := range workflow.Jobs {
		if err := e.executeJob(ctx, jobName, &job); err != nil {
			// Record error but continue to allow cleanup
			e.Context.Error = err
			return e.createErrorStatus(err), nil
		}
	}

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
				continue
			}
		}

		// Set shell if specified
		if step.Shell != "" {
			e.Context.Shell = step.Shell
		}

		// Build step environment
		stepEnv := e.buildStepEnv(&step)

		// Execute step
		var err error
		if step.Uses != "" {
			err = e.executeStepUses(ctx, &step, stepEnv)
		} else if step.Run != "" {
			err = e.executeStepRun(ctx, &step, stepEnv)
		}

		if err != nil {
			return fmt.Errorf("step %s failed: %w", stepName, err)
		}
	}

	return nil
}

// evaluateCondition evaluates an if condition.
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
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "true" || v == "1" {
			return true, nil
		}
		if v == "false" || v == "0" {
			return false, nil
		}
		// For complex expressions, we'd need JavaScript evaluation
		// For now, default to true
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
	env["RUNNER_TOOL_CACHE"] = e.Context.TempDir

	return env
}

// evaluateExpression evaluates GitHub Actions expressions like ${{ ... }}.
func (e *WorkflowExecutor) evaluateExpression(expr string) string {
	if !strings.Contains(expr, "${{") {
		return expr
	}

	// Build context for template
	data := map[string]interface{}{
		"github": e.buildGitHubContext(),
		"steps":  e.Context.Outputs,
		"inputs": e.Context.Inputs,
		"env":    e.Context.Env,
	}

	// Simple regex-based replacement for ${{ expression }}
	re := regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)
	result := re.ReplaceAllStringFunc(expr, func(match string) string {
		// Extract the expression
		inner := re.FindStringSubmatch(match)[1]
		inner = strings.TrimSpace(inner)

		// Handle simple property access like github.actor
		value := e.resolvePropertyPath(inner, data)
		if value != nil {
			return fmt.Sprintf("%v", value)
		}
		return match
	})

	return result
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
	if !strings.Contains(step.Uses, "@") {
		return fmt.Errorf("only uses: org/repo@version is supported, got: %s", step.Uses)
	}

	// Parse uses format: org/repo@version
	parts := strings.SplitN(step.Uses, "@", 2)
	orgRepo := parts[0]
	version := parts[1]

	// Download the action
	actionPath, err := e.downloadAction(orgRepo, version)
	if err != nil {
		return fmt.Errorf("failed to download action: %w", err)
	}

	// Read action.yml or action.yaml
	var actionYaml []byte
	actionYamlPath := filepath.Join(actionPath, "action.yml")
	if _, err := os.Stat(actionYamlPath); os.IsNotExist(err) {
		actionYamlPath = filepath.Join(actionPath, "action.yaml")
	}
	actionYaml, err = os.ReadFile(actionYamlPath)
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
	switch {
	case strings.HasPrefix(actionDef.Runs.Using, "node"):
		return e.executeNodeAction(ctx, actionPath, actionDef.Runs.Main, env)
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

// executeNodeAction executes a Node.js action.
func (e *WorkflowExecutor) executeNodeAction(ctx context.Context, actionPath, main string, env map[string]string) error {
	if e.NodeJSPath == "" {
		return fmt.Errorf("node.js not found in PATH")
	}

	mainPath := filepath.Join(actionPath, main)

	cmd := exec.CommandContext(ctx, e.NodeJSPath, mainPath)
	cmd.Dir = e.Context.Workspace
	cmd.Env = mapToEnvSlice(env)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, output.String())

	// Parse outputs
	e.parseOutputs(output.String())

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

	env["GITHUB_OUTPUT"] = outputFile.Name()
	env["GITHUB_ENV"] = envFile.Name()

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

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err = cmd.Run()
	e.Context.ConsoleOutput = append(e.Context.ConsoleOutput, output.String())

	// Parse annotations from output
	e.parseAnnotations(output.String())

	return err
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
