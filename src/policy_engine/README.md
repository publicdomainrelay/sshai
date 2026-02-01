# Policy Engine CLI

A Go implementation of GitHub Actions workflow evaluation with comprehensive CLI support.

## Features

- **Workflow Execution**: Execute GitHub Actions workflows
- **HTTP API**: RESTful API for submitting and monitoring workflows
- **YAML/JSON Support**: Workflows and context in both YAML and JSON formats
- **Task Management**: Async task execution with status tracking
- **Output Formatting**: JSON and YAML output formats
- **Annotation Support**: GitHub Actions annotations (errors, warnings, notices)
- **Environment Variables**: Full support for workflow environment and secrets
- **Multi-Job Workflows**: Execute complex workflows with multiple jobs

## Installation

```bash
# Build from source
go build -o policy_engine main.go

# Or install globally
go install
```

## Quick Start

### 1. Start the API Server

```bash
# Start server on default port 8080
./policy_engine api

# Start server on custom port
./policy_engine api --bind 0.0.0.0:9090
```

### 2. Submit a Workflow

```bash
# Submit workflow from file
./policy_engine client --endpoint http://localhost:8080 create \
  --workflow ./workflow.yml \
  --repository myorg/myrepo

# Submit workflow with inputs
./policy_engine client --endpoint http://localhost:8080 create \
  --workflow ./workflow.yml \
  --repository myorg/myrepo \
  --input name=test \
  --input version=1.0

# Submit inline workflow
./policy_engine client --endpoint http://localhost:8080 create \
  --workflow 'name: test\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo hello' \
  --repository myorg/myrepo
```

### 3. Check Status

```bash
# Get current status
./policy_engine client --endpoint http://localhost:8080 status --task-id abc-123

# Wait for completion
./policy_engine client --endpoint http://localhost:8080 status --task-id abc-123 --wait
```

## CLI Commands

### `api`

Start the HTTP API server.

```bash
./policy_engine api [flags]

Flags:
  --bind string       Address to bind server to (default "127.0.0.1:8080")
  --workers int       Number of workers (default: CPU*2+1)
```

### `client`

Interact with the API server.

```bash
./policy_engine client [command] [flags]

Global Flags:
  --endpoint string    API endpoint URL (required)
  --timeout int        Timeout in seconds (default 300)
  --output-format string  Output format: json, yaml (default "json")
```

#### `client create`

Submit a new workflow for execution.

```bash
./policy_engine client create [flags]

Flags:
  --workflow string       Workflow file path or inline YAML (required)
  --repository string    Repository in org/repo format (required)
  --input strings       Input key=value pairs (multiple allowed)
  --context string      Additional JSON context (default "{}")
```

#### `client status`

Check status of a workflow execution.

```bash
./policy_engine client status [flags]

Flags:
  --task-id string        Task ID to check (required)
  --poll-interval       Poll interval in seconds (default 0.5)
  --wait               Wait for completion
```

## Workflow Format

Workflows use GitHub Actions YAML format:

```yaml
name: Example Workflow
on:
  push:
    branches:
    - main

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - name: Check out code
      uses: actions/checkout@v3
      
    - name: Run tests
      env:
        NODE_ENV: test
      run: |
        npm install
        npm test
        echo "result=success" >> $GITHUB_OUTPUT
```

## Context Format

Context can be provided as JSON:

```json
{
  "config": {
    "env": {
      "GITHUB_REPOSITORY": "myorg/myrepo",
      "GITHUB_ACTOR": "testuser",
      "NODE_ENV": "production"
    }
  },
  "secrets": {
    "API_TOKEN": "secret-token",
    "DATABASE_URL": "postgres://user:pass@localhost/db"
  },
  "stack": {
    "version": "1.2.3",
    "environment": "staging"
  }
}
```

## Input Format

Inputs can be provided as key=value pairs:

```bash
# Simple values
--input name=myapp
--input version=1.2.3

# JSON values
--input config='{"env": "production", "debug": false}'

# Arrays/objects
--input list='["item1", "item2"]'
```

## Output Formats

### JSON (default)

```json
{
  "status": "complete",
  "detail": {
    "id": "abc-123",
    "exit_status": "success",
    "outputs": {},
    "annotations": {
      "warning": [],
      "error": [],
      "notice": []
    }
  },
  "console_output": "Building...\nTesting...\nDeploying..."
}
```

### YAML

```yaml
status: complete
detail:
  id: abc-123
  exit_status: success
  outputs: {}
  annotations:
    warning: []
    error: []
    notice: []
console_output: |
  Building...
  Testing...
  Deploying...
```

## API Endpoints

### POST `/request/create`

Submit a workflow for execution.

**Request:**
```json
{
  "workflow": "name: test\njobs: {...}",
  "context": {"config": {"env": {"GITHUB_REPOSITORY": "org/repo"}}},
  "inputs": {"name": "test", "version": "1.0"}
}
```

**Response:**
```json
{
  "status": "submitted",
  "detail": {"id": "task-123"}
}
```

### GET `/request/status/{task_id}`

Get execution status.

**Response:**
```json
{
  "status": "complete",
  "detail": {
    "id": "task-123",
    "exit_status": "success"
  }
}
```

### GET `/request/console_output/{task_id}`

Get console output (text/plain).

### POST `/webhook/github`

GitHub webhook endpoint.

### GET `/health`

Health check.

## Examples

### Basic Workflow

```bash
# workflow.yml
name: Hello World
on: push

jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
    - run: echo "Hello from workflow!"
```

```bash
# Submit
./policy_engine client \
  --endpoint http://localhost:8080 \
  create \
  --workflow ./workflow.yml \
  --repository myorg/myrepo
```

### Workflow with Inputs and Secrets

```bash
# Submit with inputs and context
./policy_engine client \
  --endpoint http://localhost:8080 \
  create \
  --workflow ./workflow.yml \
  --repository myorg/myrepo \
  --input environment=production \
  --input version=2.0 \
  --context '{
    "secrets": {
      "API_KEY": "secret-key-123",
      "DATABASE_URL": "postgres://user:pass@localhost/db"
    }
  }'
```

### Poll for Completion

```bash
# Submit and get task ID
TASK_ID=$(./policy_engine client \
  --endpoint http://localhost:8080 \
  create \
  --workflow ./workflow.yml \
  --repository myorg/myrepo \
  --output-format json | jq -r '.detail.id')

# Poll for completion
./policy_engine client \
  --endpoint http://localhost:8080 \
  status \
  --task-id $TASK_ID \
  --wait \
  --output-format yaml
```

## Annotations

The policy engine supports GitHub Actions annotations:

```yaml
steps:
- name: Annotate
  run: |
    echo "::error file=app.js,line=42::Syntax error: Missing semicolon"
    echo "::warning::Deprecated function used"
    echo "::notice title=Info::Build completed successfully"
```

## Error Handling

- Workflows stop on first failed step (unless `continue-on-error: true`)
- Annotations are captured and included in response
- Exit status indicates overall success/failure
- Console output contains all command output

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific tests
go test -run TestExecuteWorkflowTask
```

### Building

```bash
# Build binary
go build -o policy_engine main.go

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o policy_engine-linux main.go
GOOS=windows GOARCH=amd64 go build -o policy_engine.exe main.go
GOOS=darwin GOARCH=amd64 go build -o policy_engine-mac main.go
```

## Architecture

- **HTTP Server**: RESTful API using net/http
- **Task Management**: In-memory task tracking with goroutines
- **Workflow Execution**: GitHub Actions-compatible step execution
- **Context Management**: Environment variables, secrets, and inputs
- **Output Processing**: GitHub Actions annotations and outputs parsing

## License

MIT License - see LICENSE file for details.