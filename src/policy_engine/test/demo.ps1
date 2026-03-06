# Policy Engine Demo Script (PowerShell)
# This script demonstrates policy engine CLI capabilities

param(
    [string]$ApiEndpoint = "http://localhost:8080",
    [string]$PolicyEngine = "./policy_engine.exe"
)

Write-Host "🚀 Policy Engine Demo" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan

# Check if policy engine binary exists
if (-not (Test-Path $PolicyEngine)) {
    Write-Host "❌ Policy engine binary not found. Building..." -ForegroundColor Red
    go build -o policy_engine.exe ./cmd/policy-engine/
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to build policy engine" -ForegroundColor Red
        exit 1
    }
}

# Start API server in background
Write-Host "🔧 Starting API server..." -ForegroundColor Yellow
$ServerProcess = Start-Process -FilePath $PolicyEngine -ArgumentList "api" -PassThru -WindowStyle Hidden

# Wait for server to start
Write-Host "⏳ Waiting for server to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Check if server is running
try {
    $response = Invoke-RestMethod -Uri "$ApiEndpoint/health" -Method Get -TimeoutSec 5
    Write-Host "✅ Server started successfully" -ForegroundColor Green
}
catch {
    Write-Host "❌ Server failed to start" -ForegroundColor Red
    Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host ""

# Demo 1: Basic workflow
Write-Host "📋 Demo 1: Basic workflow" -ForegroundColor Cyan
Write-Host "---------------------------" -ForegroundColor Cyan

$basicWorkflow = @"
name: Basic Demo
on: push

jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
    - name: Say Hello
      run: echo "Hello from policy engine!"
    - name: Show Environment
      run: |
        echo "Repository: `$env:GITHUB_REPOSITORY"
        echo "Actor: `$env:GITHUB_ACTOR"
"@

Set-Content -Path "basic_workflow.yml" -Value $basicWorkflow

Write-Host "📤 Submitting basic workflow..." -ForegroundColor Yellow
$createResponse = & $PolicyEngine client create `
    --endpoint $ApiEndpoint `
    --workflow ./basic_workflow.yml `
    --repository demo/hello `
    --output-format json

$taskId = ($createResponse | ConvertFrom-Json).detail.id
Write-Host "🆔 Task ID: $taskId" -ForegroundColor Green

Write-Host "⏳ Polling for completion..." -ForegroundColor Yellow
& $PolicyEngine client status `
    --endpoint $ApiEndpoint `
    --task-id $taskId `
    --wait `
    --output-format yaml

Write-Host ""
Write-Host "📄 Demo 1 completed" -ForegroundColor Green
Write-Host ""

# Demo 2: Workflow with inputs and secrets
Write-Host "📋 Demo 2: Workflow with inputs and secrets" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan

$inputWorkflow = @"
name: Input Demo
on: workflow_dispatch

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
    - name: Process inputs
      env:
        STEP_NAME: process_data
      run: |
        echo "Processing with inputs:"
        echo "Environment: `${{ inputs.environment }}"
        echo "Version: `${{ inputs.version }}"
        echo "Step name: `$env:STEP_NAME"
    - name: Use secret
      run: |
        echo "Using API key: `${{ secrets.API_KEY }}"
        echo "Database: `${{ secrets.DATABASE_URL }}"
"@

Set-Content -Path "input_workflow.yml" -Value $inputWorkflow

$contextJson = @{
    secrets = @{
        API_KEY = "sk-1234567890"
        DATABASE_URL = "postgres://user:password@localhost:5432/mydb"
    }
} | ConvertTo-Json -Compress

Write-Host "📤 Submitting workflow with inputs and secrets..." -ForegroundColor Yellow
$createResponse2 = & $PolicyEngine client create `
    --endpoint $ApiEndpoint `
    --workflow ./input_workflow.yml `
    --repository demo/input `
    --input environment=staging `
    --input version=2.1.0 `
    --context $contextJson `
    --output-format json

$taskId2 = ($createResponse2 | ConvertFrom-Json).detail.id
Write-Host "🆔 Task ID: $taskId2" -ForegroundColor Green

Write-Host "⏳ Polling for completion..." -ForegroundColor Yellow
& $PolicyEngine client status `
    --endpoint $ApiEndpoint `
    --task-id $taskId2 `
    --wait `
    --output-format json | ConvertFrom-Json

Write-Host ""
Write-Host "📄 Demo 2 completed" -ForegroundColor Green
Write-Host ""

# Demo 3: Multi-job workflow
Write-Host "📋 Demo 3: Multi-job workflow" -ForegroundColor Cyan
Write-Host "------------------------------" -ForegroundColor Cyan

$multiJobWorkflow = @"
name: Multi-Job Demo
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - name: Build
      run: |
        echo "🏗️ Building application..."
        echo "version=1.2.3" >> `$env:GITHUB_OUTPUT
        
  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
    - name: Test
      run: |
        echo "🧪 Running tests..."
        echo "All tests passed!"
        
  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - name: Deploy
      run: |
        echo "🚀 Deploying application..."
        echo "Deployment complete!"
"@

Set-Content -Path "multi_job_workflow.yml" -Value $multiJobWorkflow

Write-Host "📤 Submitting multi-job workflow..." -ForegroundColor Yellow
$createResponse3 = & $PolicyEngine client create `
    --endpoint $ApiEndpoint `
    --workflow ./multi_job_workflow.yml `
    --repository demo/multi `
    --output-format json

$taskId3 = ($createResponse3 | ConvertFrom-Json).detail.id
Write-Host "🆔 Task ID: $taskId3" -ForegroundColor Green

Write-Host "⏳ Polling for completion..." -ForegroundColor Yellow
& $PolicyEngine client status `
    --endpoint $ApiEndpoint `
    --task-id $taskId3 `
    --wait `
    --output-format yaml

Write-Host ""
Write-Host "📄 Demo 3 completed" -ForegroundColor Green
Write-Host ""

# Demo 4: Error handling and annotations
Write-Host "📋 Demo 4: Error handling and annotations" -ForegroundColor Cyan
Write-Host "------------------------------------------" -ForegroundColor Cyan

$errorWorkflow = @"
name: Error Demo
on: push

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
    - name: Validate
      run: |
        echo "::notice title=Validation::Starting validation..."
        if [ -f "nonexistent.txt" ]; then
          echo "File exists"
        else
          echo "::warning::File not found, but continuing..."
        fi
        
  process:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
    - name: Process with error
      run: |
        echo "::error file=app.js,line=42::Syntax error: Missing semicolon"
        echo "This step will fail but workflow continues"
        exit 1
        
  cleanup:
    needs: process
    runs-on: ubuntu-latest
    steps:
    - name: Cleanup
      run: |
        echo "::notice title=Cleanup::Cleaning up resources..."
        echo "Cleanup complete"
"@

Set-Content -Path "error_workflow.yml" -Value $errorWorkflow

Write-Host "📤 Submitting workflow with errors and annotations..." -ForegroundColor Yellow
$createResponse4 = & $PolicyEngine client create `
    --endpoint $ApiEndpoint `
    --workflow ./error_workflow.yml `
    --repository demo/errors `
    --output-format json

$taskId4 = ($createResponse4 | ConvertFrom-Json).detail.id
Write-Host "🆔 Task ID: $taskId4" -ForegroundColor Green

Write-Host "⏳ Polling for completion..." -ForegroundColor Yellow
& $PolicyEngine client status `
    --endpoint $ApiEndpoint `
    --task-id $taskId4 `
    --wait `
    --output-format json | ConvertFrom-Json

Write-Host ""
Write-Host "📄 Demo 4 completed" -ForegroundColor Green
Write-Host ""

# Clean up
Write-Host "🧹 Cleaning up..." -ForegroundColor Yellow
Write-Host "Stopping server..." -ForegroundColor Yellow
Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue

# Clean up workflow files
Remove-Item -Path "basic_workflow.yml", "input_workflow.yml", "multi_job_workflow.yml", "error_workflow.yml" -Force -ErrorAction SilentlyContinue

Write-Host "✅ Demo completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📚 Policy Engine Features Demonstrated:" -ForegroundColor Cyan
Write-Host "  • Basic workflow execution" -ForegroundColor White
Write-Host "  • Input parameter handling" -ForegroundColor White
Write-Host "  • Secret management" -ForegroundColor White
Write-Host "  • Multi-job workflows with dependencies" -ForegroundColor White
Write-Host "  • Error handling and annotations" -ForegroundColor White
Write-Host "  • Multiple output formats (JSON/YAML)" -ForegroundColor White
Write-Host "  • Polling for completion" -ForegroundColor White
Write-Host ""
Write-Host "🎉 Thank you for trying Policy Engine!" -ForegroundColor Green