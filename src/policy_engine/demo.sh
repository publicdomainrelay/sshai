#!/bin/bash

# Policy Engine Demo Script
# This script demonstrates the policy engine CLI capabilities

set -e

# Configuration
API_ENDPOINT="http://localhost:8080"
POLICY_ENGINE="./policy_engine"

echo "🚀 Policy Engine Demo"
echo "===================="

# Check if policy engine binary exists
if [ ! -f "$POLICY_ENGINE" ]; then
    echo "❌ Policy engine binary not found. Building..."
    go build -o policy_engine main.go
fi

# Start the API server in background
echo "🔧 Starting API server..."
$POLICY_ENGINE api &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 3

# Check if server is running
if ! curl -s "$API_ENDPOINT/health" > /dev/null; then
    echo "❌ Server failed to start"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "✅ Server started successfully"
echo ""

# Demo 1: Basic workflow
echo "📋 Demo 1: Basic workflow"
echo "---------------------------"

cat > basic_workflow.yml << 'EOF'
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
        echo "Repository: $GITHUB_REPOSITORY"
        echo "Actor: $GITHUB_ACTOR"
EOF

echo "📤 Submitting basic workflow..."
TASK_ID=$($POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  create \
  --workflow ./basic_workflow.yml \
  --repository demo/hello \
  --output-format json | jq -r '.detail.id')

echo "🆔 Task ID: $TASK_ID"

echo "⏳ Polling for completion..."
$POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  status \
  --task-id $TASK_ID \
  --wait \
  --output-format yaml

echo ""
echo "📄 Demo 1 completed"
echo ""

# Demo 2: Workflow with inputs and secrets
echo "📋 Demo 2: Workflow with inputs and secrets"
echo "----------------------------------------"

cat > input_workflow.yml << 'EOF'
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
        echo "Environment: ${{ inputs.environment }}"
        echo "Version: ${{ inputs.version }}"
        echo "Step name: $STEP_NAME"
    - name: Use secret
      run: |
        echo "Using API key: ${{ secrets.API_KEY }}"
        echo "Database: ${{ secrets.DATABASE_URL }}"
EOF

echo "📤 Submitting workflow with inputs and secrets..."
TASK_ID2=$($POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  create \
  --workflow ./input_workflow.yml \
  --repository demo/input \
  --input environment=staging \
  --input version=2.1.0 \
  --context '{
    "secrets": {
      "API_KEY": "sk-1234567890",
      "DATABASE_URL": "postgres://user:password@localhost:5432/mydb"
    }
  }' \
  --output-format json | jq -r '.detail.id')

echo "🆔 Task ID: $TASK_ID2"

echo "⏳ Polling for completion..."
$POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  status \
  --task-id $TASK_ID2 \
  --wait \
  --output-format json | jq .

echo ""
echo "📄 Demo 2 completed"
echo ""

# Demo 3: Multi-job workflow
echo "📋 Demo 3: Multi-job workflow"
echo "------------------------------"

cat > multi_job_workflow.yml << 'EOF'
name: Multi-Job Demo
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - name: Build
      run: |
        echo "🏗️ Building application..."
        echo "version=1.2.3" >> $GITHUB_OUTPUT
        
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
EOF

echo "📤 Submitting multi-job workflow..."
TASK_ID3=$($POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  create \
  --workflow ./multi_job_workflow.yml \
  --repository demo/multi \
  --output-format json | jq -r '.detail.id')

echo "🆔 Task ID: $TASK_ID3"

echo "⏳ Polling for completion..."
$POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  status \
  --task-id $TASK_ID3 \
  --wait \
  --output-format yaml

echo ""
echo "📄 Demo 3 completed"
echo ""

# Demo 4: Error handling and annotations
echo "📋 Demo 4: Error handling and annotations"
echo "------------------------------------------"

cat > error_workflow.yml << 'EOF'
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
EOF

echo "📤 Submitting workflow with errors and annotations..."
TASK_ID4=$($POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  create \
  --workflow ./error_workflow.yml \
  --repository demo/errors \
  --output-format json | jq -r '.detail.id')

echo "🆔 Task ID: $TASK_ID4"

echo "⏳ Polling for completion..."
$POLICY_ENGINE client \
  --endpoint $API_ENDPOINT \
  status \
  --task-id $TASK_ID4 \
  --wait \
  --output-format json | jq .

echo ""
echo "📄 Demo 4 completed"
echo ""

# Clean up
echo "🧹 Cleaning up..."
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true

# Clean up workflow files
rm -f basic_workflow.yml input_workflow.yml multi_job_workflow.yml error_workflow.yml

echo "✅ Demo completed successfully!"
echo ""
echo "📚 Policy Engine Features Demonstrated:"
echo "  • Basic workflow execution"
echo "  • Input parameter handling"
echo "  • Secret management"
echo "  • Multi-job workflows with dependencies"
echo "  • Error handling and annotations"
echo "  • Multiple output formats (JSON/YAML)"
echo "  • Polling for completion"
echo ""
echo "🎉 Thank you for trying Policy Engine!"