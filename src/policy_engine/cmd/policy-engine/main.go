// Package main implements a Go port of the Python policy_engine.py.
// This policy engine evaluates GitHub Actions workflows and provides
// an HTTP API for submitting and monitoring workflow executions.
//
// Usage:
//
//	policy_engine api --bind 127.0.0.1:0 --port-file .port
//	policy_engine api --bind /tmp/pe.sock
//	policy_engine client -e http://127.0.0.1:8080 create -w workflow.yml -R org/repo
//	policy_engine client -e unix:/tmp/pe.sock create -w workflow.yml -R org/repo
//	policy_engine client -e "$ENDPOINT" output -t <id> --follow
//	policy_engine client -e "$ENDPOINT" status -t <id> --wait
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"policy_engine/common"

	"github.com/spf13/cobra"
)

var (
	// Version is set at build time
	Version = "dev"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "policy_engine",
	Short: "Policy Engine - GitHub Actions workflow evaluation",
	Long: `Policy Engine implements GitHub Actions workflow evaluation.

This is a Go port of the Python policy_engine.py, providing:
- HTTP API for submitting and monitoring workflow executions
- GitHub webhook integration
- Workflow step execution (uses, run)
- Client CLI for interacting with the API

Example: start the server on a random port, submit a workflow, stream output,
and check the status.

  # 1. Create a workflow file
  cat > my_workflow.yml <<'EOF'
  name: Hello World
  jobs:
    greet:
      runs-on: ubuntu-latest
      steps:
      - id: say-hello
        run: |
          echo "Hello from the policy engine!"
          echo "greeting=hello" >> $GITHUB_OUTPUT
      - env:
          MSG: "${{ steps.say-hello.outputs.greeting }}"
        run: |
          echo "Output from previous step: $MSG"
  EOF

  # 2. Start the API server on a random port; the bound address is
  #    written to .port so other processes can discover it.
  policy_engine api --bind 127.0.0.1:0 --port-file .port &
  while [ ! -s .port ]; do sleep 0.1; done
  ENDPOINT="http://$(cat .port)"

  # 3. Submit the workflow and capture the task ID
  TASK_ID=$(policy_engine client -e "$ENDPOINT" create \
    -w my_workflow.yml -R myorg/myrepo \
    -i key=value \
    | jq -r '.detail.id')

  # 4. Stream console output in real time (follows until done)
  policy_engine client -e "$ENDPOINT" output \
    -t "$TASK_ID" --follow

  # 5. Check the final status (poll until complete)
  policy_engine client -e "$ENDPOINT" status \
    -t "$TASK_ID" --wait

  # Or get the status as YAML
  policy_engine client -e "$ENDPOINT" status \
    -t "$TASK_ID" --wait --output-format yaml

Unix socket example (avoids allocating a TCP port entirely):

  # Start on a Unix socket
  policy_engine api --bind /tmp/pe.sock --port-file .port &
  while [ ! -s .port ]; do sleep 0.1; done

  # The client accepts "unix:" endpoints
  TASK_ID=$(policy_engine client -e unix:/tmp/pe.sock create \
    -w my_workflow.yml -R myorg/myrepo \
    | jq -r '.detail.id')
  policy_engine client -e unix:/tmp/pe.sock output -t "$TASK_ID" -f
  policy_engine client -e unix:/tmp/pe.sock status -t "$TASK_ID" --wait

You can also use the HTTP API directly with curl:

  # Submit a workflow (TCP)
  curl -s -X POST http://127.0.0.1:8080/request/create \
    -H 'Content-Type: application/json' \
    -d '{
      "workflow": "name: Test\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo hi",
      "context": {"config": {"env": {"GITHUB_REPOSITORY": "org/repo"}}}
    }'

  # Submit via Unix socket
  curl -s --unix-socket /tmp/pe.sock http://localhost/request/create \
    -H 'Content-Type: application/json' \
    -d '{"workflow": "...", "context": {"config": {"env": {"GITHUB_REPOSITORY": "org/repo"}}}}'

  # Check status / stream output
  curl -s http://127.0.0.1:8080/request/status/<task-id>
  curl -N http://127.0.0.1:8080/request/console_output_stream/<task-id>`,
	Version: Version,
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Run the API server",
	Long:  `Start the HTTP API server for the policy engine.`,
	Run:   runAPIServer,
}

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Run a background worker",
	Long:  `Start a background worker for processing async tasks. (In this Go implementation, tasks are processed in-process.)`,
	Run:   runWorker,
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client for interacting with the API",
	Long:  `Client CLI for creating and monitoring workflow executions.`,
}

var clientCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a workflow execution request",
	Long:  `Submit a workflow for execution.`,
	Run:   runClientCreate,
}

var clientStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get status of a workflow execution",
	Long:  `Retrieve the status of a submitted workflow execution.`,
	Run:   runClientStatus,
}

var clientOutputCmd = &cobra.Command{
	Use:   "output",
	Short: "Get console output of a workflow execution",
	Long:  `Retrieve the console output of a workflow execution. Use --follow to stream output as it runs.`,
	Run:   runClientOutput,
}

// CLI flags
var (
	// API flags
	apiBind     string
	apiPortFile string
	apiWorkers  int

	// Client flags
	clientEndpoint    string
	clientTimeout     int
	clientOutputFormat string

	// Client create flags
	clientWorkflow   string
	clientRepository string
	clientInputs     []string
	clientContext    string

	// Client status flags
	clientTaskID       string
	clientPollInterval float64
	clientWait         bool

	// Client output flags
	clientOutputTaskID string
	clientFollow       bool
)

func init() {
	// API command flags
	apiCmd.Flags().StringVar(&apiBind, "bind", "127.0.0.1:8080", "Address to bind (host:port, :0 for random port, or /path/to/socket for Unix socket)")
	apiCmd.Flags().StringVar(&apiPortFile, "port-file", "", "Write the bound address to this file after listening (useful with --bind :0)")
	apiCmd.Flags().IntVar(&apiWorkers, "workers", defaultWorkers(), "Number of workers (informational, Go uses goroutines)")

	// Worker command flags
	workerCmd.Flags().StringVar(&apiBind, "bind", "127.0.0.1:8080", "Address of API server to connect to")

	// Client command flags
	clientCmd.PersistentFlags().StringVarP(&clientEndpoint, "endpoint", "e", "", "API endpoint URL (required)")
	clientCmd.PersistentFlags().IntVar(&clientTimeout, "timeout", 300, "Timeout in seconds")
	clientCmd.PersistentFlags().StringVar(&clientOutputFormat, "output-format", "json", "Output format (json, yaml)")
	clientCmd.MarkPersistentFlagRequired("endpoint")

	// Client create flags
	clientCreateCmd.Flags().StringVarP(&clientWorkflow, "workflow", "w", "", "Workflow file path or inline YAML (required)")
	clientCreateCmd.Flags().StringVarP(&clientRepository, "repository", "R", "", "Repository (org/repo) (required)")
	clientCreateCmd.Flags().StringArrayVarP(&clientInputs, "input", "i", []string{}, "Input key=value pairs")
	clientCreateCmd.Flags().StringVarP(&clientContext, "context", "c", "{}", "JSON context")
	clientCreateCmd.MarkFlagRequired("workflow")
	clientCreateCmd.MarkFlagRequired("repository")

	// Client status flags
	clientStatusCmd.Flags().StringVarP(&clientTaskID, "task-id", "t", "", "Task ID to check status for (required)")
	clientStatusCmd.Flags().Float64VarP(&clientPollInterval, "poll-interval-in-seconds", "p", 0.5, "Poll interval in seconds")
	clientStatusCmd.Flags().BoolVar(&clientWait, "wait", false, "Wait for completion")
	clientStatusCmd.MarkFlagRequired("task-id")

	// Client output flags
	clientOutputCmd.Flags().StringVarP(&clientOutputTaskID, "task-id", "t", "", "Task ID to get output for (required)")
	clientOutputCmd.Flags().BoolVarP(&clientFollow, "follow", "f", false, "Follow/stream output as it runs (SSE)")
	clientOutputCmd.MarkFlagRequired("task-id")

	// Build command tree
	clientCmd.AddCommand(clientCreateCmd)
	clientCmd.AddCommand(clientStatusCmd)
	clientCmd.AddCommand(clientOutputCmd)
	rootCmd.AddCommand(apiCmd)
	rootCmd.AddCommand(workerCmd)
	rootCmd.AddCommand(clientCmd)
}

func defaultWorkers() int {
	return (runtime.NumCPU() * 2) + 1
}

func runAPIServer(cmd *cobra.Command, args []string) {
	log.Printf("Starting Policy Engine API server")
	log.Printf("Bind: %s", apiBind)
	log.Printf("Go routines will handle concurrent requests")

	server := common.NewServer(apiBind)

	// Create listener first so we know the bound address before serving.
	ln, err := server.Listen()
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}

	boundAddr := server.BoundAddr()
	log.Printf("Listening on %s", boundAddr)

	// Write port file if requested.
	if apiPortFile != "" {
		if err := os.WriteFile(apiPortFile, []byte(boundAddr), 0644); err != nil {
			log.Fatalf("Failed to write port file %s: %v", apiPortFile, err)
		}
		log.Printf("Wrote bound address to %s", apiPortFile)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
		// Clean up port file on shutdown.
		if apiPortFile != "" {
			os.Remove(apiPortFile)
		}
	}()

	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func runWorker(cmd *cobra.Command, args []string) {
	log.Println("Worker mode: In Go implementation, tasks are processed in-process with goroutines.")
	log.Println("The API server handles all task processing automatically.")
	log.Println("This command is provided for CLI compatibility with the Python version.")

	// Just keep running
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Worker shutdown")
}

func runClientCreate(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Load workflow
	var workflow interface{}
	if _, err := os.Stat(clientWorkflow); err == nil {
		// It's a file
		var err error
		workflow, err = common.LoadWorkflowFromFile(clientWorkflow)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading workflow: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Treat as inline YAML
		workflow = clientWorkflow
	}

	// Parse inputs
	inputs := make(map[string]interface{})
	for _, input := range clientInputs {
		// Try to parse as key=value
		for i := 0; i < len(input); i++ {
			if input[i] == '=' {
				key := input[:i]
				value := input[i+1:]
				// Try to parse value as JSON
				var jsonVal interface{}
				if err := json.Unmarshal([]byte(value), &jsonVal); err == nil {
					inputs[key] = jsonVal
				} else {
					inputs[key] = value
				}
				break
			}
		}
	}

	// Parse context
	var requestContext map[string]interface{}
	if err := json.Unmarshal([]byte(clientContext), &requestContext); err != nil {
		requestContext = make(map[string]interface{})
	}

	// Build request
	request := &common.PolicyEngineRequest{
		Inputs:   inputs,
		Workflow: workflow,
		Context: map[string]interface{}{
			"config": map[string]interface{}{
				"env": map[string]interface{}{
					"GITHUB_REPOSITORY": clientRepository,
					"GITHUB_API":        "https://api.github.com/",
				},
			},
		},
	}

	// Merge additional context
	for k, v := range requestContext {
		request.Context[k] = v
	}

	// Create client and submit request
	client := common.NewClient(clientEndpoint, time.Duration(clientTimeout)*time.Second)
	status, err := client.CreateRequest(ctx, request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	// Output result
	output, err := common.FormatOutput(status, clientOutputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(output)
}

func runClientOutput(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if clientTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(clientTimeout)*time.Second)
		defer cancel()
	}

	client := common.NewClient(clientEndpoint, time.Duration(clientTimeout)*time.Second)

	if clientFollow {
		// Stream output via SSE
		err := client.StreamConsoleOutput(ctx, clientOutputTaskID, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error streaming output: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Get current console output
		output, err := client.GetConsoleOutput(ctx, clientOutputTaskID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting output: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)
	}
}

func runClientStatus(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if clientTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(clientTimeout)*time.Second)
		defer cancel()
	}

	client := common.NewClient(clientEndpoint, time.Duration(clientTimeout)*time.Second)

	var status *common.PolicyEngineStatus
	var err error

	if clientWait {
		status, err = client.WaitForCompletion(ctx, clientTaskID, time.Duration(clientPollInterval*float64(time.Second)))
	} else {
		status, err = client.GetStatus(ctx, clientTaskID)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting status: %v\n", err)
		os.Exit(1)
	}

	// Output result
	output, err := common.FormatOutput(status, clientOutputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(output)
}
