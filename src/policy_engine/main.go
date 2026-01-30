// Package main implements a Go port of the Python policy_engine.py.
// This policy engine evaluates GitHub Actions workflows and provides
// an HTTP API for submitting and monitoring workflow executions.
//
// Usage:
//
//	policy_engine api --bind 0.0.0.0:8080
//	policy_engine client --endpoint http://localhost:8080 create --workflow workflow.yml --repository org/repo
//	policy_engine client --endpoint http://localhost:8080 status --task-id <id>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

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
- Client CLI for interacting with the API`,
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

// CLI flags
var (
	// API flags
	apiBind    string
	apiWorkers int

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
)

func init() {
	// API command flags
	apiCmd.Flags().StringVar(&apiBind, "bind", "127.0.0.1:8080", "Address to bind the server to")
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

	// Build command tree
	clientCmd.AddCommand(clientCreateCmd)
	clientCmd.AddCommand(clientStatusCmd)
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

	server := NewServer(apiBind)

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
	}()

	if err := server.Start(); err != nil {
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
		workflow, err = LoadWorkflowFromFile(clientWorkflow)
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
	request := &PolicyEngineRequest{
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
	client := NewClient(clientEndpoint, time.Duration(clientTimeout)*time.Second)
	status, err := client.CreateRequest(ctx, request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	// Output result
	output, err := FormatOutput(status, clientOutputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(output)
}

func runClientStatus(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if clientTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(clientTimeout)*time.Second)
		defer cancel()
	}

	client := NewClient(clientEndpoint, time.Duration(clientTimeout)*time.Second)

	var status *PolicyEngineStatus
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
	output, err := FormatOutput(status, clientOutputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(output)
}
