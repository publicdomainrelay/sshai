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
    - run: |
        sleep 1
        echo 1
        sleep 2
        echo 2
    - env:
        MSG: "${{ steps.say-hello.outputs.greeting }}"
      run: |
        echo "Output from previous step: $MSG"
EOF

yq -P < my_workflow.yml

# 2. Start the API server on a random port; the bound address is
#    written to .port so other processes can discover it.
rm -f .port
policy_engine api --bind 127.0.0.1:0 --port-file .port 1>/dev/null 2>&1 &
PID=$?
trap "kill ${PID}" EXIT
while [ ! -s .port ]; do sleep 0.1; done
ENDPOINT="http://$(cat .port)"

# 3. Submit the workflow and capture the task ID
TASK_ID=$(policy_engine client -e "$ENDPOINT" create \
  -w my_workflow.yml -R myorg/myrepo \
  -i key=value \
  | jq -r '.detail.id')

# 4. Stream console output in real time (follows until done)
echo ' === BEING STREAM CONSOLE OUTPUT === '
policy_engine client -e "$ENDPOINT" output \
  -t "$TASK_ID" --follow
echo ' ===  END  STREAM CONSOLE OUTPUT === '

# 5. Check the final status (poll until complete)
policy_engine client -e "$ENDPOINT" status \
  -t "$TASK_ID" --wait

# Or get the status as YAML
policy_engine client -e "$ENDPOINT" status \
  -t "$TASK_ID" --wait --output-format yaml
