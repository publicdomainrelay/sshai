r"""
# Alice - aka the Open Architecture

```bash
python -m uvicorn "agi:app" --uds "/tmp/agi.sock"

AGI_SOCK=/tmp/agi.sock go run agi_sshd.go

export INPUT_SOCK="$(mktemp -d)/input.sock"; export OUTPUT_SOCK="$(mktemp -d)/text-output.sock"; export NDJSON_OUTPUT_SOCK="$(mktemp -d)/ndjson-output.sock"; export MCP_REVERSE_PROXY_SOCK="$(mktemp -d)/mcp-reverse-proxy.sock"; ssh -NnT -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no -R /tmux.sock:$(echo $TMUX | sed -e 's/,.*//g') -R "${OUTPUT_SOCK}:${OUTPUT_SOCK}" -R "${NDJSON_OUTPUT_SOCK}:${NDJSON_OUTPUT_SOCK}" -R "${MCP_REVERSE_PROXY_SOCK}:${MCP_REVERSE_PROXY_SOCK}" -R "${INPUT_SOCK}:${INPUT_SOCK}" user@localhost


gh auth refresh -h github.com -s admin:public_key
gh ssh-key add --title hat-$RANDOM ~/.ssh/*.pub
export GITHUB_USER=myusername
echo Or extract from GitHub CLI https://cli.github.com
export GITHUB_USER=$(gh auth status | grep 'Logged in to github.com account ' | awk '{print $7}')
echo On first run you have to run it twice
ssh -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no -R /tmp/${GITHUB_USER}.sock:$(echo $TMUX | sed -e 's/,.*//g') ${GITHUB_USER}@localhost
ssh -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no -R /tmp/${GITHUB_USER}.sock:$(echo $TMUX | sed -e 's/,.*//g') ${GITHUB_USER}@localhost
```

# Contributing

## Setup: Python

```bash
python -m pip install -U pip setuptools wheel snoop openai keyring libtmux
```

## Testing

```bash
nodemon -e py,toml,yaml,yml,json --exec "clear; python -m keyring del alice agents.alice.id; python -u agi.py; test 1"
```
"""

#!/usr/bin/env python
"""
Implement GitHub Actions workflow evaluation as step towards workflow based
policy engine. TODO Receipts with attestations for SLSA L4.

```mermaid
graph TD
    subgraph Tool_Catalog[Tool Catalog]
        subgraph Third_Party[3rd Party Catalog - Open Source / External OpenAPI Endpoints]
            run_kubernetes_get_pod[kubectl get pod]
            run_kubernetes_delete_deployment[kubectl delete deploy $deployment_name]
        end
        subgraph Second_Party[2nd Party Catalog - Org Local OpenAPI Endpoints]
            query_org_database[Query Org Database]
        end
        query_org_database --> tool_catalog_list_tools
        run_kubernetes_get_pod --> tool_catalog_list_tools
        run_kubernetes_delete_deployment --> tool_catalog_list_tools
        tool_catalog_list_tools[#47;tools#47;list]
    end
    subgraph llm_provider_Endpoint[LLM Endpoint - https://api.openai.com/v1/]
        llm_provider_completions_endpoint[#47;chat#47;completions]

        llm_provider_completions_endpoint --> query_org_database
        llm_provider_completions_endpoint --> run_kubernetes_get_pod
        llm_provider_completions_endpoint --> run_kubernetes_delete_deployment
    end
    subgraph Transparency_Service[Transparency Service]
        Transparency_Service_Statement_Submission_Endpoint[POST #47;entries]
        Transparency_Service_Policy_Engine[Decide admicability per Registration Policy]
        Transparency_Service_Receipt_Endpoint[GET #47;receipts#47;urn...qnGmr1o]

        Transparency_Service_Statement_Submission_Endpoint --> Transparency_Service_Policy_Engine
        Transparency_Service_Policy_Engine --> Transparency_Service_Receipt_Endpoint
    end
    subgraph LLM_Proxy[LLM Proxy]
        llm_proxy_completions_endpoint[#47;chat#47;completions]
        intercept_tool_definitions[Intercept tool definitions to LLM]
        add_tool_definitions[Add tools from tool catalog to tool definitions]
        make_modified_request_to_llm_provider[Make modified request to llm_provider]
        validate_llm_reponse_tool_calls[Validate LLM reponse tool calls]

        llm_proxy_completions_endpoint --> intercept_tool_definitions
        intercept_tool_definitions --> add_tool_definitions
        tool_catalog_list_tools --> add_tool_definitions
        add_tool_definitions --> make_modified_request_to_llm_provider
        make_modified_request_to_llm_provider --> llm_provider_completions_endpoint
        llm_provider_completions_endpoint --> validate_llm_reponse_tool_calls
        validate_llm_reponse_tool_calls --> Transparency_Service_Statement_Submission_Endpoint
        Transparency_Service_Receipt_Endpoint --> validate_llm_reponse_tool_calls
        validate_llm_reponse_tool_calls --> llm_proxy_completions_endpoint
    end
    subgraph AI_Agent[AI Agent]
        langchain_agent[langchain.ChatOpenAI] --> llm_proxy_completions_endpoint
    end

    llm_proxy_completions_endpoint -->|Return proxied response| langchain_agent
```

Testing with token auth (fine grained tokens required for status checks):

NO_CELERY=1 GITHUB_TOKEN=$(gh auth token) nodemon -e py --exec 'clear; python -m pytest -s -vv scitt_emulator/policy_engine.py; test 1'

Testing with GitHub App auth:

LIFESPAN_CONFIG_1=github_app.yaml LIFESPAN_CALLBACK_1=scitt_emulator.policy_engine:lifespan_github_app_gidgethub nodemon -e py --exec 'clear; pytest -s -vv scitt_emulator/policy_engine.py; test 1'

**github_app.yaml**

```yaml
app_id: 1234567
private_key: |
  -----BEGIN RSA PRIVATE KEY-----
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  -----END RSA PRIVATE KEY-----
```

Usage with Celery:

Terminal 1:

```bash
nodemon --signal SIGKILL -e py --exec 'clear; ./scitt_emulator/policy_engine.py --lifespan scitt_emulator.policy_engine:lifespan_github_app_gidgethub github_app.yaml api --workers 1 --bind 0.0.0.0:8080; test 1'
```

Terminal 2:

nodemon -e py --exec 'clear; ./scitt_emulator/policy_engine.py --lifespan scitt_emulator.policy_engine:lifespan_github_app_gidgethub github_app.yaml worker; test 1'

Usage without Celery:

Terminal 1:

```bash
echo For GitHub App
NO_CELERY=1 ./scitt_emulator/policy_engine.py api --lifespan scitt_emulator.policy_engine:lifespan_github_app_gidgethub github_app.yaml --workers 1
echo OR for token (need commit status: write)
GITHUB_TOKEN=$(gh auth token) NO_CELERY=1 ./scitt_emulator/policy_engine.py api --workers 1
```

**request.yml**

```yaml
context:
  config:
    env:
      GITHUB_REPOSITORY: "scitt-community/scitt-api-emulator"
      GITHUB_API: "https://api.github.com/"
      GITHUB_ACTOR: "aliceoa"
      GITHUB_ACTOR_ID: "1234567"
  secrets:
    MY_SECRET: "test-secret"
workflow: |
  on:
    push:
      branches:
      - main

  jobs:
    lint:
      runs-on: ubuntu-latest
      steps:
      - uses: actions/checkout@v4
```

In another terminal request exec via curl:

```bash
jsonschema -i <(cat request.yml | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') <(python -c 'import json, scitt_emulator.policy_engine; print(json.dumps(scitt_emulator.policy_engine.PolicyEngineRequest.model_json_schema(), indent=4, sort_keys=True))')

TASK_ID=$(curl -X POST -H "Content-Type: application/json" -d @<(cat request.yml | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') http://localhost:8080/request/create  | jq -r .detail.id)
curl http://localhost:8080/request/status/$TASK_ID | jq
```

For webhook responses:

**request-webhook.yml**

```yaml
after: 222d0403b29c4da9bfcd838d711b9746e73ea226
repository:
  full_name: "scitt-community/scitt-api-emulator"
sender:
  login: pdxjohnny
  webhook_workflow: |
    name: 'Webhook Workflow Name'
    on:
      push:
        branches:
        - main

    jobs:
      lint:
        runs-on: ubuntu-latest
        steps:
        - run: |
            echo ::error path=test.py::Hi
```

```bash
TASK_ID=$(curl -X POST http://localhost:8080/webhook/github -H "X-GitHub-Event: push" -H "X-GitHub-Delivery: 42" -H "Content-Type: application/json" -d @<(cat request-webhook.yml | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') | jq -r .detail.id)
curl http://localhost:8080/request/status/$TASK_ID | jq
```

Or you can use the builtin client (workflow.yml is 'requests.yml'.workflow):

**workflow.yml**

```yaml
on:
  push:
    branches:
    - main
  workflow_dispatch:
    file_paths:
      description: 'File paths to download'
      default: '[]'
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
    - env:
        FILE_PATHS: ${{ github.event.inputs.file_paths }}
        GITHUB_TOKEN: ${{ github.token }}
      shell: python -u {0}
      run: |
        import os
        import json
        import pathlib

        from github import Github

        file_paths = json.loads(os.environ["FILE_PATHS"])

        g = Github(os.environ["GITHUB_TOKEN"])
        upstream = g.get_repo(os.environ["GITHUB_REPOSITORY"])

        for file_path in file_paths:
            file_path = pathlib.Path("./" + file_path)
            pygithub_fileobj = upstream.get_contents(
                str(file_path),
            )
            content = pygithub_fileobj.decoded_content
            file_path.write_bytes(content)
```

Pass inputs or more context with `--input` and `--context`.

```bash
TASK_ID=$(python -u ./scitt_emulator/policy_engine.py client --endpoint http://localhost:8080 create --repository pdxjohnny/scitt-api-emulator --workflow workflow.yml --input file_paths '["/README.md"]' | tee >(jq 1>/dev/stderr) | jq -r .detail.id)
python -u ./scitt_emulator/policy_engine.py client --endpoint http://localhost:8080 status --task-id "${TASK_ID}" | tee >(jq -r .detail.annotations.error[] 1>&2) | jq
```
"""
import os
import io
import re
import sys
import json
import time
import enum
import uuid
import copy
import shlex
import types
import atexit
import asyncio
import pathlib
import zipfile
import tarfile
import inspect
import logging
import argparse
import tempfile
import textwrap
import datetime
import threading
import importlib
import traceback
import itertools
import subprocess
import contextlib
import contextvars
import urllib.request
import multiprocessing
import concurrent.futures
from typing import (
    Union,
    Awaitable,
    Callable,
    Optional,
    Tuple,
    List,
    Dict,
    Any,
    Annotated,
    # Self,
    Iterator,
)


import yaml
import snoop
import pytest
import aiohttp
import libtmux
import gidgethub.apps
import gidgethub.aiohttp
import gunicorn.app.base
from celery import Celery, current_app as celery_current_app
from celery.result import AsyncResult
from fastapi import FastAPI, Request
from fastapi.responses import Response
from pydantic import (
    BaseModel,
    PlainSerializer,
    Field,
    model_validator,
    field_validator,
)
from fastapi.testclient import TestClient


logger = logging.getLogger(__name__)


def entrypoint_style_load(
    *args: str, relative: Optional[Union[str, pathlib.Path]] = None
) -> Iterator[Any]:
    """
    Load objects given the entrypoint formatted path to the object. Roughly how
    the python stdlib docs say entrypoint loading works.
    """
    # Push current directory into front of path so we can run things
    # relative to where we are in the shell
    if relative is not None:
        if relative == True:
            relative = os.getcwd()
        # str() in case of Path object
        sys.path.insert(0, str(relative))
    try:
        for entry in args:
            modname, qualname_separator, qualname = entry.partition(":")
            obj = importlib.import_module(modname)
            for attr in qualname.split("."):
                if hasattr(obj, "__getitem__"):
                    obj = obj[attr]
                else:
                    obj = getattr(obj, attr)
            yield obj
    finally:
        if relative is not None:
            sys.path.pop(0)


class PolicyEngineCompleteExitStatuses(enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class PolicyEngineComplete(BaseModel, extra="forbid"):
    id: str
    exit_status: PolicyEngineCompleteExitStatuses
    outputs: Dict[str, Any]
    annotations: Dict[str, Any]


class PolicyEngineStatuses(enum.Enum):
    SUBMITTED = "submitted"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    UNKNOWN = "unknown"
    INPUT_VALIDATION_ERROR = "input_validation_error"


class PolicyEngineStatusUpdateJobStep(BaseModel, extra="forbid"):
    status: PolicyEngineStatuses
    metadata: Dict[str, str]
    outputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})


class PolicyEngineStatusUpdateJob(BaseModel, extra="forbid"):
    steps: Dict[str, PolicyEngineStatusUpdateJobStep]


class PolicyEngineInProgress(BaseModel, extra="forbid"):
    id: str
    status_updates: Dict[str, PolicyEngineStatusUpdateJob]


class PolicyEngineSubmitted(BaseModel, extra="forbid"):
    id: str


class PolicyEngineUnknown(BaseModel, extra="forbid"):
    id: str


class PolicyEngineInputValidationError(BaseModel):
    msg: str
    loc: List[str]
    type: str
    url: Optional[str] = None
    input: Optional[str] = None


class PolicyEngineStatus(BaseModel, extra="forbid"):
    status: PolicyEngineStatuses
    detail: Union[
        PolicyEngineSubmitted,
        PolicyEngineInProgress,
        PolicyEngineComplete,
        PolicyEngineUnknown,
        List[PolicyEngineInputValidationError],
    ]

    @model_validator(mode="before")
    @classmethod
    def model_validate_detail(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            if "status" not in data:
                data["status"] = PolicyEngineStatuses.INPUT_VALIDATION_ERROR.value
            if isinstance(data["status"], PolicyEngineStatuses):
                data["status"] = data["status"].value

            detail_class = DETAIL_CLASS_MAPPING[data["status"]]
            data["detail"] = detail_class.model_validate(data["detail"])
        return data


DETAIL_CLASS_MAPPING = {
    PolicyEngineStatuses.SUBMITTED.value: PolicyEngineSubmitted,
    PolicyEngineStatuses.IN_PROGRESS.value: PolicyEngineInProgress,
    PolicyEngineStatuses.COMPLETE.value: PolicyEngineComplete,
    PolicyEngineStatuses.UNKNOWN.value: PolicyEngineUnknown,
    PolicyEngineStatuses.INPUT_VALIDATION_ERROR.value: types.SimpleNamespace(
        model_validate=lambda detail: list(map(PolicyEngineInputValidationError.model_validate, detail)),
    ),
}

# or `from typing import Annotated` for Python 3.9+
from typing_extensions import Annotated

from typing import Optional
from pydantic import BaseModel
from pydantic.functional_serializers import model_serializer


class OmitIfNone:
    pass


class PolicyEngineWorkflowJobStep(BaseModel, extra="forbid"):
    id: Annotated[Union[str, None], OmitIfNone()]
    # TODO Alias doesn't seem to be working here
    # if_condition: Optional[str] = Field(default=None, alias="if")
    # TODO Implement step if conditionals, YAML load output of eval_js
    if_condition: Annotated[Union[bool, None], OmitIfNone()]
    name: Annotated[Union[str, None], OmitIfNone()]
    uses: Annotated[Union[str, None], OmitIfNone()]
    shell: Annotated[Union[str, None], OmitIfNone()]
    # TODO Alias doesn't seem to be working here
    # with_inputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {}, alias="with")
    with_inputs: Annotated[Union[Dict[str, str], None], OmitIfNone()]
    env: Annotated[Union[Dict[str, str], None], OmitIfNone()]
    run: Annotated[Union[str, None], OmitIfNone()]

    @model_serializer
    def _serialize(self):
        omit_if_none_fields = {
            k
            for k, v in self.__class__.model_fields.items()
            if any(isinstance(m, OmitIfNone) for m in v.metadata)
        }

        obj = {k: v for k, v in self if k not in omit_if_none_fields or v is not None}

        if self.if_condition is True:
            del obj["if_condition"]

        return obj

    @model_validator(mode="before")
    @classmethod
    def fix_hyphen_keys(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            for find, replace in [
                ("if", "if_condition"),
                ("with", "with_inputs"),
            ]:
                if find in data:
                    data[replace] = data[find]
                    del data[find]
        return data


class PolicyEngineWorkflowJobRunsOn(BaseModel, extra="forbid"):
    group: str
    labels: Union[str, List[str]]


class PolicyEngineWorkflowJob(BaseModel, extra="forbid"):
    runs_on: Union[str, List[str], PolicyEngineWorkflowJobRunsOn]
    steps: List[PolicyEngineWorkflowJobStep]

    @model_validator(mode="before")
    @classmethod
    def fix_hyphen_keys(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            for find, replace in [("runs-on", "runs_on")]:
                if find in data:
                    data[replace] = data[find]
                    del data[find]
        return data


class PolicyEngineWorkflow(BaseModel, extra="forbid"):
    name: Union[str, None]
    # on: Union[List[str], Dict[str, Any]]
    on: Union[List[str]] = Field(default_factory=lambda: ["push"])
    jobs: Union[Dict[str, PolicyEngineWorkflowJob], None]

    @model_validator(mode="before")
    @classmethod
    def fix_yaml_on_parsed_as_bool(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            for check in [1, True]:
                if check in data:
                    data["on"] = data[check]
                    del data[check]
        return data


pathlib.Path(__file__).parent.joinpath("workflow.schema.json").write_text(
    json.dumps(PolicyEngineWorkflow.model_json_schema(), indent=4, sort_keys=True),
)


class GitHubWebhookEventSender(BaseModel):
    login: str
    webhook_workflow: Optional[Union[str, PolicyEngineWorkflow]] = textwrap.dedent(
        """
        name: 'My Cool Status Check'
        on:
          push:
            branches:
            - main

        jobs:
          test:
            name: "My Job"
            runs-on: self-hosted
            steps:
            - run: |
                # https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
                echo "::error file=app.js,line=1,col=5,endColumn=7::Missing semicolon"
        """
    )


class GitHubWebhookEventRepository(BaseModel):
    full_name: str


class GitHubWebhookEvent(BaseModel):
    after: str
    sender: Optional[GitHubWebhookEventSender]
    repository: Optional[GitHubWebhookEventRepository]


class PolicyEngineRequest(BaseModel, extra="forbid"):
    # Inputs should come from json-ld @context instance
    inputs: Dict[str, Any]
    workflow: PolicyEngineWorkflow
    context: Dict[str, Any]
    stack: Dict[str, Any]

    @field_validator("workflow")
    @classmethod
    def parse_workflow_github_actions(cls, workflow, _info):
        if isinstance(workflow, str):
            workflow = yaml.safe_load(workflow)
        if isinstance(workflow, dict):
            workflow = PolicyEngineWorkflow.model_validate(workflow)
        return workflow

    @field_validator("context")
    @classmethod
    def parse_context_set_secrets_if_not_set(cls, context, _info):
        context.setdefault("secrets", {})
        return context


celery_app = Celery(
    "tasks",
    backend=os.environ.get("CELERY_BACKEND", "redis://localhost"),
    broker=os.environ.get("CELERY_BROKER", "redis://localhost"),
    broker_connection_retry_on_startup=True,
)


def number_of_workers():
    return (multiprocessing.cpu_count() * 2) + 1


def _no_celery_task(func, bind=False, no_celery_async=None):
    async def asyncio_delay(*args):
        nonlocal bind
        nonlocal no_celery_async
        if no_celery_async is None:
            raise Exception(
                "Must specify async def version of task via @celery_task decorator keyword argument no_celery_async"
            )
        task_id = str(uuid.uuid4())
        if bind:
            mock_celery_task_bind_self = types.SimpleNamespace(
                request=types.SimpleNamespace(
                    id=task_id,
                )
            )
            args = [mock_celery_task_bind_self] + list(args)
        task = asyncio.create_task(no_celery_async(*args))

        async def async_no_celery_try_set_state(task_id):
            request = fastapi_current_request.get()
            async with request.state.no_celery_async_results_lock:
                no_celery_try_set_state(
                    request.state.no_celery_async_results[task_id],
                )

        task.add_done_callback(
            lambda _task: asyncio.create_task(
                async_no_celery_try_set_state(task_id)
            ),
        )
        request = fastapi_current_request.get()
        async with request.state.no_celery_async_results_lock:
            results = request.state.no_celery_async_results
            results[task_id] = {
                "state": "PENDING",
                "result": None,
                "future": None,
                "task": task,
            }
            no_celery_try_set_state(results[task_id])
        return types.SimpleNamespace(id=task_id)

    func.asyncio_delay = asyncio_delay
    return func


def no_celery_task(*args, **kwargs):
    if kwargs:

        def wrap(func):
            return _no_celery_task(func, **kwargs)

        return wrap
    return _no_celery_task(*args)


def no_celery_try_set_state(state):
    task = state["task"]
    future = state["future"]
    if task is not None:
        if not task.done():
            state["state"] = "PENDING"
        else:
            exception = task.exception()
            if exception is not None:
                state["result"] = exception
                state["state"] = "FAILURE"
            else:
                state["state"] = "SUCCESS"
                state["result"] = task.result()
    elif future is not None:
        exception = future.exception(timeout=0)
        if exception is not None:
            state["result"] = exception
            state["state"] = "FAILURE"
        elif not future.done():
            state["state"] = "PENDING"
        else:
            state["state"] = "SUCCESS"
            state["result"] = future.result()


class NoCeleryAsyncResult:
    def __init__(self, task_id, *, app=None):
        self.task_id = task_id

    @property
    def state(self):
        request = fastapi_current_request.get()
        results = request.state.no_celery_async_results
        if self.task_id not in results:
            return "UNKNOWN"
        state = results[self.task_id]
        no_celery_try_set_state(state)
        return state["state"]

    def get(self):
        result = fastapi_current_request.get().state.no_celery_async_results[
            self.task_id
        ]["result"]
        if isinstance(result, Exception):
            raise result
        return result


def _make_celery_task_asyncio_delay(app, func, **kwargs):
    async def asyncio_delay(*args):
        nonlocal func
        return func.delay(*args)

    if kwargs:
        func = app.task(**kwargs)(func)
    else:
        func = app.task(func)
    func.asyncio_delay = asyncio_delay
    return func


def make_celery_task_asyncio_delay(app):
    def celery_task_asyncio_delay(*args, **kwargs):
        if kwargs:

            def wrap(func):
                return _make_celery_task_asyncio_delay(app, func, **kwargs)

            return wrap
        return _make_celery_task_asyncio_delay(app, *args, **kwargs)

    return celery_task_asyncio_delay


if int(os.environ.get("NO_CELERY", "0")):
    AsyncResult = NoCeleryAsyncResult
    celery_task = no_celery_task
else:
    celery_task = make_celery_task_asyncio_delay(celery_app)


def download_step_uses_from_url(
    context,
    request,
    step,
    step_uses_org_repo,
    step_uses_version,
    step_download_url,
):
    stack = request.context["stack"][-1]

    exit_stack = stack["exit_stack"]
    if "cachedir" in stack:
        downloads_path = stack["cachedir"]
    else:
        downloads_path = exit_stack.enter_context(
            tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
        )
    downloads_path = pathlib.Path(downloads_path)

    # TODO(security) MoM of hashes? stat as well? How to validate on disk?
    compressed_path = pathlib.Path(
        downloads_path, step_uses_org_repo, "compressed.zip"
    )
    extracted_tmp_path = pathlib.Path(
        downloads_path, step_uses_org_repo, "extracted_tmp"
    )
    extracted_path = pathlib.Path(
        downloads_path, step_uses_org_repo, "extracted"
    )
    compressed_path.parent.mkdir(parents=True, exist_ok=True)
    headers = {}
    github_token = stack["secrets"].get("GITHUB_TOKEN", "")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    request = urllib.request.Request(
        step_download_url,
        headers=headers,
    )
    if not compressed_path.is_file():
        request = exit_stack.enter_context(urllib.request.urlopen(request))
        compressed_path.write_bytes(request.read())
    if not extracted_path.is_dir():
        zipfileobj = exit_stack.enter_context(zipfile.ZipFile(compressed_path))
        zipfileobj.extractall(extracted_tmp_path)
        # Rename uplevel from repo-vYXZ name as archive into extracted/
        list(extracted_tmp_path.glob("*"))[0].rename(extracted_path)

    stack.setdefault("steps", {})
    stack["steps"].setdefault("extracted_path", {})
    stack["steps"]["extracted_path"][step.uses] = extracted_path
    # https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
    stack["env"]["GITHUB_ACTION_PATH"] = str(extracted_path.resolve())

    return extracted_path.resolve()


class DownloadStepUsesError(Exception):
    pass


def download_step_uses(context, request, step):
    exception = None
    step_uses_org_repo, step_uses_version = step.uses.split("@")
    # TODO refs/heads/
    for step_download_url in [
        f"https://github.com/{step_uses_org_repo}/archive/refs/tags/{step_uses_version}.zip",
        f"https://github.com/{step_uses_org_repo}/archive/{step_uses_version}.zip",
        f"https://github.com/{step_uses_org_repo}/archive/refs/heads/{step_uses_version}.zip",
    ]:
        try:
            return download_step_uses_from_url(
                context,
                request,
                step,
                step_uses_org_repo,
                step_uses_version,
                step_download_url,
            )
        except Exception as error:
            exception = error
    raise DownloadStepUsesError(step_download_url) from exception


def transform_property_accessors(js_code):
    transformed_code = ""
    index = 0
    while index < len(js_code):
        if js_code[index] in ('"', "'"):
            # If within a string, find the closing quote
            quote = js_code[index]
            end_quote_index = js_code.find(quote, index + 1)
            if end_quote_index == -1:
                # If no closing quote is found, break the loop
                break
            else:
                # Append the string as is
                transformed_code += js_code[index : end_quote_index + 1]
                index = end_quote_index + 1
        elif js_code[index].isspace():
            # If whitespace, just append it
            transformed_code += js_code[index]
            index += 1
        elif js_code[index] == ".":
            # Replace dot with bracket notation if not within a string
            transformed_code += "['"
            prop_end_index = index + 1
            while (
                prop_end_index < len(js_code)
                and js_code[prop_end_index].isalnum()
                or js_code[prop_end_index] == "_"
                or js_code[prop_end_index] == "-"
            ):
                prop_end_index += 1
            transformed_code += js_code[index + 1 : prop_end_index]
            transformed_code += "']"
            index = prop_end_index
        else:
            # Just append characters as is
            transformed_code += js_code[index]
            index += 1
    return transformed_code


def _evaluate_using_javascript(context, request, code_block):
    stack = request.context["stack"][-1]

    exit_stack = stack["exit_stack"]
    tempdir = exit_stack.enter_context(
        tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
    )

    github_context = {
        **{
            input_key.lower().replace(
                "github_", "", 1
            ): evaluate_using_javascript(
                context,
                request,
                input_value,
            )
            for input_key, input_value in stack["env"].items()
            if input_key.startswith("GITHUB_")
        },
        **{
            "token": stack["secrets"].get("GITHUB_TOKEN", ""),
            "event": {
                "inputs": request.context["inputs"],
            },
        },
    }
    runner_context = {
        "debug": stack.get("debug", 1),
    }
    steps_context = stack["outputs"]
    # TODO secrets_context

    # Find property accessors in dot notation and replace dot notation
    # with bracket notation. Avoids replacements within strings.
    code_block = transform_property_accessors(code_block)

    javascript_path = pathlib.Path(tempdir, "check_output.js")
    # TODO vars and env contexts
    javascript_path.write_text(
        textwrap.dedent(
            r"""
            function always() { return "__GITHUB_ACTIONS_ALWAYS__"; }
            const github = """
            + json.dumps(github_context, sort_keys=True)
            + """;
            const runner = """
            + json.dumps(runner_context, sort_keys=True)
            + """;
            const steps = """
            + json.dumps(steps_context, sort_keys=True)
            + """;
            const result = ("""
            + code_block
            + """);
            console.log(result)
            """
        ).strip()
    )
    output = subprocess.check_output(
        [context.state.deno, "repl", "-q", f"--eval-file={javascript_path.resolve()}"],
        stdin=request.context["devnull"],
        cwd=stack["workspace"],
    ).decode()
    if output.startswith(
        f'Error in --eval-file file "{javascript_path.resolve()}"'
    ):
        raise Exception(
            output
            + ("-" * 100)
            + "\n"
            + javascript_path.read_text()
            + ("-" * 100)
            + "\n"
        )
    return output.strip()


def evaluate_using_javascript(context, request, code_block):
    if code_block is None:
        return ""

    # TODO Not startswith, search for each and run deno
    if not isinstance(code_block, str) or "${{" not in code_block:
        return str(code_block)

    result = ""
    start_idx = 0
    end_idx = 0
    while "${{" in code_block[start_idx:]:
        # Find the starting index of "${{"
        start_idx = code_block.index("${{", start_idx)
        result += code_block[end_idx:start_idx]
        # Find the ending index of "}}"
        end_idx = code_block.index("}}", start_idx) + 2
        # Extract the data between "${{" and "}}"
        data = code_block[start_idx + 3 : end_idx - 2]
        # Call evaluate_using_javascript() with the extracted data
        evaluated_data = _evaluate_using_javascript(context, request, data)
        # Append the evaluated data to the result
        result += code_block[start_idx + 3 : end_idx - 2].replace(
            data, str(evaluated_data)
        )
        # Move the start index to the next position after the match
        start_idx = end_idx

    result += code_block[start_idx:]

    return result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "template,should_be",
    [
        [
            "${{ github.actor }} <${{ github.actor_id }}+${{ github.actor }}@users.noreply.github.com>",
            "aliceoa <1234567+aliceoa@users.noreply.github.com>",
        ],
        [
            "${{ github.actor_id + \" \" + 'https://github.com' + '/' + github.actor }}",
            "1234567 https://github.com/aliceoa",
        ],
    ],
)
async def test_evaluate_using_javascript(template, should_be):
    context = make_default_policy_engine_context()
    request = PolicyEngineRequest(
        context={
            "config": {
                "env": {
                    "GITHUB_ACTOR": "aliceoa",
                    "GITHUB_ACTOR_ID": "1234567",
                },
            },
        }
    )
    async with async_celery_setup_workflow(context, request) as (context, request):
        evaluated = evaluate_using_javascript(
            context,
            request,
            template,
        )
        assert evaluated == should_be


def step_parse_outputs_github_actions(context, step, step_outputs_string):
    outputs = {}
    current_output_key = None
    current_output_delimiter = None
    current_output_value = ""
    for line in step_outputs_string.split("\n"):
        if "=" in line and not current_output_key:
            current_output_key, current_output_value = line.split(
                "=", maxsplit=1
            )
            outputs[current_output_key] = current_output_value
        elif "<<" in line and not current_output_key:
            current_output_key, current_output_delimiter = line.split(
                "<<", maxsplit=1
            )
        elif current_output_delimiter:
            if line.startswith(current_output_delimiter):
                outputs[current_output_key] = current_output_value[:-1]
                current_output_key = None
                current_output_delimiter = None
                current_output_value = ""
            else:
                current_output_value += line + "\n"
    return outputs


def step_build_default_inputs(context, request, action_yaml_obj, step):
    return {
        f"INPUT_{input_key.upper()}": evaluate_using_javascript(
            context, request, input_value["default"]
        )
        for input_key, input_value in action_yaml_obj.get("inputs", {}).items()
        if "default" in input_value
    }


def step_build_env(context, request, step):
    return {
        input_key: evaluate_using_javascript(context, request, input_value)
        for input_key, input_value in step.env.items()
    }


def step_build_inputs(context, request, step):
    return {
        f"INPUT_{input_key.upper()}": evaluate_using_javascript(
            context, request, input_value
        )
        for input_key, input_value in step.with_inputs.items()
    }


def step_io_output_github_actions(context, request):
    stack = request.context["stack"][-1]
    step_tempdir = stack["exit_stack"].enter_context(
        tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
    )
    step_outputs_path = pathlib.Path(step_tempdir, "output.txt")
    step_env_path = pathlib.Path(step_tempdir, "env.txt")
    step_outputs_path.write_text("")
    step_env_path.write_text("")
    return {
        "GITHUB_OUTPUT": str(step_outputs_path.resolve()),
        "GITHUB_ENV": str(step_env_path.resolve()),
        "GITHUB_WORKSPACE": stack["workspace"],
    }


def step_io_update_stack_output_and_env_github_actions(context, request, step):
    stack = request.context["stack"][-1]
    outputs = step_parse_outputs_github_actions(
        context,
        step,
        pathlib.Path(stack["env"]["GITHUB_OUTPUT"]).read_text(),
    )
    context_env_updates = step_parse_outputs_github_actions(
        context,
        step,
        pathlib.Path(stack["env"]["GITHUB_ENV"]).read_text(),
    )

    if step.id:
        stack["outputs"].setdefault(step.id, {})
        stack["outputs"][step.id]["outputs"] = outputs
    stack["env"].update(context_env_updates)


def step_parse_annotations_github_actions_line(context, step, line):
    line = line.strip().strip("::")
    annotation_level, message = line.split("::", maxsplit=1)
    details = {
        "title": message,
        "message": message,
        "raw_details": line,
    }
    if " " in annotation_level:
        annotation_level, details_string = annotation_level.split(" ", maxsplit=1)
        details.update(urllib.parse.parse_qsl(details_string.replace(",", "&")))
        details["annotation_level"] = annotation_level
        details_items = list(details.items())
        for key, value in details_items:
            del details[key]
            key = re.sub(r'(?<!^)(?=[A-Z])', '_', key).lower()
            details[key] = value
    return GitHubCheckSuiteAnnotation.model_validate(details)


def step_parse_annotations_github_actions(context, step, step_annotations_string):
    # TODO Groups
    # https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#grouping-log-lines
    return [
        step_parse_annotations_github_actions_line(
            context,
            step,
            line,
        )
        for line in step_annotations_string.split("\n")
        if line.startswith("::")
    ]


def step_io_update_stack_annotations_github_actions(context, request, step):
    stack = request.context["stack"][-1]
    for annotation in itertools.chain(
        step_parse_annotations_github_actions(
            context,
            step,
            pathlib.Path(stack["console_output"]).read_text(),
        )
    ):
        stack["annotations"].setdefault(annotation.annotation_level, [])
        stack["annotations"][annotation.annotation_level].append(annotation)


async def execute_step_uses(context, request, step):
    stack = request.context["stack"][-1]

    extracted_path = stack["steps"]["extracted_path"][step.uses]
    action_yaml_path = list(extracted_path.glob("action.*"))[0]
    action_yaml_obj = yaml.safe_load(action_yaml_path.read_text())

    stack["env"].update(
        {
            **step_io_output_github_actions(context, request),
            **step_build_default_inputs(
                context, request, action_yaml_obj, step
            ),
        }
    )

    if action_yaml_obj["runs"]["using"].startswith("node"):
        env = copy.deepcopy(os.environ)
        env.update(stack["env"])
        cmd = [
            context.state.nodejs,
            extracted_path.joinpath(action_yaml_obj["runs"]["main"]),
        ]
        tee_proc = subprocess.Popen(
            ["tee", stack["console_output"]],
            stdin=subprocess.PIPE,
        )
        try:
            completed_proc = subprocess.run(
                cmd,
                cwd=stack["workspace"],
                stdin=request.context["devnull"],
                stdout=tee_proc.stdin,
                stderr=tee_proc.stdin,
                env=env,
            )
            step_io_update_stack_output_and_env_github_actions(
                context,
                request,
                step,
            )
            step_io_update_stack_annotations_github_actions(
                context,
                request,
                step,
            )
            try:
                completed_proc.check_returncode()
            except Exception as error:
                tee_proc.stdin.close()
                tee_proc.wait()
                raise Exception(f'Command ({shlex.join(map(str, cmd))}) exited with code {error.returncode}:\n{pathlib.Path(stack["console_output"]).read_text(errors="ignore")}') from error
        finally:
            tee_proc.stdin.close()
            tee_proc.wait()
    elif action_yaml_obj["runs"]["using"] == "composite":
        composite_steps = action_yaml_obj["runs"]["steps"]
        # TODO HACK Remove by fixing PyDantic Field.alias = True deserialization
        for composite_step in composite_steps:
            if "with" in composite_step:
                composite_step["with_inputs"] = composite_step["with"]
                del composite_step["with"]
        stack = celery_run_workflow_context_stack_make_new(context, request, step.uses)
        # TODO Reusable workflows, populate secrets
        # stack["secrets"] = request.context["secrets"]
        await no_celery_async_celery_run_workflow(
            context,
            PolicyEngineRequest(
                inputs=step.with_inputs,
                workflow={
                    "jobs": {
                        "composite": {
                            "steps": composite_steps,
                        },
                    },
                },
                context=request.context,
                stack=stack,
            ),
        )
    else:
        raise NotImplementedError("Only node and composite actions implemented")


async def execute_step_uses_org_repo_at_version(context, request, step):
    download_step_uses(context, request, step)
    await execute_step_uses(context, request, step)


async def execute_step_run(context, request, step):
    stack = request.context["stack"][-1]
    stack["env"].update(step_io_output_github_actions(context, request))

    temp_script_path = pathlib.Path(
        stack["exit_stack"].enter_context(
            tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
        ),
        "run.sh",
    )

    step_run = evaluate_using_javascript(context, request, step.run)
    temp_script_path.write_text(step_run)

    shell = stack["shell"]
    if "{0}" not in shell:
        shell += " {0}"
    shell = shell.replace("{0}", str(temp_script_path.resolve()))
    cmd = list(
        [
            sys.executable
            if cmd_arg == "python"
            else cmd_arg
            for cmd_arg in shlex.split(shell)
        ]
    )

    env = copy.deepcopy(os.environ)
    env.update(stack["env"])
    tee_proc = subprocess.Popen(
        ["tee", stack["console_output"]],
        stdin=subprocess.PIPE,
    )
    try:
        completed_proc = subprocess.run(
            cmd,
            cwd=stack["workspace"],
            stdin=request.context["devnull"],
            stdout=tee_proc.stdin,
            stderr=tee_proc.stdin,
            env=env,
        )

        step_io_update_stack_output_and_env_github_actions(
            context,
            request,
            step,
        )
        step_io_update_stack_annotations_github_actions(
            context,
            request,
            step,
        )

        try:
            completed_proc.check_returncode()
        except Exception as error:
            tee_proc.stdin.close()
            tee_proc.wait()
            raise Exception(f'Command ({shlex.join(map(str, cmd))}) exited with code {error.returncode}:\n{pathlib.Path(stack["console_output"]).read_text(errors="ignore")}') from error
    finally:
        tee_proc.stdin.close()
        tee_proc.wait()


async def execute_step(context, request, step):
    stack = request.context["stack"][-1]

    if_condition = step.if_condition
    if if_condition is not None:
        if not isinstance(if_condition, (bool, int)):
            if not "${{" in if_condition:
                if_condition = "${{ " + if_condition + " }}"
            if_condition = evaluate_using_javascript(context, request, if_condition)
            if_condition = yaml.safe_load(f"if_condition: {if_condition}")["if_condition"]
        if not if_condition:
            return
        if stack["error"] and if_condition != "__GITHUB_ACTIONS_ALWAYS__":
            return

    if step.uses:
        if "@" in step.uses:
            await execute_step_uses_org_repo_at_version(context, request, step)
        else:
            raise NotImplementedError("Only uses: org/repo@vXYZ is implemented")
    elif step.run:
        await execute_step_run(context, request, step)
    else:
        raise NotImplementedError(
            "Only uses: org/repo@vXYZ and run implemented"
        )


def celery_run_workflow_context_stack_make_new(context, request, stack_path_part):
    old_stack = request.context
    if request.context["stack"]:
        old_stack = request.context["stack"][-1]
    stack = {
        "stack_path": old_stack.get("stack_path", []) + [stack_path_part],
        "error": old_stack.get("error", None),
        # TODO shell from platform.system() selection done in lifecycle
        "shell": old_stack.get("shell", "bash -xe"),
        "outputs": {},
        "annotations": {},
        "secrets": {},
        "cachedir": old_stack["cachedir"],
        "tempdir": old_stack["tempdir"],
        "workspace": old_stack["workspace"],
        "env": copy.deepcopy(old_stack["env"]),
    }
    return stack


def celery_run_workflow_context_stack_push(context, request, stack):
    old_stack = request.context
    if request.context["stack"]:
        old_stack = request.context["stack"][-1]
    stack["exit_stack"] = contextlib.ExitStack().__enter__()
    console_output_path = pathlib.Path(
        stack["exit_stack"].enter_context(
            tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
        ),
        "console_output.txt",
    )
    console_output_path.write_bytes(b"")
    stack["console_output"] = str(console_output_path)
    request.context["stack"].append(stack)


def celery_run_workflow_context_stack_pop(context, request):
    # TODO Deal with ordering of lines by time, logging module?
    popped_stack = request.context["stack"].pop()
    for annotation in itertools.chain(*popped_stack["annotations"].values()):
        request.context["annotations"].setdefault(annotation.annotation_level, [])
        request.context["annotations"][annotation.annotation_level].append(annotation)
    request.context["console_output"].append(
        [
            popped_stack["stack_path"],
            pathlib.Path(popped_stack["console_output"]).read_bytes(),
        ],
    )
    popped_stack["exit_stack"].__exit__(None, None, None)


async def celery_run_workflow_context_init(
    context,
    request,
    *,
    force_init: bool = False,
):
    request.context.setdefault("secrets", {})
    config = request.context.get("config", {})
    config_cwd = config.get("cwd", os.getcwd())
    config_env = config.get("env", {})
    if force_init or "env" not in request.context:
        request.context["env"] = copy.deepcopy(config_env)
    if force_init or "devnull" not in request.context:
        # Open /dev/null for empty stdin to subprocesses
        request.context["devnull"] = open(os.devnull)
    if force_init or "inputs" not in request.context:
        request.context["inputs"] = copy.deepcopy(request.inputs)
    if force_init or "cachedir" not in request.context:
        # Cache dir for caching actions
        cache_path = pathlib.Path(config_cwd, ".cache")
        cache_path.mkdir(exist_ok=True)
        request.context["cachedir"] = str(cache_path)
    if force_init or "tempdir" not in request.context:
        # Temp dir
        tempdir_path = pathlib.Path(config_cwd, ".tempdir")
        tempdir_path.mkdir(exist_ok=True)
        request.context["tempdir"] = str(tempdir_path)
        if "RUNNER_TEMP" not in request.context["env"]:
            request.context["env"]["RUNNER_TEMP"] = request.context["tempdir"]
        if "RUNNER_TOOL_CACHE" not in request.context["env"]:
            request.context["env"]["RUNNER_TOOL_CACHE"] = request.context[
                "tempdir"
            ]
    if force_init or "workspace" not in request.context:
        # Workspace dir
        request.context["workspace"] = request.context[
            "exit_stack"
        ].enter_context(
            tempfile.TemporaryDirectory(dir=config.get("tempdir", None)),
        )
    if force_init or "stack" not in request.context:
        request.context["stack"] = []
    if force_init or "console_output" not in request.context:
        request.context["console_output"] = []
    if force_init or "annotations" not in request.context:
        request.context["annotations"] = {}
    if force_init or "_init" not in request.context:
        request.context["_init"] = True
        for extra_init in context.extra_inits:
            if inspect.iscoroutinefunction(extra_init):
                await extra_init(context, request)
            else:
                extra_init(context, request)


@contextlib.contextmanager
def prepend_to_path(*args: str, env=None):
    """
    Prepend all given directories to the ``PATH`` environment variable.
    """
    if env is None:
        raise Exception("env kwarg must be given")
    old_path = env.get("PATH", "")
    # TODO Will this work on Windows?
    env["PATH"] = ":".join(list(map(str, args)) + old_path.split(":"))
    try:
        yield env
    finally:
        env["PATH"] = old_path


def which(binary):
    for dirname in os.environ.get("PATH", "").split(":"):
        check_path = pathlib.Path(dirname, binary)
        if check_path.exists():
            return check_path.resolve()


@contextlib.asynccontextmanager
async def lifespan_deno(
    config_string,
    _app,
    _context,
    state,
):
    deno_path = which("deno")
    if deno_path is not None:
        yield {"deno": deno_path}
        return
    with tempfile.TemporaryDirectory(prefix="deno-") as tempdir:
        downloads_path = pathlib.Path(tempdir)
        compressed_path = pathlib.Path(downloads_path, "compressed.zip")

        github_token = None
        if "github_app" in state:
            github_token = state["github_app"].danger_wide_permissions_token
        elif "github_token" in state:
            github_token = state["github_token"]

        headers = {}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        def do_download():
            request = urllib.request.Request(config_string, headers=headers)
            with urllib.request.urlopen(request) as response:
                compressed_path.write_bytes(response.read())
            with zipfile.ZipFile(compressed_path) as zipfileobj:
                zipfileobj.extractall(downloads_path)
            compressed_path.unlink()

        logger.warning("Downloading deno...")
        await asyncio.get_event_loop().run_in_executor(None, do_download)

        deno_path = downloads_path.joinpath("deno").resolve()
        deno_path.chmod(0o755)
        logger.warning("Finished downloading deno: %s", deno_path)

        yield {"deno": deno_path}


@contextlib.asynccontextmanager
async def lifespan_nodejs(
    config_string,
    app,
    _context,
    _state,
):
    if isinstance(app, FastAPI) and not int(os.environ.get("NO_CELERY", "0")):
        yield
        return
    nodejs_path = which("node")
    if nodejs_path is not None:
        yield {"nodejs": nodejs_path}
        return
    with tempfile.TemporaryDirectory(prefix="nodejs-") as tempdir:
        downloads_path = pathlib.Path(tempdir)

        def do_download():
            with urllib.request.urlopen(config_string) as fileobj:
                with tarfile.open(fileobj=fileobj, mode='r|*') as tarfileobj:
                    tarfileobj.extractall(downloads_path)

        logger.warning("Downloading nodejs...")
        await asyncio.get_event_loop().run_in_executor(None, do_download)

        nodejs_path = list(
            [
                path
                for path in downloads_path.rglob("node")
                if path.parent.stem == "bin"
            ]
        )[0].resolve()
        nodejs_path.chmod(0o755)
        logger.warning("Finished downloading nodejs: %s", nodejs_path)

        yield {"nodejs": nodejs_path}


@contextlib.asynccontextmanager
async def lifespan_gidgethub(
    _config_string,
    _app,
    _context,
    _state,
):
    async with aiohttp.ClientSession(trust_env=True) as session:
        yield {
            "gidgethub": gidgethub.aiohttp.GitHubAPI(
                session,
                # TODO Change actor
                "pdxjohnny",
            ),
        }


class LifespanGitHubAppConfig(BaseModel):
    app_id: int
    private_key: str
    danger_wide_permissions_token: str


@contextlib.asynccontextmanager
async def lifespan_github_app(
    config_string,
    app,
    context,
    _state,
):
    config = yaml.safe_load(
        pathlib.Path(config_string).expanduser().read_text()
    )

    # NOTE SECURITY This token has permissions to all installations!!! Swap
    # it for a more finely scoped token next:
    config["danger_wide_permissions_token"] = gidgethub.apps.get_jwt(
        app_id=config["app_id"],
        private_key=config["private_key"],
    )

    yield {"github_app": LifespanGitHubAppConfig.model_validate(config)}


@contextlib.asynccontextmanager
async def lifespan_github_token(
    config_string,
    app,
    context,
    _state,
):
    if (
        config_string == "try_env"
        and not os.environ.get("GITHUB_TOKEN", "")
    ):
        yield
        return

    if config_string == "env" and not os.environ.get("GITHUB_TOKEN", ""):
        raise ValueError("GITHUB_TOKEN environment variable is not set")

    if config_string in ("try_env", "env"):
        config_string = os.environ["GITHUB_TOKEN"]

    yield {"github_token": config_string}


@contextlib.asynccontextmanager
def policy_engine_context_extra_init_secret_github_token_from_lifespan(
    context, request
):
    secrets = request.context["secrets"]
    if "GITHUB_TOKEN" not in secrets and hasattr(context.state, "github_token"):
        secrets["GITHUB_TOKEN"] = context.state.github_token


@contextlib.asynccontextmanager
def policy_engine_context_extra_init_fqdn(
    context, request
):
    request.context.setdefault("fqdn", os.environ.get("FQDN", "localhost:8080"))


async def gidgethub_get_access_token(context, request):
    # If we have a fine grained personal access token try using that
    if hasattr(context.state, "github_token"):
        return {"token": context.state.github_token}
    # Find installation ID associated with requesting actor to generated
    # finer grained token
    installation_id = None
    async for data in context.state.gidgethub.getiter(
        "/app/installations",
        jwt=context.state.github_app.danger_wide_permissions_token,
    ):
        if (
            request.context["config"]["env"].get("GITHUB_ACTOR", None)
            == data["account"]["login"]
        ):
            installation_id = data["id"]
            break
        elif request.context["config"]["env"]["GITHUB_REPOSITORY"].startswith(
            data["account"]["login"] + "/"
        ):
            installation_id = data["id"]
            break
    if installation_id is None:
        raise Exception(
            f'App installation not found for GitHub Repository {request.context["config"]["env"]["GITHUB_REPOSITORY"]!r} or Actor {request.context["config"]["env"].get("GITHUB_ACTOR", None)!r}'
        )

    result = await gidgethub.apps.get_installation_access_token(
        context.state.gidgethub,
        installation_id=installation_id,
        app_id=context.state.github_app.app_id,
        private_key=context.state.github_app.private_key,
    )
    result["installation"] = data
    return result


# TODO We need to async init lifespan callbacks and set context.state which
# will be not serializable on initial entry into async_celery_run_workflow
# @app.task(bind=True, base=MyTask)
# https://celery.school/sqlalchemy-session-celery-tasks
async def policy_engine_context_extra_init_secret_github_token_from_github_app(
    context, request
):
    secrets = request.context["secrets"]
    if "GITHUB_TOKEN" in secrets or not hasattr(context.state, "gidgethub") or not hasattr(context.state, "github_app"):
        return

    secrets["GITHUB_TOKEN"] = (
        await gidgethub_get_access_token(context, request)
    )["token"]


def make_entrypoint_style_string(obj):
    """
    Celery gets confused about import paths when os.exec()'d due to __main__.
    This fixes that by finding what package this file is within via path
    traversal of directories up the tree until no __init__.py file is found.
    """
    module_name = inspect.getmodule(obj).__name__
    file_path = pathlib.Path(__file__)
    module_path = [file_path.stem]
    if module_name == "__main__":
        module_in_dir_path = file_path.parent
        while module_in_dir_path.joinpath("__init__.py").exists():
            module_path.append(module_in_dir_path.stem)
            module_in_dir_path = module_in_dir_path.parent
        module_name = ".".join(module_path[::-1])
    return f"{module_name}:{obj.__name__}"


class LifespanCallbackWithConfig(BaseModel):
    entrypoint_string: Optional[str] = None
    config_string: Optional[str] = None
    callback: Optional[Callable] = Field(exclude=True, default=None)

    @model_validator(mode="after")
    # def load_callback_or_set_entrypoint_string(self) -> Self:
    def load_callback_or_set_entrypoint_string(self):
        if self.callback is not None and self.config_string is not None:
            self.entrypoint_string = (
                f"{make_entrypoint_style_string(self.callback)}"
            )
        elif self.entrypoint_string is not None and self.config_string is not None:
            self.callback = list(entrypoint_style_load(self.entrypoint_string))[
                0
            ]
        else:
            raise ValueError(
                "Must specify either (entrypoint_string and config_string) or (callback and config_string) via kwargs"
            )
        return self

    def __call__(self, *args, **kwargs):
        return self.callback(self.config_string, *args, **kwargs)


AnnotatedEntrypoint = Annotated[
    Callable,
    PlainSerializer(
        lambda obj: make_entrypoint_style_string(obj)
        if obj is not None and inspect.getmodule(obj) is not None
        else obj,
        return_type=str,
    ),
]


AnnotatedLifespanCallbackWithConfig = Annotated[
    Callable,
    PlainSerializer(
        lambda obj: obj.model_dump() if obj is not None else obj,
        return_type=dict,
    ),
]


class PolicyEngineContext(BaseModel, extra="forbid"):
    app: Optional[Any] = Field(exclude=True, default=None)
    state: Optional[Any] = Field(exclude=True, default=None)
    lifespan: Union[
        List[Dict[str, Any]], List[AnnotatedLifespanCallbackWithConfig]
    ] = Field(
        default_factory=lambda: [],
    )
    extra_inits: Union[List[str], List[AnnotatedEntrypoint]] = Field(
        default_factory=lambda: [],
    )
    extra_inits_config: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {}
    )

    @field_validator("extra_inits")
    @classmethod
    def parse_extra_inits(cls, extra_inits, _info):
        return list(
            [
                extra_init
                if not isinstance(extra_init, str)
                else list(entrypoint_style_load(extra_init))[0]
                for extra_init in extra_inits
            ]
        )

    @field_validator("lifespan")
    @classmethod
    def parse_lifespan(cls, lifespan, _info):
        return list(
            [
                lifespan_callback
                if isinstance(lifespan_callback, LifespanCallbackWithConfig)
                else LifespanCallbackWithConfig(**lifespan_callback)
                for lifespan_callback in lifespan
            ]
        )


fastapi_current_app = contextvars.ContextVar("fastapi_current_app")
fastapi_current_request = contextvars.ContextVar("fastapi_current_request")


@contextlib.asynccontextmanager
async def async_celery_setup_workflow(context, request):
    if isinstance(context, str):
        context = PolicyEngineContext.model_validate_json(context)
    if isinstance(request, str):
        request = PolicyEngineRequest.model_validate_json(request)
    stack = request.stack

    workflow = request.workflow

    async with contextlib.AsyncExitStack() as async_exit_stack:
        with contextlib.ExitStack() as exit_stack:
            if "async_exit_stack" not in request.context:
                request.context["async_exit_stack"] = async_exit_stack
            if "exit_stack" not in request.context:
                request.context["exit_stack"] = exit_stack
            if context.app is None or context.state is None:
                await request.context["async_exit_stack"].enter_async_context(
                    startup_fastapi_app_policy_engine_context(
                        fastapi_current_app.get()
                        if int(os.environ.get("NO_CELERY", "0"))
                        else celery_current_app,
                        context,
                    )
                )
            await celery_run_workflow_context_init(
                context,
                request,
            )
            if stack is None or len(stack) == 0:
                stack = celery_run_workflow_context_stack_make_new(
                    context, request, workflow.name,
                )
                stack["secrets"] = copy.deepcopy(request.context["secrets"])
                celery_run_workflow_context_stack_push(context, request, stack)
            yield (context, request)


async def async_celery_run_workflow(context, request):
    async with async_celery_setup_workflow(context, request) as (
        context,
        request,
    ):
        # TODO Kick off jobs in parallel / dep matrix
        for job_name, job in request.workflow.jobs.items():
            old_stack = request.context["stack"][-1]
            stack = celery_run_workflow_context_stack_make_new(
                context, request, job_name,
            )
            celery_run_workflow_context_stack_push(context, request, stack)
            # Don't allow messing with outputs at workflow scope (copy.deepcopy)
            stack["outputs"] = copy.deepcopy(old_stack["outputs"])
            # Don't allow messing with secrets at workflow scope (copy.deepcopy)
            stack["secrets"] = copy.deepcopy(old_stack["secrets"])
            # Run steps
            for i, step in enumerate(job.steps):
                old_stack = request.context["stack"][-1]
                stack = celery_run_workflow_context_stack_make_new(context, request, f"{i + 1} / {len(job.steps)}")
                celery_run_workflow_context_stack_push(context, request, stack)
                if step.shell:
                    stack["shell"] = step.shell
                # Keep the weakref, outputs should mod via pointer with job
                stack["outputs"] = old_stack["outputs"]
                # Don't allow messing with secrets (copy.deepcopy)
                stack["secrets"] = copy.deepcopy(old_stack["secrets"])
                stack["env"].update(step_build_env(context, request, step))
                stack["env"].update(step_build_inputs(context, request, step))
                try:
                    # step_index is tuple of (current index, length of steps)
                    await execute_step(context, request, step)
                except Exception as step_error:
                    # TODO error like app: and state: in PolicyEngineContext
                    if int(os.environ.get("DEBUG", "0")):
                        step_error = traceback.format_exc()
                        traceback.print_exc(file=sys.stderr)
                    request.context["stack"][-1]["error"] = step_error
                    if request.context["stack"][-2]["error"] is None:
                        request.context["stack"][-2]["error"] = step_error
                finally:
                    celery_run_workflow_context_stack_pop(context, request)
            job_error = request.context["stack"][-1]["error"]
            if job_error is not None:
                if not isinstance(job_error, Exception):
                    job_error = Exception(job_error)
                raise job_error

    detail = PolicyEngineComplete(
        id="",
        exit_status=PolicyEngineCompleteExitStatuses.SUCCESS,
        outputs={},
        annotations=request.context["annotations"],
    )
    request_status = PolicyEngineStatus(
        status=PolicyEngineStatuses.COMPLETE,
        detail=detail,
    )
    return request_status


async def no_celery_async_celery_run_workflow(context, request):
    try:
        return (
            await async_celery_run_workflow(context, request)
        ).model_dump_json()
    except Exception as error:
        if int(os.environ.get("DEBUG", "0")):
            error = traceback.format_exc()
        detail = PolicyEngineComplete(
            id="",
            exit_status=PolicyEngineCompleteExitStatuses.FAILURE,
            annotations={"error": [str(error)]},
        )
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.COMPLETE,
            detail=detail,
        )
        return request_status.model_dump_json()


@celery_task(no_celery_async=no_celery_async_celery_run_workflow)
def celery_run_workflow(context, request):
    return asyncio.get_event_loop().run_until_complete(
        no_celery_async_celery_run_workflow(context, request),
    )


@contextlib.asynccontextmanager
async def startup_fastapi_app_policy_engine_context(
    app,
    context: Optional[Dict[str, Any]] = None,
):
    state = {}
    if context is None:
        context = {}
    if isinstance(context, str):
        context = PolicyEngineContext.model_validate_json(context)
    elif not isinstance(context, PolicyEngineContext):
        context = PolicyEngineContext.model_validate(context)
    context.app = app
    state["context"] = context
    async with contextlib.AsyncExitStack() as async_exit_stack:
        for lifespan_callback in context.lifespan:
            state_update = await async_exit_stack.enter_async_context(
                lifespan_callback(app, context, state),
            )
            if state_update:
                state.update(state_update)
        context.state = types.SimpleNamespace(**state)
        yield state


def make_fastapi_app(
    *,
    context: Optional[Dict[str, Any]] = None,
):
    app = FastAPI(
        lifespan=lambda app: startup_fastapi_app_policy_engine_context(
            app,
            context,
        ),
    )

    @app.get("/rate_limit")
    async def route_policy_engine_status(
        fastapi_request: Request,
    ):
        state = fastapi_request.state
        github_token = None
        if hasattr(state, "github_app"):
            github_token = state.github_app.danger_wide_permissions_token
        elif hasattr(state, "github_token"):
            github_token = state.github_token
        return await state.gidgethub.getitem("/rate_limit", jwt=github_token)

    @app.get("/request/status/{request_id}")
    async def route_policy_engine_status(
        request_id: str,
        fastapi_request: Request,
    ) -> PolicyEngineStatus:
        global celery_app
        fastapi_current_app.set(fastapi_request.app)
        fastapi_current_request.set(fastapi_request)
        async with fastapi_request.state.no_celery_async_results_lock:
            request_task = AsyncResult(request_id, app=celery_app)
            request_task_state = request_task.state
        if request_task_state == "PENDING":
            request_status = PolicyEngineStatus(
                status=PolicyEngineStatuses.IN_PROGRESS,
                detail=PolicyEngineInProgress(
                    id=request_id,
                    # TODO Provide previous status updates?
                    status_updates={},
                ),
            )
        elif request_task_state in ("SUCCESS", "FAILURE"):
            async with fastapi_request.state.no_celery_async_results_lock:
                status_json_string = request_task.get()
            status = json.loads(status_json_string)
            detail_class = DETAIL_CLASS_MAPPING[status["status"]]
            status["detail"] = detail_class(**status["detail"])
            request_status = PolicyEngineStatus(**status)
            request_status.detail.id = request_id
        else:
            request_status = PolicyEngineStatus(
                status=PolicyEngineStatuses.UNKNOWN,
                detail=PolicyEngineUnknown(
                    id=request_id,
                ),
            )
        return request_status

    @app.post("/request/create")
    async def route_request(
        request: PolicyEngineRequest,
        fastapi_request: Request,
    ) -> PolicyEngineStatus:
        fastapi_current_app.set(fastapi_request.app)
        fastapi_current_request.set(fastapi_request)
        # TODO Handle when submitted.status cases
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.SUBMITTED,
            detail=PolicyEngineSubmitted(
                id=str(
                    (
                        await celery_run_workflow.asyncio_delay(
                            fastapi_request.state.context.model_dump_json(),
                            request.model_dump_json(),
                        )
                    ).id
                ),
            ),
        )
        return request_status


    @app.post("/webhook/github")
    async def github_webhook_endpoint(request: Request):
        fastapi_current_app.set(request.app)
        fastapi_current_request.set(request)
        # TODO(security) Set webhook secret as kwarg in from_http() call
        event = sansio.Event.from_http(request.headers, await request.body())
        # TODO Configurable events routed to workflows, issue ops
        if event.event not in ("push", "pull_request"):
            return
        # Copy context for this request
        context = PolicyEngineContext.model_validate_json(
            request.state.context.model_dump_json()
        )
        context.app = request.app
        context.state = request.state
        # Router does not return results of dispatched functions
        task_id = await check_suite_requested_triggers_run_workflows(
            event,
            context.state.gidgethub,
            context,
        )
        return PolicyEngineStatus(
            status=PolicyEngineStatuses.SUBMITTED,
            detail=PolicyEngineSubmitted(id=task_id),
        )

    return app


class NoLockNeeded:
    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc_value, _exc_traceback):
        pass


@contextlib.asynccontextmanager
async def lifespan_no_celery(
    config_string,
    _app,
    _context,
    _state,
):
    lock = asyncio.Lock()
    if not int(config_string):
        lock = NoLockNeeded()
    yield {
        "no_celery_async_results_lock": lock,
        "no_celery_async_results": {},
    }


DEFAULT_LIFESPAN_CALLBACKS = [
    LifespanCallbackWithConfig(
        callback=lifespan_no_celery,
        config_string=os.environ.get("NO_CELERY", "0"),
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_gidgethub,
        config_string="",
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_github_token,
        config_string="try_env",
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_deno,
        config_string="https://github.com/denoland/deno/releases/download/v1.41.3/deno-x86_64-unknown-linux-gnu.zip",
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_nodejs,
        config_string="https://nodejs.org/dist/v20.11.1/node-v20.11.1-linux-x64.tar.xz",
    ),
]
for callback_key, entrypoint_string in os.environ.items():
    if not callback_key.startswith("LIFESPAN_CALLBACK_"):
        continue
    config_key = callback_key.replace("CALLBACK", "CONFIG", 1)
    if not config_key in os.environ:
        raise Exception(
            f"{callback_key} set in environment. {config_key} required but not found."
        )
    DEFAULT_LIFESPAN_CALLBACKS.append(
        LifespanCallbackWithConfig(
            entrypoint_string=entrypoint_string,
            config_string=os.environ[config_key],
        )
    )


DEFAULT_EXTRA_INITS = [
    policy_engine_context_extra_init_secret_github_token_from_github_app,
    policy_engine_context_extra_init_secret_github_token_from_lifespan,
    policy_engine_context_extra_init_fqdn,
]

def make_default_policy_engine_context():
    return PolicyEngineContext(
        lifespan=DEFAULT_LIFESPAN_CALLBACKS.copy(),
        extra_inits=DEFAULT_EXTRA_INITS.copy(),
    )


async def background_task_celery_worker():
    # celery_app.worker_main(argv=["worker", "--loglevel=INFO"])
    celery_app.tasks["tasks.celery_run_workflow"] = celery_run_workflow
    celery_app.tasks["tasks.workflow_run_github_app_gidgethub"] = (
        workflow_run_github_app_gidgethub
    )
    async with startup_fastapi_app_policy_engine_context(
        celery_app,
        context=make_default_policy_engine_context(),
    ) as state:
        # Ensure these are always in the path so they don't download on request
        with prepend_to_path(
            state["deno"].parent, state["nodejs"].parent, env=os.environ,
        ) as env:
            celery_app.Worker(app=celery_app).start()


def celery_worker_exec_with_python():
    import nest_asyncio

    nest_asyncio.apply()
    asyncio.run(background_task_celery_worker())


module_name, function_name = make_entrypoint_style_string(celery_worker_exec_with_python).split(":")
CELERY_WORKER_EXEC_WITH_PYTHON = f"import {module_name}; {module_name}.{function_name}()"


@contextlib.contextmanager
def subprocess_celery_worker(**kwargs):
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            CELERY_WORKER_EXEC_WITH_PYTHON,
        ],
        **kwargs,
    )
    try:
        yield proc
    finally:
        proc.terminate()


@pytest.fixture
def pytest_fixture_background_task_celery_worker():
    if int(os.environ.get("NO_CELERY", "0")):
        yield
        return
    with subprocess_celery_worker() as proc:
        yield proc


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "context,workflow",
    [
        [
            make_default_policy_engine_context(),
            {
                "jobs": {
                    "TEST_JOB": {
                        "steps": [
                            {
                                "id": "greeting-step",
                                "env": {
                                    "REPO_NAME": "${{ github.event.inputs.repo_name }}",
                                },
                                "run": "echo hello=$REPO_NAME | tee -a $GITHUB_OUTPUT",
                            },
                            {
                                "uses": "actions/github-script@v7",
                                "env": {
                                    "GREETING": "${{ steps.greeting-step.outputs.hello }}",
                                },
                                "with": {
                                    "script": 'console.log(`Hello ${process.env["GREETING"]}`)',
                                },
                            },
                        ],
                    },
                },
            },
        ],
        [
            make_default_policy_engine_context(),
            textwrap.dedent(
                """
                on:
                  push:
                    branches:
                    - main

                jobs:
                  test:
                    runs-on: self-hosted
                    steps:
                    - uses: actions/checkout@v4
                    - run: |
                        echo Hello World
                """
            ),
        ],
    ],
)
async def test_read_main(
    pytest_fixture_background_task_celery_worker,
    context,
    workflow,
):
    app = make_fastapi_app(context=context)

    policy_engine_request = PolicyEngineRequest(
        inputs={
            "repo_name": "scitt-community/scitt-api-emulator",
        },
        context={
            "config": {
                "env": {
                    "GITHUB_REPOSITORY": "scitt-community/scitt-api-emulator",
                    "GITHUB_API": "https://api.github.com/",
                    "GITHUB_ACTOR": "pdxjohnny",
                    "GITHUB_ACTOR_ID": "1234567",
                },
            },
        },
        # URN for receipt for policy / transparency-configuration
        workflow=workflow,
    )
    policy_engine_request_serialized = policy_engine_request.model_dump_json()

    with TestClient(app) as client:
        # Submit
        response = client.post(
            "/request/create", content=policy_engine_request_serialized
        )
        assert response.status_code == 200, json.dumps(
            response.json(), indent=4
        )
        policy_engine_request_status = response.json()
        assert (
            PolicyEngineStatuses.SUBMITTED.value
            == policy_engine_request_status["status"]
        )

        policy_engine_request_id = policy_engine_request_status["detail"]["id"]

        # Check complete
        for _ in range(0, 1000):
            response = client.get(f"/request/status/{policy_engine_request_id}")
            assert response.status_code == 200, json.dumps(
                response.json(), indent=4
            )
            policy_engine_request_status = response.json()
            policy_engine_request_id = policy_engine_request_status["detail"][
                "id"
            ]
            if (
                PolicyEngineStatuses.IN_PROGRESS.value
                != policy_engine_request_status["status"]
            ):
                break
            time.sleep(0.01)

        assert (
            PolicyEngineStatuses.COMPLETE.value
            == policy_engine_request_status["status"]
        )

        # Check completed results
        policy_engine_request_completed = policy_engine_request_status["detail"]


import asyncio
import importlib
import os
import sys
import time
import traceback

import aiohttp
from aiohttp import web
import cachetools
from gidgethub import aiohttp as gh_aiohttp
from gidgethub import routing
from gidgethub import sansio


router = routing.Router()
cache = cachetools.LRUCache(maxsize=500)


# https://docs.github.com/en/enterprise-cloud@latest/rest/checks/runs?apiVersion=2022-11-28
# https://docs.github.com/en/enterprise-cloud@latest/webhooks/webhook-events-and-payloads?actionType=requested_action#check_run
# https://docs.github.com/en/enterprise-cloud@latest/rest/guides/using-the-rest-api-to-interact-with-checks?apiVersion=2022-11-28#check-runs-and-requested-actions
# @router.register("check_run", action="requested_action")
# @router.register("check_run", action="rerequested")


class GitHubCheckSuiteAnnotation(BaseModel):
    path: str = ""
    annotation_level: str = ""
    title: str = ""
    message: str = ""
    raw_details: str = ""
    start_line: int = 0
    end_line: int = 0


class TriggerAction(BaseModel):
    triggered: bool
    markdown_link: str


async def async_workflow_run_github_app_gidgethub(
    context,
    request,
    event,
    task_id,
):
    event = sansio.Event(
        event["data"],
        event=event["event"],
        delivery_id=event["delivery_id"],
    )
    event.data = GitHubWebhookEvent.model_validate(event.data)
    async with async_celery_setup_workflow(context, request) as (
        context,
        request,
    ):
        access_token_response = await gidgethub_get_access_token(
            context, request
        )
        # access_token_response["installation"] contains installation info
        installation_jwt = access_token_response["token"]
        started_at = datetime.datetime.now()
        full_name = event.data.repository.full_name
        # NOTE BUG XXX https://support.github.com/ticket/personal/0/2686424
        # The REST check-run endpoint docs say those routes work with fine
        # grained personal access tokens, but they also say they only work with
        # GitHub Apps, I keep getting Resource not accessible by personal access
        # token when I make a request. Is this an inconsistency with the
        # documentation? Should it work with fine grained PAT's as listed? I've
        # enabled Read & Write on status checks for the fine grained PAT I'm
        # using.
        # https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28#create-a-check-run
        check_run_id = None
        if hasattr(context.state, "github_app"):
            # GitHub App, use check-runs API
            url = f"https://api.github.com/repos/{full_name}/check-runs"
            data = {
                "name": request.workflow.name,
                "head_sha": event.data.after,
                "status": "in_progress",
                "external_id": task_id,
                "started_at": started_at.astimezone(datetime.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "output": {
                    "title": request.workflow.name,
                    "summary": "",
                    "text": "",
                },
            }
        else:
            # Personal Access Token, use commit status API
            url = f'https://api.github.com/repos/{full_name}/statuses/{event.data.after}'
            data = {
                "state": "pending",
                # TODO FQDN from lifespan config
                "target_url": f'http://{request.context["fqdn"]}/request/status/{task_id}',
                "description": request.workflow.name,
                "context": f"policy_engine/workflow/{request.workflow.name}",
            }
        check_run_result = await context.state.gidgethub.post(
            url, data=data, jwt=installation_jwt
        )
        check_run_id = check_run_result["id"]
        status = await async_celery_run_workflow(context, request)

        failure_count = len(request.context["annotations"].get("error", []))
        warning_count = len(request.context["annotations"].get("warning", []))
        notice_count = len(request.context["annotations"].get("notice", []))
        annotations_flattened = []
        annotations_trigger_action_links = []

        for annotation_level in request.context["annotations"]:
            for annotation in request.context["annotations"][annotation_level]:
                annotations_flattened.append(json.loads(annotation.model_dump_json()))
                # TODO Lifespan config for trigger actions
                # TODO Use ad-hoc cve created from annotation to create statement
                # which we use the URN of as the subject for the next statement
                # which is the proposed action to take. If there are multiple
                # potential actions we propose then we add those as well to the
                # proposed workflow. Downstream jobs can propose further or hook of
                # new data events, pre-exec flight checks on operating context
                # should decided if new flows should be added prior to clear for
                # take off issused.
                # TODO Use SCITT URN of proposed exec (before clear for take off) to
                # point to proposed fix (inputs as ad-hoc cve from annotation and
                # associated fix hypothesized actions to take workflow)
                ad_hoc_cve_urn = "urn:scitt:........."
                trigger_action_link = f"https://scitt.example.com/entries/{ad_hoc_cve_urn}"
                trigger_action_link_markdown = f"[Trigger Action Based Off: {annotation.title}]({trigger_action_link})"
                annotations_trigger_action_links.append(
                    TriggerAction(
                        triggered=False,
                        markdown_link=trigger_action_link_markdown,
                    )
                )

        output_markdown = "\n".join(
            [
                f"- [{'x' if trigger_action.triggered else ' '}] {trigger_action.markdown_link}"
                for trigger_action in annotations_trigger_action_links
            ]
        )

        if hasattr(context.state, "github_app"):
            # GitHub App, use check-runs API
            url = f"https://api.github.com/repos/{full_name}/check-runs/{check_run_id}"
            data = {
                "name": request.workflow.name,
                "started_at": started_at.astimezone(datetime.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "status": "completed",
                "conclusion": (
                    PolicyEngineCompleteExitStatuses.FAILURE.value
                    if request.context.get("failure_on_error_annotations_present", True) and failure_count
                    else status.detail.exit_status.value
                ),
                "completed_at": datetime.datetime.now()
                .astimezone(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "output": {
                    "title": request.workflow.name,
                    "summary": f"There are {failure_count} failures, {warning_count} warnings, and {notice_count} notices.",
                    "text": output_markdown,
                    "annotations": annotations_flattened,
                    # "images": [
                    #     {
                    #         "alt": "Super bananas",
                    #         "image_url": "http://example.com/images/42",
                    #     }
                    # ],
                },
            }
            await context.state.gidgethub.patch(
                url, data=data, jwt=installation_jwt
            )
        else:
            # Personal Access Token, use commit status API
            url = f'https://api.github.com/repos/{full_name}/statuses/{event.data.after}'
            data = {
                # TODO Handle failure
                "state": (
                    PolicyEngineCompleteExitStatuses.FAILURE.value
                    if request.context.get("failure_on_error_annotations_present", True) and failure_count
                    else status.detail.exit_status.value
                ),
                "target_url": f'http://{request.context["fqdn"]}/request/status/{task_id}',
                "description": request.workflow.name[:160],
                "context": f"policy_engine/workflow/{request.workflow.name}",
            }
            await context.state.gidgethub.post(
                url, data=data, jwt=installation_jwt
            )
            # TODO Create commit comment with same content as GitHub App would
            # https://docs.github.com/en/enterprise-cloud@latest/rest/commits/comments?apiVersion=2022-11-28#create-a-commit-comment

    detail = PolicyEngineComplete(
        id="",
        exit_status=PolicyEngineCompleteExitStatuses.SUCCESS,
        outputs={},
        annotations=request.context["annotations"],
    )
    request_status = PolicyEngineStatus(
        status=PolicyEngineStatuses.COMPLETE,
        detail=detail,
    )
    return request_status


async def no_celery_async_workflow_run_github_app_gidgethub(
    self, context, request, event
):
    try:
        return (
            await async_workflow_run_github_app_gidgethub(
                context,
                request,
                event,
                self.request.id,
            )
        ).model_dump_json()
    except Exception as error:
        traceback.print_exc(file=sys.stderr)
        detail = PolicyEngineComplete(
            id="",
            exit_status=PolicyEngineCompleteExitStatuses.FAILURE,
            annotations={"error": [str(error)]},
        )
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.COMPLETE,
            detail=detail,
        )
        return request_status.model_dump_json()


@celery_task(
    bind=True, no_celery_async=no_celery_async_workflow_run_github_app_gidgethub
)
def workflow_run_github_app_gidgethub(self, context, request, event):
    return asyncio.get_event_loop().run_until_complete(
        no_celery_async_workflow_run_github_app_gidgethub(
            self,
            context,
            request,
            event,
        )
    )


# @router.register("check_suite", action="requested")
@router.register("push")
@router.register("pull_request", action="opened")
@router.register("pull_request", action="synchronize")
async def check_suite_requested_triggers_run_workflows(
    event,
    gh,
    context,
):
    event.data = GitHubWebhookEvent.model_validate(event.data)
    return str(
        (
            await workflow_run_github_app_gidgethub.asyncio_delay(
                context.model_dump_json(),
                PolicyEngineRequest(
                    context={
                        "config": {
                            "env": {
                                "GITHUB_ACTOR": event.data.sender.login,
                                "GITHUB_REPOSITORY": event.data.repository.full_name,
                            },
                        },
                    },
                    # TODO workflow router to specify which webhook trigger which workflows
                    workflow=event.data.sender.webhook_workflow,
                ).model_dump_json(),
                {
                    **event.__dict__,
                    **{
                        "data": json.loads(event.data.model_dump_json()),
                    }
                },
            )
        ).id
    )


@pytest.mark.asyncio
async def test_github_app_gidgethub_github_webhook(
    pytest_fixture_background_task_celery_worker,
):
    context = make_default_policy_engine_context()

    app = make_fastapi_app(context=context)

    data = {
        "after": "a1b70ee3b0343adc24e3b75314262e43f5c79cc2",
        "repository": {
            "full_name": "pdxjohnny/scitt-api-emulator",
        },
        "sender": {
            "login": "pdxjohnny",
        },
    }
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": "42",
    }

    with TestClient(app) as client:
        # Submit
        response = client.post(
            "/webhook/github",
            headers=headers,
            json=data,
        )
        assert response.status_code == 200, json.dumps(
            response.json(), indent=4
        )
        policy_engine_request_status = response.json()
        assert (
            PolicyEngineStatuses.SUBMITTED.value
            == policy_engine_request_status["status"]
        )

        policy_engine_request_id = policy_engine_request_status["detail"]["id"]

        # Check complete
        for _ in range(0, 1000):
            response = client.get(f"/request/status/{policy_engine_request_id}")
            assert response.status_code == 200, json.dumps(
                response.json(), indent=4
            )
            policy_engine_request_status = response.json()
            policy_engine_request_id = policy_engine_request_status["detail"][
                "id"
            ]
            if (
                PolicyEngineStatuses.IN_PROGRESS.value
                != policy_engine_request_status["status"]
            ):
                break
            time.sleep(0.01)

        assert (
            PolicyEngineStatuses.COMPLETE.value
            == policy_engine_request_status["status"]
        )

        # Check completed results
        policy_engine_request_completed = policy_engine_request_status["detail"]


class StandaloneApplication(gunicorn.app.base.BaseApplication):
    # https://docs.gunicorn.org/en/stable/custom.html
    # https://www.uvicorn.org/deployment/#gunicorn

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def cli_worker(args):
    lifespan_callbacks_env = {}
    for lifespan_callback in args.lifespan:
        if lifespan_callback in DEFAULT_LIFESPAN_CALLBACKS:
            continue

        i = str(uuid.uuid4())
        lifespan_callbacks_env.update(
            {
                f"LIFESPAN_CALLBACK_{i}": lifespan_callback.entrypoint_string,
                f"LIFESPAN_CONFIG_{i}": lifespan_callback.config_string,
            }
        )

    os.execvpe(
        sys.executable,
        [
            sys.executable,
            "-c",
            CELERY_WORKER_EXEC_WITH_PYTHON,
        ],
        env={
            **os.environ,
            **lifespan_callbacks_env,
        },
    )


def cli_api(args):
    app = make_fastapi_app(
        context={
            "extra_inits": args.request_context_extra_inits,
            "lifespan": args.lifespan,
        },
    )
    options = {
        "bind": args.bind,
        "workers": args.workers,
        "worker_class": "uvicorn.workers.UvicornWorker",
    }
    StandaloneApplication(app, options).run()


async def client_create(
    endpoint: str,
    repository: str,
    workflow: Union[str, dict, PolicyEngineWorkflow],
    input: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    timeout: Optional[int] = None,
    session: Optional[aiohttp.ClientSession] = None,
):
    if isinstance(workflow, str):
        if workflow.startswith("https://"):
            # TODO Download workflow, optionally supply auth token
            raise NotImplementedError("Workflows from URLs not implemented")
        elif workflow.endswith(".yml") or workflow.endswith(".yaml"):
            workflow = pathlib.Path(workflow).expanduser().read_text()
    request = PolicyEngineRequest(
        inputs=dict(input),
        context={
            "config": {
                "env": {
                    "GITHUB_REPOSITORY": repository,
                    "GITHUB_API": "https://api.github.com/",
                    # TODO Lookup from auth response?
                    # "GITHUB_ACTOR": actor,
                    # "GITHUB_ACTOR_ID": actor_id,
                },
            },
        },
        workflow=workflow,
    )
    if context is not None:
        request.context.update(context)

    async with contextlib.AsyncExitStack() as async_exit_stack:
        if session is None:
            session = await async_exit_stack.enter_async_context(
                aiohttp.ClientSession(trust_env=True),
            )
        url = f"{endpoint}/request/create"
        async with session.post(url, json=request.model_dump()) as response:
            try:
                status = PolicyEngineStatus.model_validate(await response.json())
            except:
                raise Exception(await response.text())

            if PolicyEngineStatuses.SUBMITTED != status.status:
                raise Exception(status)

    return status


async def client_status(
    endpoint: str,
    task_id: str,
    poll_interval_in_seconds: Union[int, float] = 0.01,
    timeout: Optional[int] = None,
    session: Optional[aiohttp.ClientSession] = None,
):
    async with contextlib.AsyncExitStack() as async_exit_stack:
        if session is None:
            session = await async_exit_stack.enter_async_context(
                aiohttp.ClientSession(trust_env=True),
            )
        # TODO Make this an argument or provide another command to poll + wss://
        # Check complete
        time_elapsed = 0.0
        while timeout == 0 or time_elapsed < timeout:
            url = f"{endpoint}/request/status/{task_id}"
            async with session.get(url) as response:
                try:
                    status = PolicyEngineStatus.model_validate(await response.json())
                except:
                    raise Exception(await response.text())
            if PolicyEngineStatuses.IN_PROGRESS != status.status:
                break
            await asyncio.sleep(poll_interval_in_seconds)
            time_elapsed += poll_interval_in_seconds

        if PolicyEngineStatuses.COMPLETE != status.status:
            raise Exception(f"Task timeout reached: {status!r}")

    return status


def cli_async_output(func, args):
    args = vars(args)
    output_args = {
        "output_format": "json",
        "output_file": sys.stdout,
    }
    del args["func"]
    for key in output_args:
        if key in args:
            output_args[key] = args[key]
            del args[key]
    output_args = types.SimpleNamespace(**output_args)
    coro = func(**args)
    result = asyncio.run(coro)
    if hasattr(result, "model_dump_json"):
        result = json.loads(result.model_dump_json())
    if output_args.output_format == "json":
        serialized = json.dumps(result, indent=4, sort_keys=True)
    elif output_args.output_format == "yaml":
        serialized = yaml.dump(result, default_flow_style=False)[:-1]
    else:
        raise NotImplementedError("Can only output JSON and YAML")
    print(serialized, file=output_args.output_file)


def parser_add_argument_lifespan(parser):
    parser.add_argument(
        "--lifespan",
        nargs=2,
        action="append",
        metavar=("entrypoint", "config"),
        default=DEFAULT_LIFESPAN_CALLBACKS.copy(),
        help=f"entrypoint.style:path ~/path/to/assocaited/config.json for startup and shutdown async context managers. Yield from to set fastapi|celery.app.state",
    )


def cli():
    # TODO Take sys.argv as args to parse as optional
    estimated_number_of_workers = number_of_workers()

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(help="sub-command help")
    parser.set_defaults(func=lambda _: None)

    parser_worker = subparsers.add_parser("worker", help="Run Celery worker")
    parser_worker.set_defaults(func=cli_worker)
    parser_add_argument_lifespan(parser_worker)

    parser_api = subparsers.add_parser("api", help="Run API server")
    parser_api.set_defaults(func=cli_api)
    parser_add_argument_lifespan(parser_api)
    parser_api.add_argument(
        "--bind",
        default="127.0.0.1:8080",
        help="Interface to bind on, default: 127.0.0.1:8080",
    )
    parser_api.add_argument(
        "--workers",
        type=int,
        default=estimated_number_of_workers,
        help=f"Number of workers, default: {estimated_number_of_workers}",
    )
    parser_api.add_argument(
        "--request-context-extra-inits",
        nargs="+",
        default=DEFAULT_EXTRA_INITS.copy(),
        help=f"Entrypoint style paths for PolicyEngineContext.extra_inits",
    )

    parser_client = subparsers.add_parser("client", help="Interact with API")
    parser_client.set_defaults(func=lambda _args: None)
    client_subparsers = parser_client.add_subparsers(help="Client")
    parser_client.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout to wait for status to move to complete. 0 is don't wait just check status",
    )
    parser_client.add_argument(
        "--endpoint",
        "-e",
        required=True,
        help="Endpoint to connect to",
    )
    parser_client.add_argument(
        "--output-format",
        default="json",
        help="Output format (json, yaml)",
    )
    parser_client.add_argument(
        "--output-file",
        default=sys.stdout,
        type=argparse.FileType('w', encoding='UTF-8'),
        help="Output file",
    )

    parser_client_create = client_subparsers.add_parser("create", help="Create workflow execution request")
    parser_client_create.set_defaults(
        func=lambda args: cli_async_output(client_create, args),
    )
    parser_client_create.add_argument(
        "--input",
        "-i",
        nargs=2,
        action="append",
        metavar=("key", "value"),
        default=[],
        help="Inputs to workflow",
    )
    parser_client_create.add_argument(
        "--context",
        "-c",
        type=json.loads,
        default={},
        help="JSON string for updates to context",
    )
    parser_client_create.add_argument(
        "--workflow",
        "-w",
        required=True,
        help="Workflow to run",
    )
    parser_client_create.add_argument(
        "--repository",
        "-R",
        required=True,
        help="Repository to run as",
    )

    parser_client_status = client_subparsers.add_parser("status", help="Status of workflow execution request")
    parser_client_status.set_defaults(
        func=lambda args: cli_async_output(client_status, args),
    )
    parser_client_status.add_argument(
        "--task-id",
        "-t",
        default=None,
        help="Task ID to monitor status of",
    )
    parser_client_status.add_argument(
        "--poll-interval-in-seconds",
        "-p",
        type=float,
        default=0.01,
        help="Time between poll re-request of status route",
    )

    args = parser.parse_args()

    if hasattr(args, "lifespan"):
        args.lifespan = list(
            map(
                lambda arg: arg
                if isinstance(arg, LifespanCallbackWithConfig)
                else LifespanCallbackWithConfig(
                    entrypoint_string=arg[0],
                    config_string=arg[1],
                ),
                args.lifespan,
            )
        )

    args.func(args)


import os
import abc
import sys
import pdb
import enum
import uuid
import json
import pprint
import asyncio
import getpass
import pathlib
import tempfile
import argparse
import traceback
import contextlib
import collections
import dataclasses
from typing import Any, List, Optional, NewType, AsyncIterator

with contextlib.suppress(Exception):
    import snoop


import openai
import agents.mcp as openai_agents_mcp
import keyring
import logging
import uvicorn
from pydantic import BaseModel, ConfigDict


logger = logging.getLogger(__name__)


class RetreiveInformation(BaseModel, extra="forbid"):
    query: str


class AGIOpenAIAssistantResponseStep(BaseModel, extra="forbid"):
    explanation: str
    bash_command: str


class AGIOpenAIAssistantResponse(BaseModel, extra="forbid"):
    # steps: list[AGIOpenAIAssistantResponseStep]
    # final_goal: str
    workflow: PolicyEngineWorkflow


def async_lambda(func):
    async def async_func():
        nonlocal func
        return func()

    return async_func


async def asyncio_sleep_for_then_coro(sleep_time, coro):
    await asyncio.sleep(sleep_time)
    return await coro


class AGIEventType(enum.Enum):
    ERROR = "error"
    END_EVENTS = "end_events"
    INTERNAL_RE_QUEUE = "internal_re_queue"
    NEW_AGENT_CREATED = "new_agent_created"
    EXISTING_AGENT_RETRIEVED = "existing_agent_retrieved"
    FILE_INGESTED = "file_ingested"
    NEW_THREAD_CREATED = "new_thread_created"
    NEW_THREAD_RUN_CREATED = "new_thread_run_created"
    NEW_THREAD_MESSAGE = "new_thread_message"
    THREAD_MESSAGE_ADDED = "thread_message_added"
    THREAD_RUN_COMPLETE = "thread_run_complete"
    THREAD_RUN_IN_PROGRESS = "thread_run_in_progress"
    THREAD_RUN_FAILED = "thread_run_failed"
    THREAD_RUN_EVENT_WITH_UNKNOWN_STATUS = "thread_run_event_with_unknown_status"


@dataclasses.dataclass
class AGIEvent:
    event_type: AGIEventType
    event_data: Any


AGIEventStream = NewType("AGIEventStream", AsyncIterator[AGIEvent])


@dataclasses.dataclass
class AGIEventNewAgent:
    agent_id: str
    agent_name: str


@dataclasses.dataclass
class AGIEventNewFileAdded:
    agent_id: str
    file_id: str


@dataclasses.dataclass
class AGIEventNewThreadCreated:
    agent_id: str
    thread_id: str


@dataclasses.dataclass
class AGIEventNewThreadRunCreated:
    agent_id: str
    thread_id: str
    run_id: str
    run_status: str


@dataclasses.dataclass
class AGIEventThreadRunComplete:
    agent_id: str
    thread_id: str
    run_id: str
    run_status: str


@dataclasses.dataclass
class AGIEventThreadRunInProgress:
    agent_id: str
    thread_id: str
    run_id: str
    run_status: str


@dataclasses.dataclass
class AGIEventThreadRunFailed:
    agent_id: str
    thread_id: str
    run_id: str
    run_status: str
    last_error: Any


@dataclasses.dataclass
class AGIEventThreadRunEventWithUnknwonStatus(AGIEventNewThreadCreated):
    agent_id: str
    thread_id: str
    run_id: str
    run_status: str


@dataclasses.dataclass
class AGIEventNewThreadMessage:
    agent_id: str
    thread_id: str
    message_role: str
    message_content_type: str
    message_content: str


@dataclasses.dataclass
class AGIEventThreadMessageAdded:
    agent_id: str
    thread_id: str
    message_id: str
    message_role: str
    message_content: str


class AGIActionType(enum.Enum):
    NEW_AGENT = "new_agent"
    INGEST_FILE = "ingest_file"
    ADD_MESSAGE = "add_message"
    NEW_THREAD = "new_thread"
    RUN_THREAD = "run_thread"
    CHECK_THREAD = "check_thread"


@dataclasses.dataclass
class AGIAction:
    action_type: AGIActionType
    action_data: Any


@dataclasses.dataclass
class AGIActionIngestFile:
    agent_id: str
    file_path: str


@dataclasses.dataclass
class AGIActionNewAgent:
    agent_id: str
    agent_name: str
    agent_instructions: str


@dataclasses.dataclass
class AGIActionNewThread:
    agent_id: str


@dataclasses.dataclass
class AGIActionCheckThread:
    agent_id: str
    thread_id: str


@dataclasses.dataclass
class AGIActionAddMessage:
    agent_id: str
    thread_id: str
    message_role: str
    message_content: str


@dataclasses.dataclass
class AGIActionRunThread:
    agent_id: str
    thread_id: str


AGIActionStream = NewType("AGIActionStream", AsyncIterator[AGIAction])


class AGIStateType(enum.Enum):
    AGENT = "agent"
    THREAD = "thread"


@dataclasses.dataclass
class AGIState:
    state_type: AGIStateType
    state_data: Any


@dataclasses.dataclass
class AGIStateAgent:
    agent_name: str
    agent_id: str
    file_ids: List[str] = dataclasses.field(
        default_factory=lambda: [],
    )
    thread_ids: List[str] = dataclasses.field(
        default_factory=lambda: [],
    )


@dataclasses.dataclass
class AGIStateThread:
    agent_id: str
    thread_id: str
    most_recent_run_id: Optional[str] = None
    most_recent_run_status: Optional[str] = None


class _KV_STORE_DEFAULT_VALUE:
    pass


KV_STORE_DEFAULT_VALUE = _KV_STORE_DEFAULT_VALUE()


class KVStore(abc.ABC):
    @abc.abstractmethod
    async def get(self, key, default_value: Any = KV_STORE_DEFAULT_VALUE):
        raise NotImplementedError()

    @abc.abstractmethod
    async def set(self, key, value):
        raise NotImplementedError()

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc_value, _traceback):
        return


class KVStoreKeyring(KVStore):
    def __init__(self, config):
        self.service_name = config["service_name"]

    async def get(self, key, default_value: Any = KV_STORE_DEFAULT_VALUE):
        if default_value is not KV_STORE_DEFAULT_VALUE:
            return self.keyring_get_password_or_return(
                self.service_name,
                key,
                not_found_return_value=default_value,
            )
        return keyring.get_password(self.service_name, key)

    async def set(self, key, value):
        return keyring.set_password(self.service_name, key, value)

    @staticmethod
    def keyring_get_password_or_return(
        service_name: str,
        username: str,
        *,
        not_found_return_value=None,
    ) -> str:
        with contextlib.suppress(Exception):
            value = keyring.get_password(service_name, username)
            if value is not None:
                return value
        return not_found_return_value


def make_argparse_parser(argv=None):
    parser = argparse.ArgumentParser(description="Generic AI")
    parser.add_argument(
        "--uds",
        dest="uds",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--user-name",
        dest="user_name",
        type=str,
        default=KVStoreKeyring.keyring_get_password_or_return(
            getpass.getuser(),
            "profile.username",
            not_found_return_value=getpass.getuser(),
        ),
        help="Handle to address the user as",
    )
    parser.add_argument(
        "--log",
        dest="log",
        default=logging.CRITICAL,
        type=lambda value: getattr(logging, value.upper()),
    )
    # TODO Integrate tmux stuff cleanly
    parser.add_argument(
        "--socket-path",
        dest="socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--input-socket-path",
        dest="input_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--client-side-input-socket-path",
        dest="client_side_input_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--text-output-socket-path",
        dest="text_output_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--client-side-text-output-socket-path",
        dest="client_side_text_output_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--ndjson-output-socket-path",
        dest="ndjson_output_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--client-side-ndjson-output-socket-path",
        dest="client_side_ndjson_output_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--mcp-reverse-proxy-socket-path",
        dest="mcp_reverse_proxy_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--client-side-mcp-reverse-proxy-socket-path",
        dest="client_side_mcp_reverse_proxy_socket_path",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--agi-name",
        dest="agi_name",
        default="alice",
        type=str,
    )
    parser.add_argument(
        "--kvstore-service-name",
        dest="kvstore_service_name",
        default="alice",
        type=str,
    )
    parser.add_argument(
        "--openai-api-key",
        dest="openai_api_key",
        type=str,
        default=os.environ.get(
            "OPENAI_API_KEY",
            KVStoreKeyring.keyring_get_password_or_return(
                getpass.getuser(),
                "openai.api.key",
            ),
        ),
        help="OpenAI API Key",
    )
    parser.add_argument(
        "--openai-base-url",
        dest="openai_base_url",
        type=str,
        default=KVStoreKeyring.keyring_get_password_or_return(
            getpass.getuser(),
            "openai.api.base_url",
        ),
        help="OpenAI API Key",
    )

    return parser


import inspect
import asyncio
from collections import UserList
from contextlib import AsyncExitStack
from typing import (
    Dict,
    Any,
    AsyncIterator,
    Tuple,
    Type,
    AsyncContextManager,
    Optional,
    Set,
)


class _STOP_ASYNC_ITERATION:
    pass


STOP_ASYNC_ITERATION = _STOP_ASYNC_ITERATION()


async def ignore_stopasynciteration(coro):
    try:
        return await coro
    except StopAsyncIteration:
        return STOP_ASYNC_ITERATION


async def concurrently(
    work: Dict[asyncio.Task, Any],
    *,
    errors: str = "strict",
    nocancel: Optional[Set[asyncio.Task]] = None,
) -> AsyncIterator[Tuple[Any, Any]]:
    # Track if first run
    first = True
    # Set of tasks we are waiting on
    tasks = set(work.keys())
    # Return when outstanding operations reaches zero
    try:
        while first or tasks:
            first = False
            # Wait for incoming events
            done, _pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                # Remove the task from the set of tasks we are waiting for
                tasks.remove(task)
                # Get the tasks exception if any
                exception = task.exception()
                if errors == "strict" and exception is not None:
                    raise exception
                if exception is None:
                    # Remove the compeleted task from work
                    complete = work[task]
                    del work[task]
                    yield complete, task.result()
                    # Update tasks in case work has been updated by called
                    tasks = set(work.keys())
    finally:
        for task in tasks:
            if not task.done() and (nocancel is None or task not in nocancel):
                task.cancel()
            else:
                # For tasks which are done but have exceptions which we didn't
                # raise, collect their exceptions
                task.exception()


GPT_MODEL_VERSION = "gpt-4o-2024-08-06"


def make_async_lambda(result):
    return async_lambda(lambda: result)

r"""
TODO

- Update agi.py to deploy client side service so we aren't doing things with
  bash so much in shell. Sock connects back and all should be API based
- Time tracking and engineering log gen
- Bash hook for new processes
  - kubectl exec
    - Capture context and insepct cluster, make available to LLM
- Trust boundries for code gen
  - Metadata classes should be created and loaded dynamically and added to
    vector db or whatever so that LLM can cruse through full context
  - Some runs on server with OpenAI API key and some runs on client.
  - Ideally we have some sort of proxy which issues scoped tokens so that the
    client can talk "directly" to OpenAI API and we keep stuff context local
- https://github.com/slsa-framework/attested-build-environments-demo
- "Clippy"
  - Open pane when debugging help is identified based on train of thought
    analysis.
    - Looks like you're trying to kubectl apply but it's stuck in
      ContainerCreating, did you type the image name correctly?
"""

import json
import logging
from typing import Dict, List, Optional, Union

import libtmux
import psutil
from pydantic import BaseModel, Field

# -----------------------------
# Define Pydantic data models
# -----------------------------

class GitRemote(BaseModel):
    name: str
    url: str

class GitMetadata(BaseModel):
    repo_root: str
    remotes: List[GitRemote] = Field(default_factory=list)

class ProcessNode(BaseModel):
    cmd: List[str]
    children: List["ProcessNode"] = []

# Allow recursive models
ProcessNode.model_rebuild()

class CommandMetadata(BaseModel):
    tree: ProcessNode

# This is the wrapper model that will be used to hold any metadata type.
class MetadataWrapper(BaseModel):
    metadata_class_entrypoint: str
    data: Union[GitMetadata, CommandMetadata]

class TmuxContext(BaseModel):
    active_pane: str = Field(default="Active pane unknown")
    session: Any = Field(exclude=True, default=None)
    pane: Any = Field(exclude=True, default=None)
    sessions: Dict[str, dict] = Field(default_factory=dict)

# -----------------------------
# Helper functions to collect metadata
# -----------------------------

def get_git_metadata(cwd: str) -> Optional[GitMetadata]:
    """
    Attempt to discover if the given cwd is inside a Git repository.
    If it is, return a GitMetadata instance containing the repo's top level
    directory (repo_root) and its remotes. Otherwise, return None.
    """
    try:
        from git import Repo  # GitPython must be installed.
        # search_parent_directories=True ensures that if cwd is a subdirectory,
        # the repository root will be located.
        repo = Repo(cwd, search_parent_directories=True)
        repo_root = repo.git.rev_parse("--show-toplevel")
        remotes = []
        for remote in repo.remotes:
            # Each remote can have one or more URLs; here we add each as a GitRemote.
            for url in remote.urls:
                remotes.append(GitRemote(name=remote.name, url=url))
        return GitMetadata(repo_root=repo_root, remotes=remotes)
    except Exception as error:
        logging.exception("get_git_metadata(%s)", cwd, exc_info=error)
        # cwd is likely not in a Git repository or an error occurred.
        return None

def build_process_tree(proc: psutil.Process) -> ProcessNode:
    """
    Recursively builds a tree structure for the given process.
    """
    try:
        cmdline = proc.cmdline()
        # NOTE Top level PIDs of bash processes seem to be "-bash", this fixes
        if cmdline[0].startswith("-"):
            cmdline[0] = cmdline[0][1:]
    except Exception as error:
        logging.exception("build_process_tree(%s)", proc, exc_info=error)
        cmdline = []
    try:
        children = proc.children()
    except Exception as error:
        logging.exception("build_process_tree(%s)", proc, exc_info=error)
        children = []
    child_nodes = [build_process_tree(child) for child in children]
    return ProcessNode(cmd=cmdline, children=child_nodes)

def get_command_metadata(pid: int) -> CommandMetadata:
    """
    Returns a CommandMetadata instance containing a process tree for the given PID.
    The tree includes the command-line (cmd) for the process and all its child processes.
    """
    try:
        root_proc = psutil.Process(pid)
        tree = build_process_tree(root_proc)
        return CommandMetadata(tree=tree)
    except Exception as error:
        logging.exception("get_command_metadata(%d)", pid, exc_info=error)
        # Process may have exited or access is denied.
        return None

# -----------------------------
# Main function to gather tmux info with metadata
# -----------------------------

def get_tmux_window_info(*, server: libtmux.Server = None):
    """
    Create a nested dictionary where:
      - The keys of the outer dictionary are session names.
      - For each session, keys of the inner dictionary are window names.
      - For each window, a list of pane dictionaries is stored.

    Each pane dictionary contains:
      - 'cwd': current working directory of the pane.
      - 'pid': pane's process id.
      - 'metadata': a list of MetadataWrapper instances providing additional info.
    """
    if server is None:
        server = libtmux.Server()
    tmux_ctx = TmuxContext(
        session=server.active_window.session,
    )
    session_info = tmux_ctx.sessions

    for session in server.sessions:
        windows_info = {}
        for window in session.windows:
            pane_details = []
            for pane in window.panes:
                cwd = pane.pane_current_path
                pid = int(pane.pane_pid)
                metadata_entries = []

                # Discover Git metadata based on the pane's cwd.
                git_meta = get_git_metadata(cwd)
                if git_meta is not None:
                    git_wrapper = MetadataWrapper(
                        metadata_class_entrypoint="my_module.git_metadata.GitMetadata",
                        data=git_meta
                    )
                    metadata_entries.append(git_wrapper)

                # Discover command metadata based on the pane's pid.
                cmd_meta = get_command_metadata(pid)
                if cmd_meta is not None:
                    cmd_wrapper = MetadataWrapper(
                        metadata_class_entrypoint="my_module.command_metadata.CommandMetadata",
                        data=cmd_meta
                    )
                    metadata_entries.append(cmd_wrapper)

                pane_detail = {
                    "cwd": cwd,
                    "pid": pid,
                    "metadata": metadata_entries,
                }
                pane_details.append(pane_detail)
            windows_info[window.name] = pane_details
        session_info[session.name] = windows_info

    return tmux_ctx


@dataclasses.dataclass
class UserContext:
    mcp_reverse_proxy_socket_path: str
    tmux_context: TmuxContext = Field(default_factory=TmuxContext)


from agents import Agent, RunContextWrapper, Runner, function_tool, set_default_openai_client, trace


@function_tool
async def fetch_user_tmux_session(wrapper: RunContextWrapper[UserContext]) -> str:
    tmux_context = wrapper.context.tmux_context
    if tmux_context.session is not None:
        tmux_context.active_pane = str(tmux_context.session.active_pane)
        tmux_context.sessions = get_tmux_window_info(
            server=tmux_context.session.server,
        )
    return f"User terminal multiplexer context is {tmux_context.model_dump_json()}"


# TODO We should reverse proxy the policy engine service and enable output
# capture of workflow execution, is there already streaming of output? We want
# it so we can return it from this tool
@function_tool
async def execute_generated_workflow(
    wrapper: RunContextWrapper[UserContext],
    workflow: PolicyEngineWorkflow,
) -> str:
    snoop.pp("execute_generated_workflow", workflow)
    tmux_context = wrapper.context.tmux_context
    pane = tmux_context.pane
    policy_engine_task_id = None

    if pane is not None:
        session = pane.window.session
        tempdir_lookup_env_var = f'TEMPDIR_ENV_VAR_TMUX_WINDOW_{session.active_window.id.replace("@", "")}'
        tempdir_env_var  = pane.window.session.show_environment()[tempdir_lookup_env_var]
        tempdir = pathlib.Path(
            pane.window.session.show_environment()[tempdir_env_var],
        )
        # Proposed workflow to be submitted to policy engine to get clear
        # for take off (aka workload id and exec in phase 0). Executing the
        # policy aka the workflow (would be the one we insert to once
        # paths can be mapped to poliy engine workflows easily
        proposed_workflow_contents = yaml.dump(
            json.loads(workflow.model_dump_json()),
            default_flow_style=False,
            sort_keys=True,
        )
        request_contents = yaml.dump(
            json.loads(
                PolicyEngineRequest(
                    inputs={},
                    context={
                        "config": {
                            "cwd": str(tempdir),
                        },
                    },
                    stack={},
                    workflow=workflow,
                ).model_dump_json(),
            )
        )
        # Find and kill jq listening to ndjson output so we can type
        pane.send_keys("C-c", enter=False, suppress_history=False)
        pane.send_keys('if [ "x${CALLER_PATH}" = "x" ]; then export CALLER_PATH="' + str(tempdir) + '"; fi', enter=True)
        pane.send_keys(
            "cat > \"${CALLER_PATH}/proposed-workflow.yml\" <<\'WRITE_OUT_SH_EOF\'"
            + "\n"
            + proposed_workflow_contents
            + "\nWRITE_OUT_SH_EOF",
            enter=True,
        )
        pane.send_keys(
            "cat > \"${CALLER_PATH}/request.yml\" <<\'WRITE_OUT_SH_EOF\'"
            + "\n"
            + request_contents
            + "\nWRITE_OUT_SH_EOF",
            enter=True,
        )
        pane.send_keys(f"submit_policy_engine_request", enter=True)

        # TODO(windows) Env dumping changes on Windows
        echo_policy_engine_task_id = 'echo POLICY_ENGINE_TASK_ID="${POLICY_ENGINE_TASK_ID}"'
        pane.send_keys(echo_policy_engine_task_id, enter=True)
        while not any([line.startswith("POLICY_ENGINE_TASK_ID=") for line in pane.capture_pane()]):
            await asyncio.sleep(0.1)

        policy_engine_task_id = list(
            [
                line.strip().split("POLICY_ENGINE_TASK_ID=", maxsplit=1)[-1]
                for line in pane.capture_pane()
                if line.startswith("POLICY_ENGINE_TASK_ID=")
            ]
        )[0]

    else:
        # TODO Send workflow to policy engine via pty or forwarded socket
        raise NotImplementedError("Only TMUX support for workflow exec currently")

    if policy_engine_task_id is None:
        raise Exception("Failed to get policy engine task ID to capture output")

    transport = httpx.AsyncHTTPTransport(
        uds=wrapper.context.mcp_reverse_proxy_socket_path,
    )
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get(
            f"http://policy-engine/request/status/{policy_engine_task_id}",
        )
        request_status = response.json()
        response = await client.get(
            f"http://policy-engine/request/console_output/{policy_engine_task_id}",
        )
        snoop.pp(request_status, response.status_code, response.text)
        response.raise_for_status()
        return response.text


class AGIThreadNotFoundError(Exception):
    pass


import http
import httpx


class CaddyConfigLoadError(Exception):
    pass


async def caddy_config_update(mcp_reverse_proxy_socket_path, slug):
    transport = httpx.AsyncHTTPTransport(uds=mcp_reverse_proxy_socket_path)
    async with httpx.AsyncClient(transport=transport) as client:
        # TODO Booooooooo timeout booooooo
        time = 0
        success = False
        while not success and time < 5:
            try:
                await client.get("http://127.0.0.1/config/")
                success = True
            except httpx.RemoteProtocolError:
                await asyncio.sleep(0.1)
                time += 0.1
        response = await client.get(
            "http://127.0.0.1/config/",
        )
        caddy_config = response.json()
        exists = False
        proxy_route_caddy_admin = None
        for route in caddy_config['apps']['http']['servers']['srv0']['routes']:
            for match in route['match']:
                for host in match['host']:
                    if host == '127.0.0.1':
                        proxy_route_caddy_admin = route
                    elif host == slug:
                        exists = True
        if exists:
            return
        proxy_route_new = json.loads(
            json.dumps(
                proxy_route_caddy_admin,
            ).replace(
                "caddy-admin", slug,
            ).replace(
                "127.0.0.1", slug,
            ),
        )
        caddy_config['apps']['http']['servers']['srv0']['routes'].append(
            proxy_route_new,
        )
        response = await client.post(
            "http://127.0.0.1/load",
            headers={"Content-Type": "application/json"},
            content=json.dumps(caddy_config),
        )
        if response.status_code != http.HTTPStatus.OK.value:
            raise CaddyConfigLoadError(f"{response.status_code}: {response.text}")
        response = await client.get(
            "http://127.0.0.1/config/",
        )
        caddy_config = response.json()
        snoop.pp(caddy_config)


def make_done_callback(event):
    def done_callback(*args):
        nonlocal event
        snoop.pp('done_callback', args)
        event.set()
    return done_callback


async def agent_openai(
    tg: asyncio.TaskGroup,
    async_exit_stack: contextlib.AsyncExitStack,
    user_context: UserContext,
    agi_name: str,
    kvstore: KVStore,
    action_stream: AGIActionStream,
    action_stream_insert: Callable[[Any], Awaitable[Any]],
    waiting_event_stream_insert: Callable[[Any], Awaitable[Any]],
    openai_api_key: str,
    mcp_reverse_proxy_socket_path: str,
    *,
    openai_base_url: Optional[str] = None,
):
    client = openai.AsyncOpenAI(
        api_key=openai_api_key,
        base_url=openai_base_url,
    )
    set_default_openai_client(client)

    # TODO NOTE This fucks up conncurently() due to aynio.create_task_group or
    # something called under the MCP server, maybe just stdio fuck up? Maybe SSE
    # works?
    # mcp_server_top = await async_exit_stack.enter_async_context(
    #     openai_agents_mcp.MCPServerStdio(
    #         # cache_tools_list=True,  # Cache the tools list, for demonstration
    #         params={"command": "uvx", "args": ["mcp-server-git"]},
    #     )
    # )
    # TODO Actions for adding more MCP servers, for N-1 in stack actions for
    # starting them on the client, for N-1 in stack writing new ones and
    # analysis and threat model trust boundry stuff.
    # TODO These should be a class that's part of the action data
    mcp_servers = [
        {
            "name": "File Resource Server",
            "slug": "files",
        },
        # {
        #     "name": "Execute terminal commands and manage files with diff editing capabilities. Coding, shell and terminal, task automation",
        #     "slug": "desktopcommander",
        # },
    ]
    mcp_servers_top = []

    transport = httpx.AsyncHTTPTransport(uds=mcp_reverse_proxy_socket_path)
    for mcp_server in mcp_servers:
        await caddy_config_update(mcp_reverse_proxy_socket_path, mcp_server['slug'])
        mcp_servers_top.append(
            await async_exit_stack.enter_async_context(
                openai_agents_mcp.MCPServerSse(
                    name=mcp_server["name"],
                    params={
                        "url": f"http://{mcp_server['slug']}/sse",
                        "transport": transport,
                    },
                ),
            ),
        )

    snoop.pp("MCP servers have been setup")

    agents = {}
    threads = {}
    tool_calls = {}

    action_stream_iter = action_stream.__aiter__()
    work = {
        tg.create_task(
            ignore_stopasynciteration(action_stream_iter.__anext__())
        ): (
            "action_stream",
            action_stream_iter,
        ),
    }
    async for (work_name, work_ctx), result in concurrently(work):
        logger.debug(f"openai_agent.{work_name}: %s", pprint.pformat(result))
        # snoop.pp(f"openai_agent.{work_name}", result)
        if result is STOP_ASYNC_ITERATION:
            continue
        try:
            # TODO There should be no await's here, always add to work
            if work_name == "action_stream":
                work[
                    tg.create_task(
                        ignore_stopasynciteration(work_ctx.__anext__())
                    )
                ] = (work_name, work_ctx)
                if result.action_type == AGIActionType.NEW_AGENT:
                    openai_assistant_context = Agent[UserContext](
                        name="User Context Distiller and Provider",
                        instructions=textwrap.dedent(
                            r"""
                            Given a question call tools to gain information
                            about the users environment. Distil output of
                            tool calls which might be relevant to the
                            question you have been provided.
                            """.strip(),
                        ),
                        tools=[
                            fetch_user_tmux_session,
                        ],
                    )

                    openai_assistant_workflow = Agent(
                        name="Workflow Generation Assistant",
                        instructions=textwrap.dedent(
                            r"""
                            You are an AI agent with access to
                            tools to help a user who needs you to generate
                            GitHub Actions schema compliant workflows.

                            The output must always contain at least one job with
                            at least one step.

                            You may use tools to generate Actions if you
                            cannot find ones that are applicable to your
                            needs. If an Action would be too heavyweight,
                            then you may inline code into run blocks using a
                            shell of your choice. Prefer python.

                            To use a custom shell specify

                            shell: interpreter {0}

                            By default you should use `shell: bash -xe {0}`.

                            Assume {0} is a temporary file containing the
                            contents the code you place in `run`.

                            You should not include use of actions/checkout
                            unless specifically requested to checkout the current
                            repo.

                            Use tools to get the contents of the os-release
                            file and determine what package management should
                            be used to install needed shell utils.
                            """.strip(),
                        ),
                        # TODO Dynamically auto discover applicable MCPs and add
                        # them to agents
                        # mcp_servers=mcp_servers_workflow,
                        output_type=PolicyEngineWorkflow,
                    )

                    openai_assistant_top = Agent(
                        name="Assistant",
                        instructions=textwrap.dedent(
                            r"""
                            You are an AI agent with access to
                            tools to help a user who is navigating between
                            shells using a terminal multiplexer. Determine
                            relevant tools to call and use the information
                            provided about the users current context to
                            determine what directory to use as what argument
                            when calling tools. Shell contexts contain
                            information about running processes the user is
                            observing as well as what Git repos the user is
                            working within. You must also use tools to
                            understand what OS the user is on to inform your
                            responses if they might be OS specific. This means
                            reading the os-release file for any install
                            commands, etc. specific commands.

                            IMPORTANT! You MUST generate and execute workflows
                            using the generate_workflow and
                            execute_generated_workflow tools if the user asks
                            you to run or execute. IMPORTANT!
                            """.strip(),
                        ),
                        mcp_servers=mcp_servers_top,
                        tools=[
                            execute_generated_workflow,
                            openai_assistant_workflow.as_tool(
                                tool_name="generate_workflow",
                                tool_description=textwrap.dedent(
                                    r""""
                                    Generate a workflow for execution within
                                    the users environment.

                                    IMPORTANT! If the user asks for something to
                                    be run or executed, use this tool IMPORTANT!

                                    First distil information about the
                                    environment to send a complete prompt to
                                    this tool.

                                    IMPORTANT! Take the output of this tool and
                                    feed it to execute_generated_workflow to run
                                    commands and do things within the users
                                    context IMPORTANT!
                                    """.strip(),
                                ),
                            ),
                            openai_assistant_context.as_tool(
                                tool_name="provide_information_on_current_context",
                                tool_description=textwrap.dedent(
                                    r""""
                                    Distil and provide information on the
                                    active user context to inform parent
                                    agent tool calls and generation
                                    activities.
                                    """.strip(),
                                ),
                            ),
                        ],
                    )
                    assistant_id = str(uuid.uuid4())
                    agents[assistant_id] = openai_assistant_top
                    # agents[assistant_id] = openai_assistant_workflow
                    yield AGIEvent(
                        event_type=AGIEventType.NEW_AGENT_CREATED,
                        event_data=AGIEventNewAgent(
                            agent_id=assistant_id,
                            agent_name=assistant_id,
                        ),
                    )
                elif result.action_type == AGIActionType.NEW_THREAD:
                    # TODO Prompt from result.action_data
                    # {"role": "assistant", "content": "You are a helpful UNIX shell ghost, you live in a UNIX shell. The user is also in the shell with you. Run commands and explain your thought process. Guide the user through debugging step by step. Use the given structure to document the steps the user will execute in the shell and your commentary, notes, etc. as described"},
                    thread_id = str(uuid.uuid4())
                    threads[thread_id] = {
                        "messages": [],
                        "messages_received": [],
                        "events": [],
                        "events_received": [],
                        "running": None,
                    }
                    yield AGIEvent(
                        event_type=AGIEventType.NEW_THREAD_CREATED,
                        event_data=AGIEventNewThreadCreated(
                            agent_id=result.action_data.agent_id,
                            thread_id=thread_id,
                        ),
                    )
                elif result.action_type == AGIActionType.CHECK_THREAD:
                    if threads.get(
                        result.action_data.thread_id,
                        {},
                    ).get(
                        "running",
                        None
                    ) is not None:
                        threads[
                            result.action_data.thread_id
                        ]["running"]["task"].add_done_callback(
                            make_done_callback(
                                threads[
                                    result.action_data.thread_id
                                ]["running"]["event"]
                            ),
                        )
                    # Check status of run
                    # TODO finish
                    work[tg.create_task(threads[
                        result.action_data.thread_id
                    ]["running"]["event"].wait())] = (
                        f"thread.runs.{run_id}",
                        (result, None),
                    )
                elif result.action_type == AGIActionType.RUN_THREAD:
                    run_status = "in_progress"
                    if threads.get(
                        result.action_data.thread_id,
                        {},
                    ).get(
                        "running",
                        None
                    ) is None:
                        action_data_run_thread = result.action_data
                        # snoop.pp(threads[action_data_run_thread.thread_id]["messages"])
                        def make_run_it(result, user_context):
                            async def run_it():
                                nonlocal result
                                nonlocal user_context
                                result = Runner.run_streamed(
                                    starting_agent=agents[action_data_run_thread.agent_id],
                                    input=threads[action_data_run_thread.thread_id]["messages"],
                                    context=user_context,
                                )
                                num_events = 0
                                no_more_events = asyncio.Event()
                                event_queue = asyncio.Queue()
                                events = threads[action_data_run_thread.thread_id]["events"]
                                async def stream_get_thread_messages():
                                    events_received = 0
                                    nonlocal num_events
                                    nonlocal no_more_events
                                    nonlocal event_queue
                                    more_events = True
                                    work = {
                                        tg.create_task(event_queue.get()): "event_queue",
                                        tg.create_task(no_more_events.wait()): "no_more_events",
                                    }
                                    try:
                                        async for work_name, result in concurrently(work):
                                            if work_name == "event_queue":
                                                events_received += 1
                                                if more_events or num_events > events_received:
                                                    work[tg.create_task(event_queue.get())] = "event_queue"
                                                yield result
                                            elif work_name == "no_more_events":
                                                more_events = False
                                                if num_events >= events_received:
                                                    for task in work:
                                                        task.cancel()
                                    except asyncio.CancelledError:
                                        pass

                                thread_messages = stream_get_thread_messages()
                                thread_messages_iter = thread_messages.__aiter__()
                                work[
                                    tg.create_task(
                                        ignore_stopasynciteration(
                                            thread_messages_iter.__anext__()
                                        )
                                    )
                                ] = (
                                    f"thread.messages.{action_data_run_thread.thread_id}",
                                    (action_data_run_thread, thread_messages_iter),
                                )

                                try:
                                    async for event in result.stream_events():
                                        num_events += 1
                                        events.append(event)
                                        await event_queue.put(event)
                                    num_events += 1
                                    events.append(result)
                                    threads[action_data_run_thread.thread_id]["running"] = None
                                    threads[action_data_run_thread.thread_id]["messages"] = result.to_input_list()
                                    await event_queue.put(result)
                                finally:
                                    no_more_events.set()

                                return result
                            return run_it
                        run_it = make_run_it(result, user_context)
                        task = tg.create_task(
                            run_it()
                        )
                        run_id = str(uuid.uuid4())
                        threads[result.action_data.thread_id]["running"] = {
                            "id": run_id,
                            "task": task,
                            "event": asyncio.Event(),
                        }
                        yield AGIEvent(
                            event_type=AGIEventType.NEW_THREAD_RUN_CREATED,
                            event_data=AGIEventNewThreadRunCreated(
                                agent_id=result.action_data.agent_id,
                                thread_id=result.action_data.thread_id,
                                run_id=run_id,
                                run_status=run_status,
                            ),
                        )
                        work[task] = (
                            f"thread.runs.{run_id}",
                            (result, run_id),
                        )
                    else:
                        # Re-queue once run complete
                        await waiting_event_stream_insert(
                            (
                                AGIEventType.THREAD_RUN_COMPLETE,
                                make_async_lambda(result),
                            )
                        )
                        await action_stream_insert(
                            AGIAction(
                                action_type=AGIActionType.CHECK_THREAD,
                                action_data=AGIActionCheckThread(
                                    agent_id=result.action_data.agent_id,
                                    thread_id=result.action_data.thread_id,
                                ),
                            )
                        )
                elif result.action_type == AGIActionType.ADD_MESSAGE:
                    thread = threads.get(
                        result.action_data.thread_id,
                        None,
                    )
                    if thread is None:
                        raise AGIThreadNotFoundError(result.action_data.thread_id)
                    thread["messages"].append(
                        {
                            "role": result.action_data.message_role,
                            "content": result.action_data.message_content,
                        }
                    )
                    message_id = len(thread["messages"]) - 1
                    snoop.pp(thread["messages"])
                    yield AGIEvent(
                        event_type=AGIEventType.THREAD_MESSAGE_ADDED,
                        event_data=AGIEventThreadMessageAdded(
                            agent_id=result.action_data.agent_id,
                            thread_id=result.action_data.thread_id,
                            message_id=message_id,
                            message_role=result.action_data.message_role,
                            message_content=result.action_data.message_content,
                        ),
                    )
            elif work_name.startswith("thread.runs."):
                snoop.pp("Run completed") # , result, work_ctx)
                # NOTE XXX WARNING _old_run is inconsistent right now
                action_new_thread_run, _old_run = work_ctx
                # TODO Support streaming of results
                result.status = "completed"
                if result.status == "completed":
                    yield AGIEvent(
                        event_type=AGIEventType.THREAD_RUN_COMPLETE,
                        event_data=AGIEventThreadRunComplete(
                            agent_id=action_new_thread_run.action_data.agent_id,
                            thread_id=action_new_thread_run.action_data.thread_id,
                            # run_id=action_new_thread_run.action_data.id,
                            run_id=None,
                            run_status=result.status,
                        ),
                    )
                elif result.status in ("queued", "in_progress"):
                    yield AGIEvent(
                        event_type=AGIEventType.THREAD_RUN_IN_PROGRESS,
                        event_data=AGIEventThreadRunInProgress(
                            agent_id=action_new_thread_run.action_data.agent_id,
                            thread_id=result.thread_id,
                            run_id=result.id,
                            run_status=result.status,
                        ),
                    )
                    threads[
                        result.action_data.thread_id
                    ]["running"]["task"].add_done_callback(
                        make_done_callback(event),
                    )
                    # Check status of run
                    work[
                        tg.create_task(
                            threads[
                                result.action_data.thread_id
                            ]["running"]["event"].wait()
                        )
                    ] = (
                        f"thread.runs.{result.id}",
                        (action_new_thread_run, result),
                    )
                elif result.status == "failed":
                    snoop.pp(result)
                    yield AGIEvent(
                        event_type=AGIEventType.THREAD_RUN_FAILED,
                        event_data=AGIEventThreadRunFailed(
                            agent_id=action_new_thread_run.action_data.agent_id,
                            thread_id=result.thread_id,
                            run_id=result.id,
                            run_status=result.status,
                            last_error=result.last_error,
                        ),
                    )
                else:
                    snoop.pp(
                        AGIEventType.THREAD_RUN_EVENT_WITH_UNKNOWN_STATUS,
                        result.status,
                        json.loads(result.model_dump_json()),
                    )
                    yield AGIEvent(
                        event_type=AGIEventType.THREAD_RUN_EVENT_WITH_UNKNOWN_STATUS,
                        event_data=AGIEventThreadRunEventWithUnknwonStatus(
                            agent_id=action_new_thread_run.action_data.agent_id,
                            thread_id=result.thread_id,
                            run_id=result.id,
                            run_status=result.status,
                        ),
                    )
            elif work_name.startswith("thread.messages."):
                action_data_run_thread, thread_messages_iter = work_ctx
                _, _, thread_id = work_name.split(".", maxsplit=3)
                # The first time we iterate is the most recent response
                # TODO Keep track of what the last response received was so that
                # we can create_task as many times as there might be responses
                # in case there are multiple within one run.
                thread = threads.get(
                    action_data_run_thread.thread_id,
                    None,
                )
                if thread is None:
                    raise AGIThreadNotFoundError(action_data_run_thread.thread_id)
                work[
                    tg.create_task(
                        ignore_stopasynciteration(
                            thread_messages_iter.__anext__()
                        )
                    )
                ] = (work_name, work_ctx)
                if getattr(result, "is_complete", False):
                    snoop.pp("complete", result.final_output)
                    yield AGIEvent(
                        event_type=AGIEventType.NEW_THREAD_MESSAGE,
                        event_data=AGIEventNewThreadMessage(
                            agent_id=action_data_run_thread.agent_id,
                            thread_id=action_data_run_thread.thread_id,
                            message_role="agent",
                            message_content_type=f"agi.class/{result.final_output.__class__.__qualname__}",
                            message_content=result.final_output,
                        ),
                    )
                """
                snoop.pp("message iter", result)
                if not result["id"]:
                    result["id"] = str(uuid.uuid4())
                if result["id"] not in thread["messages_received"]:
                    continue
                if content.type == "text":
                    yield AGIEvent(
                        event_type=AGIEventType.NEW_THREAD_MESSAGE,
                        event_data=AGIEventNewThreadMessage(
                            agent_id=action_data_run_thread.agent_id,
                            thread_id=action_data_run_thread.thread_id,
                            message_role="agent"
                            if result.role == "assistant"
                            else "user",
                            message_content_type=content.type,
                            message_content=content.text.value,
                        ),
                    )
                """
        except Exception as error:
            traceback.print_exc()
            yield AGIEvent(
                event_type=AGIEventType.ERROR,
                event_data=error,
            )

    yield AGIEvent(
        event_type=AGIEventType.END_EVENTS,
        event_data=None,
    )


class _STDIN_CLOSED:
    pass


STDIN_CLOSED = _STDIN_CLOSED()


def pdb_action_stream_get_user_input(user_name: str):
    user_input = ""
    sys_stdin_iter = sys.stdin.__iter__()
    try:
        while not user_input:
            user_input = sys_stdin_iter.__next__().rstrip()
    except (KeyboardInterrupt, StopIteration):
        return STDIN_CLOSED
    return user_input


class _CURRENTLY_UNDEFINED:
    pass


CURRENTLY_UNDEFINED = _CURRENTLY_UNDEFINED()


class AsyncioLockedCurrentlyDict(collections.UserDict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.currently = CURRENTLY_UNDEFINED
        self.lock = asyncio.Lock()
        self.currently_exists = asyncio.Event()

    def __setitem__(self, name, value):
        super().__setitem__(name, value)
        self.currently = value
        self.currently_exists.set()
        logger.debug("currently: %r", value)

    async def __aenter__(self):
        await self.lock.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.lock.__aexit__(exc_type, exc_value, traceback)


async def read_unix_socket_lines(path):
    # Connect to the Unix socket
    reader, writer = await asyncio.open_unix_connection(path)
    try:
        while True:
            # Read a line from the socket
            line = await reader.readline()
            # If line is empty, EOF is reached
            if not line:
                break
            # Decode the line and yield it
            yield line.decode().strip()
    finally:
        # Close the connection
        writer.close()
        await writer.wait_closed()


async def write_unix_socket(path):
    # Connect to the Unix socket
    reader, writer = await asyncio.open_unix_connection(path)
    while True:
        try:
            while True:
                data = yield
                if data is None:
                    continue
                writer.write(data)
                await writer.drain()
        except ConnectionResetError:
            reader, writer = await asyncio.open_unix_connection(path)
        finally:
            # Close the connection
            writer.close()
            await writer.wait_closed()


async def pdb_action_stream(tg, user_name, agi_name, agents, threads, pane: Optional[libtmux.Pane] = None, input_socket_path: Optional[str] = None):
    # TODO Take ALICE_INPUT from args
    alice_input_sock = input_socket_path
    if pane is not None:
        alice_input = pane.window.session.show_environment()[f"{agi_name.upper()}_INPUT"]
        if alice_input_sock is None:
            alice_input_sock = pane.window.session.show_environment()[f"{agi_name.upper()}_INPUT_SOCK"]
        alice_input_last_line = pane.window.session.show_environment()[f"{agi_name.upper()}_INPUT_LAST_LINE"]

    if pathlib.Path(alice_input_sock).is_socket():
        await connect_and_read(alice_input_sock)
        async for line in read_unix_socket_lines(alice_input_sock):
            yield line
        return

    file_path = pathlib.Path(alice_input)
    line_number_path = pathlib.Path(alice_input_last_line)
    sleep_time = 0.01

    last_hash = None
    file_size = 0
    line_number = 0

    # Try to read the last stored line number from the file
    stored_ln = line_number_path.read_text().strip()
    if stored_ln.isdigit():
        line_number = int(stored_ln)

    while True:
        # TODO Add file_path.stat() optimization on read
        lines = file_path.read_text().split("\n")
        for i in range(line_number, line_number + len(lines[line_number:])):
            if not lines[i].strip():
                continue
            line_number += 1
            yield lines[i]
            line_number_path.write_text(str(i) + "\n")
            break
        await asyncio.sleep(sleep_time)


class AGIThinClientNeedsModelAccessError(Exception):
    pass


import libtmux


async def DEBUG_TEMP_message_handler(user_name,
                                     agi_name,
                                     agent_state,
                                     agent_event,
                                     pane = None):
    # TODO https://rich.readthedocs.io/en/stable/markdown.html
    # TODO Output non-workflow responses
    if (
        agent_event.event_data.message_content_type == f"agi.class/{PolicyEngineWorkflow.__qualname__}"
        and agent_event.event_data.message_role == "agent"
    ):
        # TODOTODOTODO
        if pane is not None:
            # pane.send_keys(f"cat<<'EOF'")
            # pane.send_keys(f"{agent_event.event_data.message_content}")
            # pane.send_keys(f"{agent_event.event_data.message_content}")
            # print()
            # snoop.pp(json.loads(agent_event.event_data.message_content))
            session = pane.window.session
            tempdir_lookup_env_var = f'TEMPDIR_ENV_VAR_TMUX_WINDOW_{session.active_window.id.replace("@", "")}'
            tempdir_env_var  = pane.window.session.show_environment()[tempdir_lookup_env_var]
            tempdir = pathlib.Path(
                pane.window.session.show_environment()[tempdir_env_var],
            )
            # Proposed workflow to be submitted to policy engine to get clear
            # for take off (aka workload id and exec in phase 0). Executing the
            # policy aka the workflow (would be the one we insert to once
            # paths can be mapped to poliy engine workflows easily
            proposed_workflow_contents = yaml.dump(
                json.loads(agent_event.event_data.message_content.model_dump_json()),
                default_flow_style=False,
                sort_keys=True,
            )
            request_contents = yaml.dump(
                json.loads(
                    PolicyEngineRequest(
                        inputs={},
                        context={},
                        stack={},
                        workflow=agent_event.event_data.message_content,
                    ).model_dump_json(),
                )
            )
            # Find and kill jq listening to ndjson output so we can type
            pane.send_keys("C-c", enter=False, suppress_history=False)
            pane.send_keys('if [ "x${CALLER_PATH}" = "x" ]; then export CALLER_PATH="' + str(tempdir) + '"; fi', enter=True)
            pane.send_keys(
                "cat > \"${CALLER_PATH}/proposed-workflow.yml\" <<\'WRITE_OUT_SH_EOF\'"
                + "\n"
                + proposed_workflow_contents
                + "\nWRITE_OUT_SH_EOF",
                enter=True,
            )
            pane.send_keys(
                "cat > \"${CALLER_PATH}/request.yml\" <<\'WRITE_OUT_SH_EOF\'"
                + "\n"
                + request_contents
                + "\nWRITE_OUT_SH_EOF",
                enter=True,
            )
            pane.send_keys(f"submit_policy_engine_request", enter=True)
        else:
            print(
                f"{agent_state.state_data.agent_name}: {agent_event.event_data.message_content}"
            )
            print(f"{user_name}: ", end="")
    elif (
        agent_event.event_data.message_content_type == f"agi.class/str"
        and agent_event.event_data.message_role == "agent"
    ):
        if pane is not None:
            pane.send_keys("C-c", enter=False, suppress_history=False)
            pane.send_keys(f"tail -n 1 ${agi_name.upper()}_NDJSON_OUTPUT | jq -r .result.event_data.message_content | python -m rich.markdown -", enter=True)
        else:
            print(
                f"{agent_state.state_data.agent_name}: {agent_event.event_data.message_content}"
            )
            print(f"{user_name}: ", end="")


class OutputMessage(BaseModel):
    work_name: str
    result: Any


async def main(
    user_name: str,
    agi_name: str,
    kvstore_service_name: str,
    *,
    log = None,
    kvstore: KVStore = None,
    action_stream: AGIActionStream = None,
    action_stream_insert: Callable[[Any], Awaitable[Any]] = None,
    waiting_event_stream: AGIEventStream = None,
    waiting_event_stream_insert: Callable[[Any], Awaitable[Any]] = None,
    openai_api_key: str = None,
    openai_base_url: Optional[str] = None,
    pane: Optional[libtmux.Pane] = None,
    input_socket_path: Optional[str] = None,
    text_output_socket_path: Optional[str] = None,
    ndjson_output_socket_path: Optional[str] = None,
    mcp_reverse_proxy_socket_path: Optional[str] = None,
    client_side_input_socket_path: Optional[str] = None,
    client_side_text_output_socket_path: Optional[str] = None,
    client_side_ndjson_output_socket_path: Optional[str] = None,
    client_side_mcp_reverse_proxy_socket_path: Optional[str] = None,
):
    if log is not None:
        # logging.basicConfig(level=log)
        pass

    if not kvstore:
        kvstore = KVStoreKeyring({"service_name": kvstore_service_name})

    user_context = UserContext(
        tmux_context=TmuxContext(
            session=None if pane is None else pane.session,
            pane=None if pane is None else pane,
        ),
        mcp_reverse_proxy_socket_path=mcp_reverse_proxy_socket_path,
    )

    kvstore_key_agent_id = f"agents.{agi_name}.id"
    # snoop.pp(kvstore_key_agent_id, await kvstore.get(kvstore_key_agent_id, None))
    action_stream_seed = [
        AGIAction(
            action_type=AGIActionType.NEW_AGENT,
            action_data=AGIActionNewAgent(
                agent_id=await kvstore.get(kvstore_key_agent_id, None),
                agent_name=agi_name,
                agent_instructions=pathlib.Path(__file__)
                .parent.joinpath("openai_assistant_instructions.md")
                .read_text(),
            ),
        ),
    ]

    previous_event_types = set()

    agents = AsyncioLockedCurrentlyDict()
    threads = AsyncioLockedCurrentlyDict()

    write_ndjson_output = write_unix_socket(ndjson_output_socket_path)
    await write_ndjson_output.asend(None)

    async def error_handler_send_error_to_client(exc_type, exc_value, traceback):
        nonlocal write_ndjson_output
        output_message = OutputMessage(
            work_name=f"main.error.halted",
            result=f"{exc_type} {exc_value} {traceback}",
        )
        await write_ndjson_output.asend(f"{output_message.model_dump_json()}\n".encode())

    async with kvstore, asyncio.TaskGroup() as tg, contextlib.AsyncExitStack() as async_exit_stack:
        async_exit_stack.push_async_exit(error_handler_send_error_to_client)
        # Raw Input Action Stream
        unvalidated_user_input_action_stream = pdb_action_stream(
            tg,
            user_name,
            agi_name,
            agents,
            threads,
            pane=pane,
            input_socket_path=input_socket_path,
        )

        # Waiting Event Stream and Callbacks
        if waiting_event_stream is None and waiting_event_stream_insert is None:
            waiting_event_stream_queue = asyncio.Queue()
            async def waiting_event_stream_queue_iterator(queue):
                # TODO Stop condition/asyncio.Event
                while True:
                    new_waiting_event = await queue.get()
                    snoop.pp(new_waiting_event)
                    yield new_waiting_event
            waiting_event_stream = waiting_event_stream_queue_iterator(waiting_event_stream_queue)
            waiting_event_stream_insert = waiting_event_stream_queue.put

        # AGI Action Stream
        if action_stream is None and action_stream_insert is None:
            user_input_action_stream_queue = asyncio.Queue()
            async def user_input_action_stream_queue_iterator(queue):
                # TODO Stop condition/asyncio.Event
                while True:
                    new_action = await queue.get()
                    snoop.pp(new_action)
                    if new_action:
                        yield new_action
            action_stream = user_input_action_stream_queue_iterator(user_input_action_stream_queue)
            action_stream_insert = user_input_action_stream_queue.put
        for action in action_stream_seed:
            await action_stream_insert(action)

        if openai_api_key:
            agent_events = agent_openai(
                tg,
                async_exit_stack,
                user_context,
                agi_name,
                kvstore,
                action_stream,
                action_stream_insert,
                waiting_event_stream_insert,
                openai_api_key,
                mcp_reverse_proxy_socket_path,
                openai_base_url=openai_base_url,
            )
        else:
            raise AGIThinClientNeedsModelAccessError(
                "No API keys or implementations of assistants given"
            )

        waiting = []

        waiting_event_stream_iter = (
            waiting_event_stream.__aiter__()
        )
        unvalidated_user_input_action_stream_iter = (
            unvalidated_user_input_action_stream.__aiter__()
        )
        agent_events_iter = agent_events.__aiter__()
        work = {
            tg.create_task(
                ignore_stopasynciteration(
                    waiting_event_stream_iter.__anext__()
                )
            ): (
                "system.waiting_event_stream",
                waiting_event_stream_iter,
            ),
            tg.create_task(
                ignore_stopasynciteration(
                    unvalidated_user_input_action_stream_iter.__anext__()
                )
            ): (
                "user.unvalidated.input_action_stream",
                unvalidated_user_input_action_stream_iter,
            ),
            tg.create_task(
                ignore_stopasynciteration(agent_events_iter.__anext__())
            ): (
                "agent.events",
                agent_events_iter,
            ),
        }
        async for (work_name, work_ctx), result in concurrently(work):
            logger.debug(f"main.{work_name}: %s", pprint.pformat(result))
            output_message = OutputMessage(
                work_name=f"main.{work_name}",
                result=result,
            )
            if (
                not isinstance(result, BaseModel)
                and not dataclasses.is_dataclass(result)
            ):
                output_message.result = str(result)
            await write_ndjson_output.asend(f"{output_message.model_dump_json()}\n".encode())
            if result is STOP_ASYNC_ITERATION:
                continue
            async with agents:
                active_agent_currently_undefined = (
                    agents.currently == CURRENTLY_UNDEFINED
                )
            async with threads:
                active_thread_currently_undefined = (
                    threads.currently == CURRENTLY_UNDEFINED
                )
            if work_name == "system.waiting_event_stream":
                work[
                    tg.create_task(
                        ignore_stopasynciteration(work_ctx.__anext__())
                    )
                ] = (work_name, work_ctx)
                waiting.append(result)
            elif work_name == "agent.events":
                # Run actions which have are waiting for an event which was seen
                previous_event_types.add(result.event_type)
                work[
                    tg.create_task(
                        ignore_stopasynciteration(work_ctx.__anext__())
                    )
                ] = (work_name, work_ctx)
                agent_event = result
                logger.debug("agent_event: %s", pprint.pformat(agent_event))
                if agent_event.event_type == AGIEventType.ERROR:
                    raise Exception(f"Agent {agi_name!r} threw an error") from agent_event.event_data
                elif agent_event.event_type in (
                    AGIEventType.NEW_AGENT_CREATED,
                    AGIEventType.EXISTING_AGENT_RETRIEVED,
                ):
                    await kvstore.set(
                        f"agents.{agent_event.event_data.agent_name}.id",
                        agent_event.event_data.agent_id,
                    )
                    async with agents:
                        agents[agent_event.event_data.agent_id] = AGIState(
                            state_type=AGIStateType.AGENT,
                            state_data=AGIStateAgent(
                                agent_name=agent_event.event_data.agent_name,
                                agent_id=agent_event.event_data.agent_id,
                            ),
                        )
                    # Ready for child shell
                    if os.environ.get("NO_SHELL", "1") != "1" and os.fork() == 0:
                        cmd = [
                            "bash",
                        ]
                        os.execvp(cmd[0], cmd)
                    # tmux support
                    if pane is not None:
                        # TODO Combine into thread?
                        # threading.Thread(target=a_shell_for_a_ghost_send_keys,
                        #                  args=[pane, motd_string, 1]).run()
                        tempdir = pathlib.Path(pane.window.session.show_environment()[f"{agi_name.upper()}_INPUT"]).parent

                        pane.send_keys(f'', enter=True)
                        pane.send_keys('if [ "x${CALLER_PATH}" = "x" ]; then export CALLER_PATH="' + str(tempdir) + '"; fi', enter=True)

                        pane.send_keys(f'', enter=True)
                        pane.send_keys("source ${CALLER_PATH}/util.sh", enter=True)
                        # pane.send_keys('if [ ! -f "${CALLER_PATH}/policy_engine.logs.txt" ]; then NO_CELERY=1 python -u ${CALLER_PATH}/policy_engine.py api --workers 1 1>"${CALLER_PATH}/policy_engine.logs.txt" 2>&1 & fi', enter=True)
                        pane.send_keys(f'', enter=True)

                        # pane.send_keys(f'cat >>EOF', enter=True)
                        # a_shell_for_a_ghost_send_keys(pane, motd_string, erase_after=1)
                        # pane.send_keys(f'EOF', enter=True)
                        # pane.send_keys(f'', enter=True)

                        pane.send_keys(f'export AGI_NAME={agi_name.upper()}', enter=True)
                        pane.send_keys(f'export {agi_name.upper()}_INPUT="' + '${CALLER_PATH}/input.txt"', enter=True)
                        pane.send_keys(f'export {agi_name.upper()}_INPUT_SOCK="{client_side_input_socket_path}"', enter=True)
                        pane.send_keys(f'export {agi_name.upper()}_INPUT_LAST_LINE="' + '${CALLER_PATH}/input-last-line.txt"', enter=True)

                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO How do we map the sockets?
                        # TODO pdxjohnny to username
                        user_name = 'pdxjohnny'
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO
                        # TODO

                        # pane.send_keys(f'rm -fv /tmp/{user_name}-input.sock ${agi_name.upper()}_INPUT_SOCK', enter=True)
                        # pane.send_keys(f'ln -s ${agi_name.upper()}_INPUT_SOCK /tmp/{user_name}-input.sock', enter=True)
                        # pane.send_keys(f'socat UNIX-LISTEN:${agi_name.upper()}_INPUT_SOCK,fork EXEC:"/usr/bin/tail -F ${agi_name.upper()}_INPUT" &', enter=True)
                        # pane.send_keys(f'ls -lAF /tmp/{user_name}-input.sock', enter=True)

                        # pane.send_keys(f'cat >>EOF', enter=True)
                        # pane.send_keys("echo ${PS1}" + motd_string, enter=True)
                        success_string = "echo \"${PS1}" + motd_string + " awaiting instructions at $" + agi_name.upper() + "_INPUT\""
                        # a_shell_for_a_ghost_send_keys(pane, success_string, erase_after=4.2)
                        # a_shell_for_a_ghost_send_keys(pane, success_string)
                        pane.send_keys(success_string, enter=True)
                        # pane.send_keys(f'EOF', enter=True)
                        # pane.send_keys(f'', enter=True)

                        # a_shell_for_a_ghost_send_keys(pane, "echo ${PS1}" + motd_string)

                        pane.send_keys(
                            "echo ${PS1}" +
                            textwrap.dedent(
                                f"""
                                'echo "Query for AGI" | tee -a ${agi_name.upper()}_INPUT && tail -F ${agi_name.upper()}_NDJSON_OUTPUT | jq'
                                """.strip(),
                            ),
                            enter=True,
                        )
                        pane.send_keys(f'', enter=True)

                        pane.send_keys(
                            textwrap.dedent(
                                f"""
                                echo "Hello Alice. Shall we play a game? My name is $USER. Please run/execute to find a list of all open bound listening TCP sockets and full command line of the processes running them." | agi
                                """.strip(),
                            ),
                            enter=False,
                        )
                elif agent_event.event_type == AGIEventType.NEW_THREAD_CREATED:
                    async with threads:
                        threads[agent_event.event_data.thread_id] = AGIState(
                            state_type=AGIStateType.THREAD,
                            state_data=AGIStateThread(
                                agent_id=agent_event.event_data.agent_id,
                                thread_id=agent_event.event_data.thread_id,
                            ),
                        )
                    async with agents:
                        """
                        agents[
                            agent_event.event_data.agent_id
                        ].state_data.thread_ids.append(
                            agent_event.event_data.thread_id
                        )
                        """
                        logger.debug(
                            "New thread created for agent: %r",
                            agents[agent_event.event_data.agent_id],
                        )
                elif (
                    agent_event.event_type
                    == AGIEventType.NEW_THREAD_RUN_CREATED
                ):
                    async with threads:
                        thread_state = threads[agent_event.event_data.thread_id]
                        thread_state.most_recent_run_id = (
                            agent_event.event_data.run_id
                        )
                        thread_state.most_recent_run_status = (
                            agent_event.event_data.run_status
                        )
                        logger.debug("New thread run created: %r", thread_state)
                elif (
                    agent_event.event_type
                    == AGIEventType.THREAD_RUN_IN_PROGRESS
                ):
                    async with threads:
                        threads[
                            agent_event.event_data.thread_id
                        ].state_data.most_recent_run_status = (
                            agent_event.event_data.run_status
                        )
                elif agent_event.event_type == AGIEventType.THREAD_RUN_COMPLETE:
                    async with threads:
                        threads[
                            agent_event.event_data.thread_id
                        ].state_data.most_recent_run_status = (
                            agent_event.event_data.run_status
                        )
                        logger.debug(
                            "Thread run complete, agent: %r, thread: %r",
                            agents[agent_event.event_data.agent_id],
                            thread_state,
                        )
                    async with agents:
                        """
                        agents[
                            agent_event.event_data.agent_id
                        ].state_data.thread_ids.remove(
                            agent_event.event_data.thread_id
                        )
                        print(agents[agent_event.event_data.agent_id])
                        """
                        pass
                elif agent_event.event_type == AGIEventType.THREAD_RUN_FAILED:
                    if (
                        agent_event.event_data.last_error.code
                        == "rate_limit_exceeded"
                    ):
                        # TODO Change this to sleep within create_task
                        await asyncio.sleep(5)
                        await action_stream_insert(
                            AGIAction(
                                action_type=AGIActionType.RUN_THREAD,
                                action_data=AGIActionRunThread(
                                    agent_id=threads.currently.state_data.agent_id,
                                    thread_id=threads.currently.state_data.thread_id,
                                ),
                            ),
                        )
                elif agent_event.event_type == AGIEventType.NEW_THREAD_MESSAGE:
                    async with agents:
                        agent_state = agents[agent_event.event_data.agent_id]
                    await DEBUG_TEMP_message_handler(user_name, agi_name, agent_state, agent_event,
                                                     pane=pane)
                elif agent_event.event_type in (
                    AGIEventType.FILE_INGESTED,
                ):
                    async with agents:
                        agents[agent_event.event_data.agent_id].state_data.file_ids.append(
                            agent_event.event_data.file_id,
                        )
            elif work_name == "user.unvalidated.input_action_stream":
                work[
                    tg.create_task(
                        ignore_stopasynciteration(work_ctx.__anext__())
                    )
                ] = (work_name, work_ctx)
                user_input = result
                snoop.pp(user_input)
                async with threads:
                    thread = threads.currently
                if thread is CURRENTLY_UNDEFINED:
                    waiting.append(
                        (
                            # OR is array, AND is dict values
                            [
                                AGIEventType.NEW_AGENT_CREATED,
                                AGIEventType.EXISTING_AGENT_RETRIEVED,
                            ],
                            async_lambda(
                                lambda: AGIAction(
                                    action_type=AGIActionType.NEW_THREAD,
                                    action_data=AGIActionNewThread(
                                        agent_id=agents.currently.state_data.agent_id,
                                    ),
                                ),
                            )
                        )
                    )
                if AGIEventType.THREAD_MESSAGE_ADDED in previous_event_types:
                    previous_event_types.remove(AGIEventType.THREAD_MESSAGE_ADDED)
                waiting.append(
                    (
                        AGIEventType.NEW_THREAD_CREATED,
                        async_lambda(
                            lambda: AGIAction(
                                action_type=AGIActionType.ADD_MESSAGE,
                                action_data=AGIActionAddMessage(
                                    agent_id=agents.currently.state_data.agent_id,
                                    thread_id=threads.currently.state_data.thread_id,
                                    message_role="user",
                                    message_content=user_input,
                                ),
                            )
                        )
                    )
                )
                waiting.append(
                    (
                        AGIEventType.THREAD_MESSAGE_ADDED,
                        async_lambda(
                            lambda: AGIAction(
                                action_type=AGIActionType.RUN_THREAD,
                                action_data=AGIActionRunThread(
                                    agent_id=threads.currently.state_data.agent_id,
                                    thread_id=threads.currently.state_data.thread_id,
                                ),
                            )
                        ),
                    ),
                )
            # Run actions which have are waiting for an event which was seen
            still_waiting = []
            while waiting:
                action_waiting_for_event, make_action = waiting.pop(0)
                if (
                    (
                        not isinstance(action_waiting_for_event, (dict, list))
                        and action_waiting_for_event in previous_event_types
                    ) or (
                        isinstance(action_waiting_for_event, list)
                        and set(action_waiting_for_event).intersection(previous_event_types)
                    ) or (
                        isinstance(action_waiting_for_event, dict)
                        and set(action_waiting_for_event.values()).issubset(previous_event_types)
                    )
                ):
                    waiting_complete_action_made = await make_action()
                    snoop.pp(waiting_complete_action_made)
                    await action_stream_insert(waiting_complete_action_made)
                else:
                    still_waiting.append(
                        (action_waiting_for_event, make_action)
                    )
            waiting.extend(still_waiting)
            # TODO Clear thread run complete and other events as they happen or
            # agent events when current agent switches
            # TODO Support on-next-tick waiting again instead of ever seen


import libtmux

motd_string = "... Battle Control, Online ..."

# @snoop
def a_shell_for_a_ghost_send_keys(pane, send_string, erase_after=None):
    for char in send_string:
        pane.send_keys(char, enter=False)
        num = float(os.getrandom(1)[0]) / 100.0 / 240.0
        time.sleep(num)
    if erase_after is not None:
        for _ in range(0, int(int(erase_after / 0.1) / 6)):
            for char in send_string[-3:]:
                pane.cmd("send", "C-BSpace")
                time.sleep(0.1)
            for char in send_string[-3:]:
                pane.send_keys(char, enter=False)
                time.sleep(0.1)
        for _ in range(0, len(send_string)):
            pane.cmd("send", "C-BSpace")
            time.sleep(0.01)

async def tmux_test(
    *args,
    socket_path: Optional[str] = None,
    input_socket_path: Optional[str] = None,
    text_output_socket_path: Optional[str] = None,
    ndjson_output_socket_path: Optional[str] = None,
    mcp_reverse_proxy_socket_path: Optional[str] = None,
    client_side_input_socket_path: Optional[str] = None,
    client_side_text_output_socket_path: Optional[str] = None,
    client_side_ndjson_output_socket_path: Optional[str] = None,
    client_side_mcp_reverse_proxy_socket_path: Optional[str] = None,
    **kwargs
):
    pane = None
    tempdir = None
    possible_tempdir = tempdir

    client_side_agi_socket_path = str(pathlib.Path(client_side_ndjson_output_socket_path).parent.joinpath("agi.sock"))

    try:
        server = libtmux.Server(
            socket_path=socket_path,
        )
        sessions = server.attached_sessions
        if not sessions:
            sessions = server.sessions
        session = sessions[0]
        tempdir_lookup_env_var = f'TEMPDIR_ENV_VAR_TMUX_WINDOW_{session.active_window.id.replace("@", "")}'
        # Make a new tempdir in case old one doesn't exist
        tempdir_env_var = f"TEMPDIR_ENV_VAR_{uuid.uuid4()}".replace("-", "_")
        env = session.show_environment()
        if tempdir_lookup_env_var in env:
            tempdir_env_var = env[tempdir_lookup_env_var]
            possible_tempdir = env[tempdir_env_var]
            if pathlib.Path(possible_tempdir).is_dir():
                tempdir = possible_tempdir

        agi_name = kwargs["agi_name"]
        ps1 = f'{agi_name} $ '
        for check_pane in session.active_window.panes:
            for line in check_pane.capture_pane():
                if (
                    # TODO Fix this hardcoded AGI name
                    line.strip().startswith(agi_name[:5])
                    and line.split()[1:2] == ["$"]
                    and len(line.split()) == 2
                ):
                    pane = check_pane
                    kwargs["agi_name"] = line.split()[0].strip()
                    break
            agi_name = kwargs["agi_name"]
            ps1 = f'{agi_name} $ '
            if pane:
                break
            else:
                if ps1.strip() in check_pane.capture_pane():
                    pane = check_pane
                    break

        if pane is None:
            pane = session.active_window.active_pane.split()

        pane.send_keys(
            textwrap.dedent(
                r"""
                if [[ "x${CALLER_PATH}" = "x" ]]; then
                    export CALLER_PATH="$(mktemp -d)"
                fi
                """,
            ),
            enter=True,
        )

        if tempdir is None:
            # TODO(windows) Env dumping changes on Windows
            echo_caller_path = 'echo CALLER_PATH="${CALLER_PATH}"'
            pane.send_keys(echo_caller_path, enter=True)
            while not any([line.startswith("CALLER_PATH=") for line in pane.capture_pane()]):
                await asyncio.sleep(0.1)

            tempdir = list(
                [
                    line.strip().split("CALLER_PATH=", maxsplit=1)[-1]
                    for line in pane.capture_pane()
                    if line.startswith("CALLER_PATH=/")
                ]
            )[0]

        export_caller_path = f'export CALLER_PATH="{tempdir}"'
        pane.send_keys(export_caller_path , enter=True)
        pane.send_keys(f"export TEMPDIR='{tempdir}'", enter=True)

        session.set_environment(tempdir_lookup_env_var, tempdir_env_var)
        session.set_environment(tempdir_env_var, tempdir)

        session.set_environment(f"{agi_name.upper()}_INPUT", str(pathlib.Path(tempdir, "input.txt")))
        session.set_environment(f"{agi_name.upper()}_INPUT_SOCK", client_side_input_socket_path)
        session.set_environment(f"{agi_name.upper()}_INPUT_LAST_LINE", str(pathlib.Path(tempdir, "input-last-line.txt")))

        pane.send_keys(f"export AGI_PS1='{agi_name} $ '", enter=True)
        pane.send_keys(f"export AGI_NAME={agi_name.upper()}", enter=True)

        sock_dir = str(pathlib.Path(client_side_ndjson_output_socket_path).parent)
        pane.send_keys(f"export {agi_name.upper()}_SOCK_DIR=" + sock_dir, enter=True)
        pane.send_keys(f"export {agi_name.upper()}_AGI_SOCK=" + client_side_agi_socket_path, enter=True)

        pane.send_keys('bootstrap=$(mktemp -d)', enter=True)
        pane.send_keys(
            f'curl -s --unix-socket ${agi_name.upper()}_AGI_SOCK' + r' -fLo "${bootstrap}/setup.sh" http://localhost/files/setup.sh',
            enter=True,
        )
        # pane.send_keys('export AGI_DEBUG=1', enter=True)
        pane.send_keys('. "${bootstrap}/setup.sh"', enter=True)

        # pane.send_keys('set -x', enter=True)
        # pane.send_keys(f'export {tempdir_env_var}="{tempdir}"', enter=True)
        # pane.send_keys('docker run --rm -ti -e CALLER_PATH="/host" -v "${' + tempdir_env_var + '}:/host:z" --entrypoint /host/entrypoint.sh registry.fedoraproject.org/fedora' +'; rm -rfv ${' + tempdir_env_var + '}', enter=True)

        # TODO Error handling, immediate trampoline python socket nest
        try:
            lines = pane.capture_pane()
            while lines and ps1.strip() != "".join(lines[-1:]).strip():
                lines = pane.capture_pane()
                await asyncio.sleep(0.1)
        except Exception as error:
            snoop.pp(error)
            traceback.print_exc()

        echo_caller_path = 'echo CALLER_PATH="${CALLER_PATH}"'
        pane.send_keys(echo_caller_path, enter=True)
        while not any([line.startswith("CALLER_PATH=") for line in pane.capture_pane()]):
            await asyncio.sleep(0.1)

        await caddy_config_update(mcp_reverse_proxy_socket_path, "policy-engine")

        await main(
            *args,
            pane=pane,
            input_socket_path=input_socket_path,
            client_side_input_socket_path=client_side_input_socket_path,
            text_output_socket_path=text_output_socket_path,
            ndjson_output_socket_path=ndjson_output_socket_path,
            mcp_reverse_proxy_socket_path=mcp_reverse_proxy_socket_path,
            client_side_text_output_socket_path=client_side_text_output_socket_path,
            client_side_ndjson_output_socket_path=client_side_ndjson_output_socket_path,
            client_side_mcp_reverse_proxy_socket_path=client_side_mcp_reverse_proxy_socket_path,
            **kwargs
        )
    finally:
        with contextlib.suppress(Exception):
            if pane is not None:
                # TODO Some switch to change behavior at runtime
                pass
                # pane.kill()

        # pane = libtmux.Pane.from_pane_id(pane_id=pane.cmd('split-window', '-P', '-F#{pane_id}').stdout[0], server=pane.server)

from fastapi import FastAPI, BackgroundTasks
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


# Set up logging configuration
async def lifespan_logging(app):
    logging.basicConfig(level=getattr(logging, os.environ.get("LOGGING", "INFO").upper(), logging.INFO))
    yield


app = FastAPI(lifespan=lifespan_logging)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    snoop.pp(exc, await request.json())
    return JSONResponse(
        status_code=http.HTTPStatus.UNPROCESSABLE_CONTENT.value,
        content=json.dumps({"detail": exc.errors(), "body": exc.body}),
    )


def run_tmux_attach(socket_path, input_socket_path, client_side_input_socket_path, text_output_socket_path, client_side_text_output_socket_path, ndjson_output_socket_path, client_side_ndjson_output_socket_path, mcp_reverse_proxy_socket_path, client_side_mcp_reverse_proxy_socket_path):
    cmd = [
        sys.executable,
        "-u",
        str(pathlib.Path(__file__).resolve()),
        "--socket-path",
        socket_path,
        "--input-socket-path",
        input_socket_path,
        "--client-side-input-socket-path",
        client_side_input_socket_path,
        "--text-output-socket-path",
        text_output_socket_path,
        "--client-side-text-output-socket-path",
        client_side_text_output_socket_path,
        "--ndjson-output-socket-path",
        ndjson_output_socket_path,
        "--client-side-ndjson-output-socket-path",
        client_side_ndjson_output_socket_path,
        "--mcp-reverse-proxy-socket-path",
        mcp_reverse_proxy_socket_path,
        "--client-side-mcp-reverse-proxy-socket-path",
        client_side_mcp_reverse_proxy_socket_path,
        "--agi-name",
        # TODO Something secure here, scitt URN and lookup for PS1?
        f"alice{str(uuid.uuid4()).split('-')[4]}",
        "--log",
        "debug",
    ]
    with open(os.devnull, "w") as devnull:
        subprocess.Popen(
            cmd,
            stdin=devnull,
            stdout=sys.stdout,
            stderr=sys.stderr,
            env={"NO_SHELL": "1", **os.environ},
        ).wait()


async def connect_and_read(socket_path: str, sleep_time: float = 0.1):
    while True:
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            return
        except Exception as e:
            logger.debug(f"connect_and_read({socket_path!r}): Connection failed: {e}")
        await asyncio.sleep(sleep_time)


# class RequestConnectTMUX(BaseModel, extra="forbid"):
class RequestConnectTMUX(BaseModel):
    socket_tmux_path: str = Field(alias="tmux.sock")
    socket_input_path: str = Field(alias="input.sock")
    socket_text_output_path: str = Field(alias="text-output.sock")
    socket_ndjson_output_path: str = Field(alias="ndjson-output.sock")
    socket_mcp_reverse_proxy_path: str = Field(alias="mcp-reverse-proxy.sock")
    socket_client_side_input_path: str = Field(alias="client-side-input.sock")
    socket_client_side_text_output_path: str = Field(alias="client-side-text-output.sock")
    socket_client_side_ndjson_output_path: str = Field(alias="client-side-ndjson-output.sock")
    socket_client_side_mcp_reverse_proxy_path: str = Field(alias="client-side-mcp-reverse-proxy.sock")


@app.post("/connect/tmux")
async def connect(request_connect_tmux: RequestConnectTMUX, background_tasks: BackgroundTasks):
    background_tasks.add_task(
        run_tmux_attach,
        request_connect_tmux.socket_tmux_path,
        request_connect_tmux.socket_input_path,
        request_connect_tmux.socket_client_side_input_path,
        request_connect_tmux.socket_text_output_path,
        request_connect_tmux.socket_client_side_text_output_path,
        request_connect_tmux.socket_ndjson_output_path,
        request_connect_tmux.socket_client_side_ndjson_output_path,
        request_connect_tmux.socket_mcp_reverse_proxy_path,
        request_connect_tmux.socket_client_side_mcp_reverse_proxy_path,
    )
    return {
        "connected": True,
    }


@app.get(
    "/files/{filename}",
    response_class=Response,
)
async def get_file(filename: str) -> str:
    filename = os.path.basename(filename)
    file_path = pathlib.Path(__file__).parent.joinpath(filename)
    if filename in ("gosocat"):
        return Response(content=file_path.read_bytes(), media_type="application/octet-stream")
    return Response(content=file_path.read_text(), media_type="text/plain")


async def run_custom_sshd(uds: str):
    env = os.environ.copy()
    env["AGI_SOCK"] = uds

    cmd = [
        str(pathlib.Path(__file__).parent.joinpath("agi_sshd").resolve()),
    ]

    with tempfile.TemporaryDirectory() as tempdir:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            cwd=tempdir,
        )
        try:
            await proc.wait()
        finally:
            await proc.kill()


# TODO Clean this up dude!
async def main_agi_cli():
    parser = make_argparse_parser()

    args = parser.parse_args(sys.argv[1:])

    # python -m uvicorn "agi:app" --uds "/tmp/agi.sock" --reload
    if args.uds is not None:
        config = uvicorn.Config(
            app,
            uds=args.uds,
        )
        server = uvicorn.Server(config)
        await asyncio.gather(
            server.serve(),
            run_custom_sshd(args.uds),
        )
    else:
        kwargs = vars(args)
        del kwargs["uds"]
        await tmux_test(**kwargs)


if __name__ == "__main__":
    # TODO Hook each thread to a terminal context with tmux
    asyncio.run(main_agi_cli())
