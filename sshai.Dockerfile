# docker build --progress=plain -t sshai -f sshai.Dockerfile . && docker run --rm -ti -p 2222:2222 -e OPENAI_API_KEY=$(python -m keyring get $(git config user.email) api-key.platform.openai.com) sshai
FROM python:3.12 AS builder

RUN set -x \
  && python -m pip install -U pip setuptools wheel build

ARG GO_VERSION=1.24.2
RUN set -x \
  && curl -sfL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
       | tar -C /usr/local -xz \
  && ln -s /usr/local/go/bin/* /usr/bin/ \
  && go version

WORKDIR /usr/src/app

COPY . /usr/src/app

RUN set -x \
  && python -m build . \
  && python -m tarfile -l dist/*.tar.*

# Python server, add built golang server
FROM python:3.12 AS server

RUN set -x \
  && apt-get update \
  && apt-get install -y tmux \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/dist/*.whl /tmp/install-wheels/

ENV CALLER_PATH=/host

RUN set -x \
  && mkdir -pv $CALLER_PATH \
  && pip install /tmp/install-wheels/*.whl \
    "mcp-proxy@git+https://github.com/johnandersen777/mcp-proxy@mcp_enable_over_unix_socket" \
    "mcp@git+https://github.com/johnandersen777/python-sdk@mcp_enable_over_unix_socket" \
    "openai-agents@git+https://github.com/johnandersen777/openai-agents-python@additional_properties_dict_keys_mcp_enable_over_unix_socket"

ENTRYPOINT ["python", "-m", "sshai", "--uds", "/host/agi.sock"]
