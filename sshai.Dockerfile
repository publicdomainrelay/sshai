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
FROM registry.fedoraproject.org/fedora AS client

COPY --from=builder /usr/src/app/dist/*.whl /tmp/install-wheels/

ENV CALLER_PATH=/host

RUN set -x \
  && pip install /tmp/install-wheels/*.whl

ENTRYPOINT ["python", "-m", "sshai", "--uds", "/host/agi.sock"]
