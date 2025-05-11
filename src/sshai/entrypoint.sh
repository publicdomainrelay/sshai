#!/usr/bin/env bash
set -o pipefail

if [[ "x${FAIL_ON_ERROR}" != "x0" ]]; then
  set -e
fi

export EDITOR=vim

# TODO Per distro dependencies via /usr/lib/os-release and
# /etc/os-release bash source | env
if [[ -f /usr/lib/os-release ]]; then
  . /usr/lib/os-release
fi
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
fi

SUDO=""
if [[ -f /usr/bin/sudo ]]; then
  SUDO="sudo -E"
fi


if [[ ! -f /usr/bin/socat ]] || [[ ! -f /usr/bin/git ]] || [[ ! -f /usr/bin/tmux ]] || [[ ! -f /usr/bin/ssh ]] || [[ ! -f /usr/bin/python ]] || [[ ! -f /usr/bin/unzip ]] || [[ ! -f /usr/bin/curl ]] || [[ ! -f /usr/bin/node ]]; then
  if [[ "x${ID}" = "xfedora" ]]; then
    $SUDO dnf install -y tmux git vim curl openssh socat jq python python-pip python-venv unzip nodejs
  fi
  if [[ "x${ID}" = "xdebian" ]] || [[ "x${ID_LIKE}" = "xdebian" ]]; then
    $SUDO apt-get update && $SUDO apt-get install -y tmux git vim curl openssh-client socat jq python3 python3-pip python3-venv unzip nodejs python-is-python3
  fi
fi

set -u

if [ ! -f /usr/bin/deno ]; then
  (
    cd $(mktemp -d) \
    && curl -sfLO 'https://github.com/denoland/deno/releases/download/v1.46.3/deno-x86_64-unknown-linux-gnu.zip' \
    && unzip deno*.zip \
    && sha384sum -c <<< "6b73273cd0eb0272d293edf10ab7accc0504943076ce5c6d354d44be3a7f47d21ae234b2f77bdfe94355984406645dab  deno" \
    && $SUDO mv -v deno /usr/bin/deno
  )
fi

if [ ! -f /usr/bin/caddy ]; then
  (
    cd $(mktemp -d) \
    && curl -sfL 'https://github.com/caddyserver/caddy/releases/download/v2.9.1/caddy_2.9.1_linux_amd64.tar.gz' | tar xvz \
    && sha384sum -c <<< "559c2b006a3f30f13a0d4f081d6728875a1d2fea0dd732b434fb77158f52b49664aaff1f500258425510166030af5d13  caddy" \
    && $SUDO mv -v caddy /usr/bin/caddy
  )
fi

policy_engine_deps() {
  if [ ! -f "${CALLER_PATH}/.venv/bin/activate" ]; then
    python -m venv "${CALLER_PATH}/.venv"
  fi
  OLD_PS1="${PS1}"
  source "${CALLER_PATH}/.venv/bin/activate"
  export PS1="${OLD_PS1}"
  python -m pip install -U pip setuptools wheel build
  python -m pip install -U pyyaml snoop pytest httpx cachetools aiohttp gidgethub[aiohttp] celery[redis] fastapi pydantic gunicorn uvicorn
}

if [ ! -f "${CALLER_PATH}/policy_engine.py" ]; then
  policy_engine_deps

  (
    cd $(mktemp -d) \
    && curl -sfLo policy_engine.py https://github.com/pdxjohnny/scitt-api-emulator/raw/dc7a0b790493b960acd0bf7dfea6547619cde4b3/scitt_emulator/policy_engine.py \
    && sha384sum -c <<< "0eb82d8342bbd1ca6ec322fa253fc8603d5ffce6a09fff33b1e9c65366fd674fe35bf6176e79ff90c75d1769237b55da  policy_engine.py" \
    && mv -v policy_engine.py "${CALLER_PATH}/policy_engine.py"
  )
fi
