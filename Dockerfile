# IRKit runner: Claude Code CLI + uv/Python 3.12, for driving a case end to end.
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git tini && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (provides the `claude` binary IRKit launches).
RUN npm install -g @anthropic-ai/claude-code && claude --version

# uv for the Python project.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /opt/irkit
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY scripts ./scripts
COPY examples ./examples
RUN uv python install 3.12 && uv sync --locked --no-build-package evtx && \
    /opt/irkit/.venv/bin/python -c 'from evtx import PyEvtxParser'

ENV PATH=/opt/irkit/.venv/bin:/usr/local/bin:$PATH \
    IRKIT_EVTX_PYTHON=/opt/irkit/.venv/bin/python \
    HOME=/root \
    PYTHONUNBUFFERED=1 \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

COPY docker-run.sh /opt/irkit/docker-run.sh
RUN chmod +x /opt/irkit/docker-run.sh
ENTRYPOINT ["tini","--","/opt/irkit/docker-run.sh"]
