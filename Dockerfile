# mode: sync needs BOTH the Node-based obsidian-headless client (`ob`) and the
# Python MCP server, so we start from Node and add a Python venv.
FROM node:22-bookworm-slim

# The official Obsidian Sync headless client provides the `ob` CLI.
RUN npm install -g obsidian-headless \
    && rm -rf /root/.npm

# Python runtime for the MCP server (kept in a venv to avoid PEP 668 friction).
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[http]"

# `ob` persists login + vault link under HOME; mount volumes here (see compose).
ENV HOME=/root
EXPOSE 4012

# Serves the MCP server over HTTP and, in mode: sync, supervises `ob sync
# --continuous` as a child process. Config is mounted at /config/config.yaml.
ENTRYPOINT ["fenced-obsidian-sync-mcp"]
CMD ["--config", "/config/config.yaml"]
