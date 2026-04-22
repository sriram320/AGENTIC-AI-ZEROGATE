---
description: "Integrate ZeroGate with Claude Code as an MCP server for natural language codebase analysis."
---

# MCP Server (Claude Code Integration)

ZeroGate can run as an MCP (Model Context Protocol) server, enabling seamless integration with Claude Code and other MCP clients.

## Quick Setup

**If installed via pip** (and `zerogate` is on your PATH):

```bash
claude mcp add --transport stdio zerogate \
  --env TARGET_REPO_PATH=/absolute/path/to/your/project \
  --env CYPHER_PROVIDER=openai \
  --env CYPHER_MODEL=gpt-4 \
  --env CYPHER_API_KEY=your-api-key \
  -- zerogate mcp-server
```

**If installed from source:**

```bash
claude mcp add --transport stdio zerogate \
  --env TARGET_REPO_PATH=/absolute/path/to/your/project \
  --env CYPHER_PROVIDER=openai \
  --env CYPHER_MODEL=gpt-4 \
  --env CYPHER_API_KEY=your-api-key \
  -- uv run --directory /path/to/zerogate zerogate mcp-server
```

### Using Current Directory

```bash
cd /path/to/your/project

claude mcp add --transport stdio zerogate \
  --env TARGET_REPO_PATH="$(pwd)" \
  --env CYPHER_PROVIDER=google \
  --env CYPHER_MODEL=gemini-2.0-flash \
  --env CYPHER_API_KEY=your-google-api-key \
  -- uv run --directory /absolute/path/to/zerogate zerogate mcp-server
```

## Prerequisites

```bash
git clone https://github.com/krrishitejas/zerogate.git
cd zerogate
uv sync

docker run -p 7687:7687 -p 7444:7444 memgraph/memgraph-platform
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_projects` | List all indexed projects in the knowledge graph database |
| `delete_project` | Delete a specific project from the knowledge graph database |
| `wipe_database` | Completely wipe the entire database (cannot be undone) |
| `index_repository` | Parse and ingest the repository into the knowledge graph |
| `query_code_graph` | Query the codebase knowledge graph using natural language |
| `get_code_snippet` | Retrieve source code for a function, class, or method by qualified name |
| `surgical_replace_code` | Surgically replace an exact code block using diff-match-patch |
| `read_file` | Read file contents with pagination support |
| `write_file` | Write content to a file |
| `list_directory` | List directory contents |

## Example Usage

```
> Index this repository
> What functions call UserService.create_user?
> Update the login function to add rate limiting
```

## LLM Provider Options

=== "OpenAI"

    ```bash
    --env CYPHER_PROVIDER=openai \
    --env CYPHER_MODEL=gpt-4 \
    --env CYPHER_API_KEY=sk-...
    ```

=== "Google Gemini"

    ```bash
    --env CYPHER_PROVIDER=google \
    --env CYPHER_MODEL=gemini-2.5-flash \
    --env CYPHER_API_KEY=...
    ```

=== "Ollama (free, local)"

    ```bash
    --env CYPHER_PROVIDER=ollama \
    --env CYPHER_MODEL=llama3.2
    ```

## Multi-Repository Setup

Add separate named instances for different projects:

```bash
claude mcp add --transport stdio zerogate-backend \
  --env TARGET_REPO_PATH=/path/to/backend \
  --env CYPHER_PROVIDER=openai \
  --env CYPHER_MODEL=gpt-4 \
  --env CYPHER_API_KEY=your-api-key \
  -- uv run --directory /path/to/zerogate zerogate mcp-server

claude mcp add --transport stdio zerogate-frontend \
  --env TARGET_REPO_PATH=/path/to/frontend \
  --env CYPHER_PROVIDER=openai \
  --env CYPHER_MODEL=gpt-4 \
  --env CYPHER_API_KEY=your-api-key \
  -- uv run --directory /path/to/zerogate zerogate mcp-server
```

!!! warning
    Only one repository can be indexed at a time per MCP instance. When you index a new repository, the previous repository's data is automatically cleared.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Can't find uv/zerogate | Use absolute paths from `which uv` |
| Wrong repository analyzed | Set `TARGET_REPO_PATH` to an absolute path |
| Memgraph connection failed | Ensure `docker ps` shows Memgraph running |
| Tools not showing | Run `claude mcp list` to verify installation |

## Remove

```bash
claude mcp remove zerogate
```
