# AI Security Platform Architecture

> For the complete platform blueprint—including security model, roadmap, and interview narrative—see [platform-blueprint.md](./platform-blueprint.md).

## Overview

The AI Security Engineering Platform runs on a DigitalOcean Ubuntu VPS and provides self-hosted AI services for security investigation, AI prompt testing, model evaluation, and MCP-integrated SOC workflows. The application-layer MCP server (`soc-assistant`) runs on the developer workstation; the VPS hosts the containerized LLM stack.

## Current Components

### DigitalOcean VPS

The VPS provides the Linux runtime environment for Docker, AI tooling, monitoring, and security platform services.

### Docker

Docker is used to containerize platform services so they can be managed consistently with Docker Compose.

### Ollama

Ollama runs the local language model backend.

Current model:

- gemma2:2b

### Open WebUI

Open WebUI provides a browser-based chat interface connected to Ollama.

### Volumes

Docker volumes persist model files and Open WebUI data across container restarts.

### MCP Lab

The repository root contains `scripts/soc_mcp_server.py`, a Python FastMCP server that exposes SOC investigation tools to AI agents (Cursor and other MCP clients). It complements the VPS-hosted chat stack by providing structured, bounded security automation—not additional containers on the VPS today.

## Current Traffic Flow

```text
User Browser
    ↓
Open WebUI :3000
    ↓
Ollama :11434
    ↓
gemma2:2b
```
