# AI Security Platform Architecture

## Overview

The AI Security Platform runs on a DigitalOcean Ubuntu VPS and provides self-hosted AI services for security investigation, AI prompt testing, model evaluation, and future MCP integration.

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
