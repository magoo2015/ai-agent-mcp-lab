# AI Security Platform

This directory contains the infrastructure layer for the AI Agent MCP Lab.

## Current Capabilities

- Self-hosted Ollama LLM service
- Open WebUI browser interface
- Docker Compose deployment
- Persistent Docker volumes for model and application data
- DigitalOcean Ubuntu VPS deployment

## Current Architecture

Browser → Open WebUI → Ollama → Local model

## Current Model

- gemma2:2b

## Platform Goals

- Add Nginx reverse proxy
- Add HTTPS/TLS
- Add Prometheus and Grafana monitoring
- Add promptfoo for AI prompt evaluation
- Add garak for AI security testing
- Integrate with the MCP security assistant
