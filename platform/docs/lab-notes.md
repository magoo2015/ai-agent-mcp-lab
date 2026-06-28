# AI Security Platform Lab Notes

See also: [platform-blueprint.md](./platform-blueprint.md) for the full platform vision, security model, and roadmap.

## Current Status

- DigitalOcean Ubuntu VPS created
- SSH key authentication configured
- Non-root admin user created: sysadmin
- UFW firewall enabled
- Fail2ban enabled
- Root SSH login disabled
- Docker and Docker Compose installed
- Ollama deployed with Docker Compose
- Open WebUI deployed with Docker Compose
- gemma2:2b model installed and tested

## Architecture

MacBook connects to the VPS over SSH.

The VPS runs Docker containers for AI and security tooling.

Current containers:

- Ollama
- Open WebUI

## Next Goals

- Add Nginx reverse proxy
- Add HTTPS later
- Add promptfoo
- Add garak
- Add Prometheus and Grafana
- Integrate AI Agent MCP Lab
