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
- Nginx reverse proxy deployed (port 80)
- gemma2:2b model installed and tested

## Architecture

MacBook connects to the VPS over SSH.

The VPS runs Docker containers for AI and security tooling.

Current containers:

- Ollama (internal)
- Open WebUI (internal)
- Nginx (public entry point on port 80)

Traffic flow:

```text
Browser → Nginx :80 → Open WebUI :8080 → Ollama :11434 → gemma2:2b
```

## Next Goals

- Add HTTPS/TLS (terminate at Nginx; planned for a later module)
- Add promptfoo
- Add garak
- Add Prometheus and Grafana
- Integrate AI Agent MCP Lab
