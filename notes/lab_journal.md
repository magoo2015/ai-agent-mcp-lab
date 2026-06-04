# Session Notes

## What I Built

- Connected filesystem MCP server
- Built custom Python MCP server
- Added parse_wazuh_alert tool
- Connected Cursor to custom MCP

## Key Concepts Learned

- MCP provides tools to AI agents
- AI reasons, MCP tools perform actions
- Filesystem MCP vs custom SOC MCP
- Tool orchestration
- Scoped access and security

## Biggest Insight

SOAR playbooks automate.
AI agents reason.
Mature SOCs will likely combine both.

## Custom MCP Milestone

- Built a Python MCP server named soc-assistant
- Added parse_wazuh_alert to extract Wazuh observables
- Added score_ssh_alert to assign severity, confidence, and priority
- Confirmed Cursor can call both custom MCP tools
- Learned that MCP tools should extract/structure facts while the AI explains and reasons
