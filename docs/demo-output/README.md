# Demo Gallery

These reports are generated from fictional normalized security alerts using the platform’s deterministic investigation and reporting pipeline. HTML reports are standalone and offline. The PDF sample is produced from the SSH HTML report using browser print-to-PDF.

| Scenario              | Demonstrates                                         | Expected Disposition  | Input | Markdown | HTML | PDF  |
| --------------------- | ---------------------------------------------------- | --------------------- | ----- | -------- | ---- | ---- |
| SSH Failed Login      | Authentication and Linux remote-access investigation | Suspicious Activity   | [JSON](../../platform/mcp-server/sample_data/ssh_failed_login.json) | [MD](ssh-failed-login-investigation.md) | [HTML](ssh-failed-login-investigation.html) | [PDF](ssh-failed-login-investigation.pdf) |
| Phishing Email        | Email and URL investigation                          | Suspicious Activity   | [JSON](../../platform/mcp-server/sample_data/proofpoint_phishing.json) | [MD](phishing-email-investigation.md) | [HTML](phishing-email-investigation.html) | — |
| Suspicious Process    | Endpoint process investigation                       | Suspicious Activity   | [JSON](../../platform/mcp-server/sample_data/defender_suspicious_process.json) | [MD](suspicious-process-investigation.md) | [HTML](suspicious-process-investigation.html) | — |
| Insufficient Evidence | Conservative analyst decision with evidence gaps     | Insufficient Evidence | [JSON](../../platform/mcp-server/sample_data/insufficient_evidence.json) | [MD](insufficient-evidence-investigation.md) | [HTML](insufficient-evidence-investigation.html) | — |

GitHub may show raw HTML source for `.html` files. Download or open the standalone HTML locally in a browser for the intended presentation. The PDF sample is a browser export of the SSH HTML report.

## Regeneration

One investigation run builds a single `InvestigationReport`, then renders both Markdown and HTML. Do not hand-edit generated Markdown or HTML.

From `platform/`:

```bash
cd ~/projects/ai-agent-mcp-lab/platform

# Required: mount docs/demo-output — the MCP container has no default host docs/ mount
docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/ssh_failed_login.json \
    -o /output/ssh-failed-login-investigation.md \
    --html-output /output/ssh-failed-login-investigation.html

docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/proofpoint_phishing.json \
    -o /output/phishing-email-investigation.md \
    --html-output /output/phishing-email-investigation.html

docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/defender_suspicious_process.json \
    -o /output/suspicious-process-investigation.md \
    --html-output /output/suspicious-process-investigation.html

docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/insufficient_evidence.json \
    -o /output/insufficient-evidence-investigation.md \
    --html-output /output/insufficient-evidence-investigation.html
```

## Notes

- Generated Markdown and HTML should not be hand-edited.
- HTML is authoritative for browser presentation.
- PDF is a manual browser export (Print → Save as PDF). There is no automated PDF flag.
- Sample data is fictional (documentation IPs, example domains, synthetic hosts).
- Reports do not represent live SIEM or EDR connections.
- Analyst review remains required for every disposition.
- Only the SSH scenario includes a committed PDF sample.

Related: [Root README](../../README.md) · [MCP server README](../../platform/mcp-server/README.md) · [PROJECT_CONTEXT.md](../../PROJECT_CONTEXT.md)
