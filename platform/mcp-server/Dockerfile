FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY mcp_server.py .
COPY test_mcp_client.py .
COPY schemas/ schemas/
COPY tools/ tools/
COPY sample_data/ sample_data/

# Default remains the offline CLI help. MCP stdio is started explicitly:
#   python mcp_server.py
CMD ["python", "main.py", "--help"]
