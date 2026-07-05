import json
import sys
from datetime import datetime, timezone
from typing import Optional


def log_request_telemetry(
    *,
    request_id: str,
    provider: str,
    model: str,
    latency_ms: int,
    success: bool,
    status_code: int,
    error_type: Optional[str] = None,
) -> None:
    record = {
        "request_id": request_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "model": model,
        "latency_ms": latency_ms,
        "success": success,
        "status_code": status_code,
    }
    if error_type is not None:
        record["error_type"] = error_type

    print(json.dumps(record), file=sys.stdout, flush=True)
