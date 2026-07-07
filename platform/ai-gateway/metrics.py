from typing import Optional

from prometheus_client import Counter, Histogram

REQUESTS_TOTAL = Counter(
    "ai_gateway_requests_total",
    "Total number of AI gateway chat requests",
    ["provider", "model", "status"],
)

REQUEST_LATENCY_SECONDS = Histogram(
    "ai_gateway_request_latency_seconds",
    "AI gateway request latency in seconds",
    ["provider", "model"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float("inf")),
)

ERRORS_TOTAL = Counter(
    "ai_gateway_errors_total",
    "Total number of AI gateway errors",
    ["provider", "model", "error_type"],
)


def record_request_metrics(
    *,
    provider: str,
    model: str,
    latency_ms: int,
    success: bool,
    status_code: int,
    error_type: Optional[str] = None,
) -> None:
    REQUESTS_TOTAL.labels(
        provider=provider, model=model, status=str(status_code)
    ).inc()
    REQUEST_LATENCY_SECONDS.labels(provider=provider, model=model).observe(
        latency_ms / 1000.0
    )
    if not success and error_type is not None:
        ERRORS_TOTAL.labels(
            provider=provider, model=model, error_type=error_type
        ).inc()
