"""Deterministic evidence extraction from normalized AlertInput fields.

Extracts factual observables and alert metadata only. Does not parse
raw_event, call external APIs, or classify MITRE techniques as evidence.
"""

from __future__ import annotations

from typing import Optional

from schemas.alert_schema import AlertInput

from reports.models import EvidenceItem

# Fixed extraction order — never derive from dictionary iteration.
_EVIDENCE_SPECS: tuple[tuple[str, str, str, str, str, str], ...] = (
    # (kind, category, label, source, context, value_path)
    (
        "metadata",
        "Alert Metadata",
        "Platform",
        "alert.platform",
        "Platform that generated the normalized alert.",
        "platform",
    ),
    (
        "metadata",
        "Alert Metadata",
        "Alert type",
        "alert.alert_type",
        "Normalized alert type.",
        "alert_type",
    ),
    (
        "metadata",
        "Alert Metadata",
        "Vendor severity",
        "alert.severity",
        "Severity reported by the alert source.",
        "severity",
    ),
    (
        "metadata",
        "Alert Metadata",
        "Description",
        "alert.description",
        "Description supplied with the normalized alert.",
        "description",
    ),
    (
        "observable",
        "Identity",
        "Username",
        "alert.observables.username",
        "Account associated with the alert.",
        "observables.username",
    ),
    (
        "observable",
        "Host",
        "Hostname",
        "alert.observables.hostname",
        "Host associated with the alert.",
        "observables.hostname",
    ),
    (
        "observable",
        "Network",
        "Source IP",
        "alert.observables.source_ip",
        "Source IP associated with the alert.",
        "observables.source_ip",
    ),
    (
        "observable",
        "Network",
        "Destination IP",
        "alert.observables.destination_ip",
        "Destination IP associated with the alert.",
        "observables.destination_ip",
    ),
    (
        "observable",
        "Indicator",
        "URL",
        "alert.observables.url",
        "URL associated with the alert.",
        "observables.url",
    ),
    (
        "observable",
        "Indicator",
        "File hash",
        "alert.observables.file_hash",
        "File hash associated with the alert.",
        "observables.file_hash",
    ),
    (
        "observable",
        "Process",
        "Process name",
        "alert.observables.process_name",
        "Process name associated with the alert.",
        "observables.process_name",
    ),
    (
        "observable",
        "Email",
        "Sender",
        "alert.observables.sender",
        "Email sender associated with the alert.",
        "observables.sender",
    ),
    (
        "observable",
        "Email",
        "Recipient",
        "alert.observables.recipient",
        "Email recipient associated with the alert.",
        "observables.recipient",
    ),
)


def _resolve_field(alert: AlertInput, path: str) -> Optional[str]:
    """Return a normalized top-level or observables field value."""
    if path.startswith("observables."):
        field_name = path.split(".", 1)[1]
        return getattr(alert.observables, field_name)
    return getattr(alert, path)


def _is_present(value: Optional[str]) -> bool:
    """True when value is a non-empty, non-whitespace-only string."""
    if value is None:
        return False
    if not isinstance(value, str):
        return False
    return bool(value.strip())


def extract_evidence(alert: AlertInput) -> list[EvidenceItem]:
    """Extract factual evidence from normalized alert fields only.

    Deterministic, side-effect free, and independent of InvestigationOutput.
    Skips None / empty / whitespace-only values. Does not parse raw_event.
    """
    items: list[EvidenceItem] = []
    for kind, category, label, source, context, path in _EVIDENCE_SPECS:
        value = _resolve_field(alert, path)
        if not _is_present(value):
            continue
        assert isinstance(value, str)
        evidence_id = f"EVID-{len(items) + 1:03d}"
        items.append(
            EvidenceItem(
                evidence_id=evidence_id,
                kind=kind,
                category=category,
                label=label,
                value=value,
                source=source,
                context=context,
            )
        )
    return items
