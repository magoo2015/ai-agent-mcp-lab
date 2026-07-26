"""Deterministic structured recommended disposition (Version 1.1 Phase 5).

Builds RecommendedDisposition from AlertInput + EvidenceItem lists only.
Advisory and report-only — does not close incidents, trigger containment,
or alter confidence, severity, or MITRE. Does not consume InvestigationOutput,
AnalystReasoning, ConfidenceRationale, or raw_event.
"""

from __future__ import annotations

from typing import Callable, Optional

from schemas.alert_schema import AlertInput

from reports.models import DispositionLabel, EvidenceItem, RecommendedDisposition

# Preferred lookup keys — stable source paths from evidence extraction.
_SRC_ALERT_TYPE = "alert.alert_type"
_SRC_DESCRIPTION = "alert.description"
_SRC_USERNAME = "alert.observables.username"
_SRC_HOSTNAME = "alert.observables.hostname"
_SRC_SOURCE_IP = "alert.observables.source_ip"
_SRC_DEST_IP = "alert.observables.destination_ip"
_SRC_URL = "alert.observables.url"
_SRC_FILE_HASH = "alert.observables.file_hash"
_SRC_PROCESS = "alert.observables.process_name"
_SRC_SENDER = "alert.observables.sender"
_SRC_RECIPIENT = "alert.observables.recipient"

# Scenario-driving observables (presence → Suspicious Activity).
_SSH_DRIVING: tuple[str, ...] = (
    _SRC_USERNAME,
    _SRC_HOSTNAME,
    _SRC_SOURCE_IP,
    _SRC_DEST_IP,
)

_PHISHING_DRIVING: tuple[str, ...] = (
    _SRC_SENDER,
    _SRC_RECIPIENT,
    _SRC_URL,
    _SRC_HOSTNAME,
)

_PROCESS_DRIVING: tuple[str, ...] = (
    _SRC_PROCESS,
    _SRC_HOSTNAME,
    _SRC_FILE_HASH,
    _SRC_URL,
    _SRC_USERNAME,
    _SRC_SOURCE_IP,
)

# Fixed evidence reference order for Suspicious Activity (when present).
_SSH_REF_ORDER: tuple[str, ...] = (
    _SRC_ALERT_TYPE,
    _SRC_DESCRIPTION,
    _SRC_SOURCE_IP,
    _SRC_USERNAME,
    _SRC_HOSTNAME,
    _SRC_DEST_IP,
)

_PHISHING_REF_ORDER: tuple[str, ...] = (
    _SRC_ALERT_TYPE,
    _SRC_DESCRIPTION,
    _SRC_SENDER,
    _SRC_RECIPIENT,
    _SRC_URL,
    _SRC_HOSTNAME,
)

_PROCESS_REF_ORDER: tuple[str, ...] = (
    _SRC_ALERT_TYPE,
    _SRC_DESCRIPTION,
    _SRC_PROCESS,
    _SRC_HOSTNAME,
    _SRC_FILE_HASH,
    _SRC_USERNAME,
    _SRC_URL,
    _SRC_SOURCE_IP,
)

_SSH_SUSPICIOUS_RATIONALE = (
    "The normalized alert contains authentication-failure activity and "
    "identifying network, account, or host context. Successful access or "
    "downstream compromise cannot be confirmed from the available evidence."
)

_SSH_INSUFFICIENT_RATIONALE = (
    "The alert is categorized as authentication-failure activity, but the "
    "normalized evidence does not include enough network, account, or host "
    "context to support a stronger disposition."
)

_PHISHING_SUSPICIOUS_RATIONALE = (
    "The normalized alert contains suspicious email indicators that warrant "
    "continued analyst investigation. Delivery, user interaction, and "
    "credential impact remain unconfirmed."
)

_PHISHING_INSUFFICIENT_RATIONALE = (
    "The alert is categorized as suspicious email activity, but the "
    "normalized evidence does not include enough sender, recipient, URL, or "
    "host context to support a stronger disposition."
)

_PROCESS_SUSPICIOUS_RATIONALE = (
    "The normalized alert identifies suspicious process activity and related "
    "endpoint or indicator context. Malicious execution and endpoint "
    "compromise cannot be confirmed from the available evidence."
)

_PROCESS_INSUFFICIENT_RATIONALE = (
    "The alert is categorized as suspicious process activity, but the "
    "normalized evidence does not include enough process, host, or indicator "
    "context to support a stronger disposition."
)

_UNKNOWN_RATIONALE = (
    "The normalized alert does not provide enough scenario-specific evidence "
    "to support a stronger disposition."
)


def _normalize_alert_type(alert_type: str) -> str:
    """Private normalizer for disposition routing only — does not alter other modules."""
    return alert_type.strip().lower().replace("-", "_").replace(" ", "_")


def _dedupe_ids(evidence_ids: list[str]) -> list[str]:
    """Remove duplicate IDs while preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for evid in evidence_ids:
        if evid in seen:
            continue
        seen.add(evid)
        result.append(evid)
    return result


def _find_by_source(
    evidence: list[EvidenceItem],
    source: str,
) -> Optional[EvidenceItem]:
    """Locate the first evidence item with an exact source path."""
    for item in evidence:
        if item.source == source:
            return item
    return None


def _ids_for_sources(
    evidence: list[EvidenceItem],
    *sources: str,
) -> list[str]:
    """Collect evidence IDs for present sources, deduped in order."""
    ids: list[str] = []
    for source in sources:
        item = _find_by_source(evidence, source)
        if item is not None:
            ids.append(item.evidence_id)
    return _dedupe_ids(ids)


def _has_any_source(
    evidence: list[EvidenceItem],
    sources: tuple[str, ...],
) -> bool:
    """True when at least one of the given source paths is present."""
    return any(_find_by_source(evidence, source) is not None for source in sources)


def _validate_evidence_refs(
    disposition: RecommendedDisposition,
    evidence: list[EvidenceItem],
) -> None:
    """Confirm every referenced evidence ID exists in the supplied list."""
    known = {item.evidence_id for item in evidence}
    for evid in disposition.evidence_ids:
        if evid not in known:
            raise ValueError(
                f"Recommended disposition references unknown evidence ID {evid!r}"
            )


def _make_disposition(
    label: DispositionLabel,
    rationale: str,
    evidence_ids: list[str],
    evidence: list[EvidenceItem],
) -> RecommendedDisposition:
    """Build, validate, and return a RecommendedDisposition."""
    result = RecommendedDisposition(
        disposition=label,
        rationale=rationale,
        evidence_ids=_dedupe_ids(list(evidence_ids)),
        analyst_review_required=True,
    )
    _validate_evidence_refs(result, evidence)
    return result


def _build_scenario_disposition(
    evidence: list[EvidenceItem],
    driving: tuple[str, ...],
    ref_order: tuple[str, ...],
    suspicious_rationale: str,
    insufficient_rationale: str,
) -> RecommendedDisposition:
    """Shared sufficiency + reference logic for supported scenarios."""
    if _has_any_source(evidence, driving):
        return _make_disposition(
            DispositionLabel.SUSPICIOUS_ACTIVITY,
            suspicious_rationale,
            _ids_for_sources(evidence, *ref_order),
            evidence,
        )
    # Prefer empty IDs when no scenario-driving observable exists.
    return _make_disposition(
        DispositionLabel.INSUFFICIENT_EVIDENCE,
        insufficient_rationale,
        [],
        evidence,
    )


def _build_ssh_disposition(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> RecommendedDisposition:
    return _build_scenario_disposition(
        evidence,
        _SSH_DRIVING,
        _SSH_REF_ORDER,
        _SSH_SUSPICIOUS_RATIONALE,
        _SSH_INSUFFICIENT_RATIONALE,
    )


def _build_phishing_disposition(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> RecommendedDisposition:
    return _build_scenario_disposition(
        evidence,
        _PHISHING_DRIVING,
        _PHISHING_REF_ORDER,
        _PHISHING_SUSPICIOUS_RATIONALE,
        _PHISHING_INSUFFICIENT_RATIONALE,
    )


def _build_suspicious_process_disposition(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> RecommendedDisposition:
    return _build_scenario_disposition(
        evidence,
        _PROCESS_DRIVING,
        _PROCESS_REF_ORDER,
        _PROCESS_SUSPICIOUS_RATIONALE,
        _PROCESS_INSUFFICIENT_RATIONALE,
    )


def _build_unknown_disposition(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> RecommendedDisposition:
    """Conservative fallback — never inherits a supported-scenario label."""
    return _make_disposition(
        DispositionLabel.INSUFFICIENT_EVIDENCE,
        _UNKNOWN_RATIONALE,
        [],
        evidence,
    )


DISPOSITION_BUILDERS: dict[
    str,
    Callable[[AlertInput, list[EvidenceItem]], RecommendedDisposition],
] = {
    "ssh_failed_login": _build_ssh_disposition,
    "phishing_email": _build_phishing_disposition,
    "suspicious_process": _build_suspicious_process_disposition,
}


def build_recommended_disposition(
    alert: AlertInput,
    evidence: list[EvidenceItem],
) -> RecommendedDisposition:
    """Build structured recommended disposition from alert + extracted evidence.

    Deterministic, side-effect free, and independent of InvestigationOutput,
    numeric confidence, severity, and MITRE. Does not parse raw_event or
    mutate inputs. Always requires analyst review.
    """
    normalized = _normalize_alert_type(alert.alert_type)
    builder = DISPOSITION_BUILDERS.get(normalized, _build_unknown_disposition)
    return builder(alert, evidence)
