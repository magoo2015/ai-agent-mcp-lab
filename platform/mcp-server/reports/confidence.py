"""Deterministic structured confidence rationale (Version 1.1 Phase 4).

Builds ConfidenceRationale from AlertInput + EvidenceItem lists only.
Does not consume InvestigationOutput, confidence scores, MITRE mappings,
AnalystReasoning, or raw_event. Does not recalculate or reproduce the
numeric confidence algorithm in tools/investigate_alert._compute_confidence.
"""

from __future__ import annotations

from typing import Callable, Optional

from schemas.alert_schema import AlertInput

from reports.models import ConfidenceRationale, ConfidenceStatement, EvidenceItem

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

# Observable sources preferred for unknown-alert fallback (ordered).
_FALLBACK_OBSERVABLE_SOURCES: tuple[str, ...] = (
    _SRC_SOURCE_IP,
    _SRC_DEST_IP,
    _SRC_USERNAME,
    _SRC_HOSTNAME,
    _SRC_URL,
    _SRC_FILE_HASH,
    _SRC_PROCESS,
    _SRC_SENDER,
    _SRC_RECIPIENT,
)

_OBSERVABLE_SUPPORT_TEXT: dict[str, str] = {
    _SRC_SOURCE_IP: "A source IP is identified in the normalized evidence.",
    _SRC_DEST_IP: "A destination IP is identified.",
    _SRC_USERNAME: "A username is identified.",
    _SRC_HOSTNAME: "A hostname is identified.",
    _SRC_URL: "A URL is identified.",
    _SRC_FILE_HASH: "A file hash is identified.",
    _SRC_PROCESS: "A process name is identified.",
    _SRC_SENDER: "An email sender is identified.",
    _SRC_RECIPIENT: "An email recipient is identified.",
}


def _normalize_alert_type(alert_type: str) -> str:
    """Private normalizer for confidence routing only — does not alter other modules."""
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


def _make_statement(
    text: str,
    evidence_ids: Optional[list[str]] = None,
) -> ConfidenceStatement:
    """Build a statement without an ID (IDs assigned later by category)."""
    return ConfidenceStatement(
        statement_id="",  # assigned by _assign_statement_ids
        text=text,
        evidence_ids=_dedupe_ids(list(evidence_ids or [])),
    )


def _assign_statement_ids(
    statements: list[ConfidenceStatement],
    prefix: str,
) -> list[ConfidenceStatement]:
    """Assign deterministic category IDs beginning at 001."""
    assigned: list[ConfidenceStatement] = []
    for index, statement in enumerate(statements, start=1):
        assigned.append(
            ConfidenceStatement(
                statement_id=f"{prefix}-{index:03d}",
                text=statement.text,
                evidence_ids=list(statement.evidence_ids),
            )
        )
    return assigned


def _validate_evidence_refs(
    rationale: ConfidenceRationale,
    evidence: list[EvidenceItem],
) -> None:
    """Confirm every referenced evidence ID exists in the supplied list."""
    known = {item.evidence_id for item in evidence}
    for section in (rationale.supporting_factors, rationale.limiting_factors):
        for statement in section:
            for evid in statement.evidence_ids:
                if evid not in known:
                    raise ValueError(
                        f"Confidence statement {statement.statement_id} "
                        f"references unknown evidence ID {evid!r}"
                    )


def _finalize(
    supporting: list[ConfidenceStatement],
    limiting: list[ConfidenceStatement],
    summary: str,
    evidence: list[EvidenceItem],
) -> ConfidenceRationale:
    """Assign IDs, validate references, and return ConfidenceRationale."""
    rationale = ConfidenceRationale(
        supporting_factors=_assign_statement_ids(supporting, "SUP"),
        limiting_factors=_assign_statement_ids(limiting, "LIM"),
        summary=summary,
    )
    _validate_evidence_refs(rationale, evidence)
    return rationale


def _activity_factor(
    evidence: list[EvidenceItem],
    text: str,
) -> list[ConfidenceStatement]:
    """Supporting factor about alert type / description when those fields are present."""
    refs = _ids_for_sources(evidence, _SRC_ALERT_TYPE, _SRC_DESCRIPTION)
    if not refs:
        return []
    return [_make_statement(text, refs)]


def _field_factor(
    evidence: list[EvidenceItem],
    source: str,
    text: str,
) -> Optional[ConfidenceStatement]:
    """Single supporting factor referencing its evidence ID when present."""
    refs = _ids_for_sources(evidence, source)
    if not refs:
        return None
    return _make_statement(text, refs)


def _build_ssh_confidence(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> ConfidenceRationale:
    supporting: list[ConfidenceStatement] = []
    supporting.extend(
        _activity_factor(
            evidence,
            "Authentication-failure activity is reported in the normalized alert.",
        )
    )
    for source, text in (
        (_SRC_SOURCE_IP, "A source IP is identified in the normalized evidence."),
        (_SRC_USERNAME, "A target username is identified."),
        (_SRC_HOSTNAME, "A destination host is identified."),
        (_SRC_DEST_IP, "A destination IP is identified."),
    ):
        statement = _field_factor(evidence, source, text)
        if statement is not None:
            supporting.append(statement)

    limiting: list[ConfidenceStatement] = [
        _make_statement(
            "Successful authentication cannot be confirmed from normalized evidence alone."
        ),
        _make_statement(
            "Post-authentication endpoint activity is not available in the normalized alert."
        ),
        _make_statement("Containment or response status is not available."),
    ]

    summary = (
        "The available normalized identifiers provide grounding for the "
        "authentication investigation, while successful-login and "
        "post-authentication telemetry remain unavailable. These factors "
        "provide context for the reported confidence score but do not "
        "reproduce its calculation."
    )
    return _finalize(supporting, limiting, summary, evidence)


def _build_phishing_confidence(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> ConfidenceRationale:
    supporting: list[ConfidenceStatement] = []
    supporting.extend(
        _activity_factor(
            evidence,
            "Suspicious email activity is reported in the normalized alert.",
        )
    )
    for source, text in (
        (_SRC_SENDER, "An email sender is identified."),
        (_SRC_RECIPIENT, "An email recipient is identified."),
        (_SRC_URL, "A URL is identified."),
        (_SRC_HOSTNAME, "A related hostname is identified."),
    ):
        statement = _field_factor(evidence, source, text)
        if statement is not None:
            supporting.append(statement)

    limiting: list[ConfidenceStatement] = [
        _make_statement(
            "Message-delivery outcome cannot be confirmed from normalized evidence alone."
        ),
        _make_statement(
            "User interaction is not available in the normalized alert."
        ),
        _make_statement(
            "Credential submission cannot be confirmed from normalized evidence alone."
        ),
    ]

    summary = (
        "The available normalized email identifiers provide grounding for the "
        "phishing investigation, while delivery, interaction, and credential "
        "outcomes remain unconfirmed. These factors provide context for the "
        "reported confidence score but do not reproduce its calculation."
    )
    return _finalize(supporting, limiting, summary, evidence)


def _build_suspicious_process_confidence(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> ConfidenceRationale:
    supporting: list[ConfidenceStatement] = []
    supporting.extend(
        _activity_factor(
            evidence,
            "Suspicious process activity is reported in the normalized alert.",
        )
    )
    for source, text in (
        (_SRC_PROCESS, "A process name is identified."),
        (_SRC_HOSTNAME, "A host is identified."),
        (_SRC_FILE_HASH, "A file hash is identified."),
        (_SRC_USERNAME, "An associated username is identified."),
        (_SRC_URL, "A related URL is identified."),
        (_SRC_SOURCE_IP, "A source IP is identified."),
    ):
        statement = _field_factor(evidence, source, text)
        if statement is not None:
            supporting.append(statement)

    limiting: list[ConfidenceStatement] = [
        _make_statement(
            "A full process command line is not available in normalized observables."
        ),
        _make_statement("Parent-child process context is not available."),
        _make_statement("Endpoint containment status is not available."),
        _make_statement(
            "Confirmed network-session telemetry is not available."
        ),
    ]

    summary = (
        "The available normalized process and host identifiers provide "
        "grounding for the process investigation, while execution depth, "
        "process ancestry, network confirmation, and containment status "
        "remain unavailable. These factors provide context for the reported "
        "confidence score but do not reproduce its calculation."
    )
    return _finalize(supporting, limiting, summary, evidence)


def _build_unknown_confidence(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> ConfidenceRationale:
    supporting: list[ConfidenceStatement] = []

    type_item = _find_by_source(evidence, _SRC_ALERT_TYPE)
    if type_item is not None:
        supporting.append(
            _make_statement(
                "An alert type is identified in the normalized alert.",
                [type_item.evidence_id],
            )
        )

    desc_item = _find_by_source(evidence, _SRC_DESCRIPTION)
    if desc_item is not None:
        supporting.append(
            _make_statement(
                "A description is identified in the normalized alert.",
                [desc_item.evidence_id],
            )
        )

    added = 0
    for source in _FALLBACK_OBSERVABLE_SOURCES:
        if added >= 3:
            break
        text = _OBSERVABLE_SUPPORT_TEXT.get(source)
        if text is None:
            continue
        statement = _field_factor(evidence, source, text)
        if statement is not None:
            supporting.append(statement)
            added += 1

    limiting: list[ConfidenceStatement] = [
        _make_statement(
            "Scenario-specific corroborating telemetry is not represented in "
            "the current normalized alert model."
        ),
        _make_statement(
            "Analyst validation is required before treating the reported "
            "confidence as high-fidelity."
        ),
    ]

    summary = (
        "The available normalized fields provide limited grounding for the "
        "investigation. Scenario-specific corroboration is unavailable, and "
        "these factors do not reproduce the numeric confidence calculation."
    )
    return _finalize(supporting, limiting, summary, evidence)


CONFIDENCE_BUILDERS: dict[
    str,
    Callable[[AlertInput, list[EvidenceItem]], ConfidenceRationale],
] = {
    "ssh_failed_login": _build_ssh_confidence,
    "phishing_email": _build_phishing_confidence,
    "suspicious_process": _build_suspicious_process_confidence,
}


def build_confidence_rationale(
    alert: AlertInput,
    evidence: list[EvidenceItem],
) -> ConfidenceRationale:
    """Build structured confidence rationale from alert + extracted evidence.

    Deterministic, side-effect free, and independent of InvestigationOutput
    and numeric confidence. Does not parse raw_event or mutate inputs.
    """
    normalized = _normalize_alert_type(alert.alert_type)
    builder = CONFIDENCE_BUILDERS.get(normalized, _build_unknown_confidence)
    return builder(alert, evidence)
