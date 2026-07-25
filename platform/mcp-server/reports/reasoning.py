"""Deterministic evidence-based analyst reasoning (Version 1.1 Phase 3).

Builds structured AnalystReasoning from AlertInput + EvidenceItem lists.
Does not consume InvestigationOutput, parse raw_event, or call external APIs.
"""

from __future__ import annotations

from typing import Callable, Optional

from schemas.alert_schema import AlertInput

from reports.models import AnalystReasoning, EvidenceItem, ReasoningStatement

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

_OBSERVABLE_OBSERVATION_TEXT: dict[str, str] = {
    _SRC_SOURCE_IP: "The alert contains a source IP.",
    _SRC_DEST_IP: "The alert contains a destination IP.",
    _SRC_USERNAME: "The alert contains a username.",
    _SRC_HOSTNAME: "The alert contains a hostname.",
    _SRC_URL: "The alert contains a URL.",
    _SRC_FILE_HASH: "The alert contains a file hash.",
    _SRC_PROCESS: "The alert contains a process name.",
    _SRC_SENDER: "The alert contains an email sender.",
    _SRC_RECIPIENT: "The alert contains an email recipient.",
}


def _normalize_alert_type(alert_type: str) -> str:
    """Private normalizer for reasoning routing only — does not alter other modules."""
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
) -> ReasoningStatement:
    """Build a statement without an ID (IDs assigned later by section)."""
    return ReasoningStatement(
        statement_id="",  # assigned by _assign_statement_ids
        text=text,
        evidence_ids=_dedupe_ids(list(evidence_ids or [])),
    )


def _assign_statement_ids(
    statements: list[ReasoningStatement],
    prefix: str,
) -> list[ReasoningStatement]:
    """Assign deterministic section IDs beginning at 001."""
    assigned: list[ReasoningStatement] = []
    for index, statement in enumerate(statements, start=1):
        assigned.append(
            ReasoningStatement(
                statement_id=f"{prefix}-{index:03d}",
                text=statement.text,
                evidence_ids=list(statement.evidence_ids),
            )
        )
    return assigned


def _validate_evidence_refs(
    reasoning: AnalystReasoning,
    evidence: list[EvidenceItem],
) -> None:
    """Confirm every referenced evidence ID exists in the supplied list."""
    known = {item.evidence_id for item in evidence}
    sections = (
        reasoning.observations,
        reasoning.assessment,
        reasoning.alternative_explanations,
        reasoning.evidence_gaps,
    )
    for section in sections:
        for statement in section:
            for evid in statement.evidence_ids:
                if evid not in known:
                    raise ValueError(
                        f"Reasoning statement {statement.statement_id} "
                        f"references unknown evidence ID {evid!r}"
                    )


def _finalize(
    observations: list[ReasoningStatement],
    assessment: list[ReasoningStatement],
    alternatives: list[ReasoningStatement],
    gaps: list[ReasoningStatement],
    evidence: list[EvidenceItem],
) -> AnalystReasoning:
    """Assign IDs, validate references, and return AnalystReasoning."""
    reasoning = AnalystReasoning(
        observations=_assign_statement_ids(observations, "OBS"),
        assessment=_assign_statement_ids(assessment, "ASM"),
        alternative_explanations=_assign_statement_ids(alternatives, "ALT"),
        evidence_gaps=_assign_statement_ids(gaps, "GAP"),
    )
    _validate_evidence_refs(reasoning, evidence)
    return reasoning


def _alert_type_observation(evidence: list[EvidenceItem], text: str) -> list[ReasoningStatement]:
    """Observation about alert type / description when those fields are present."""
    refs = _ids_for_sources(evidence, _SRC_ALERT_TYPE, _SRC_DESCRIPTION)
    if not refs:
        return []
    return [_make_statement(text, refs)]


def _field_observation(
    evidence: list[EvidenceItem],
    source: str,
    text: str,
) -> Optional[ReasoningStatement]:
    """Single field observation referencing its evidence ID when present."""
    refs = _ids_for_sources(evidence, source)
    if not refs:
        return None
    return _make_statement(text, refs)


def _build_ssh_reasoning(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> AnalystReasoning:
    observations: list[ReasoningStatement] = []
    observations.extend(
        _alert_type_observation(
            evidence,
            "The normalized alert reports SSH authentication failures.",
        )
    )
    for source, text in (
        (_SRC_SOURCE_IP, "The alert contains a source IP."),
        (_SRC_DEST_IP, "The alert contains a destination IP."),
        (_SRC_USERNAME, "The alert contains a username."),
        (_SRC_HOSTNAME, "The alert contains a hostname."),
    ):
        statement = _field_observation(evidence, source, text)
        if statement is not None:
            observations.append(statement)

    assessment: list[ReasoningStatement] = [
        _make_statement(
            "The reported behavior is consistent with repeated SSH authentication failures.",
            _ids_for_sources(evidence, _SRC_ALERT_TYPE, _SRC_DESCRIPTION),
        ),
        _make_statement(
            "The normalized evidence does not establish that authentication succeeded.",
        ),
    ]

    alternatives: list[ReasoningStatement] = [
        _make_statement("Automated internet scanning or password guessing."),
        _make_statement(
            "Authorized security testing or administrative validation."
        ),
        _make_statement(
            "A vendor detection triggered on repeated but unsuccessful "
            "authentication activity."
        ),
    ]

    gaps: list[ReasoningStatement] = [
        _make_statement(
            "No successful-authentication telemetry is included in the normalized alert."
        ),
        _make_statement("No post-authentication process telemetry is included."),
        _make_statement("No lateral-movement telemetry is included."),
    ]

    return _finalize(observations, assessment, alternatives, gaps, evidence)


def _build_phishing_reasoning(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> AnalystReasoning:
    observations: list[ReasoningStatement] = []
    observations.extend(
        _alert_type_observation(
            evidence,
            "The normalized alert reports suspicious email activity.",
        )
    )
    for source, text in (
        (_SRC_SENDER, "The alert contains an email sender."),
        (_SRC_RECIPIENT, "The alert contains an email recipient."),
        (_SRC_URL, "The alert contains a URL."),
        (_SRC_HOSTNAME, "The alert contains a hostname or mail gateway."),
    ):
        statement = _field_observation(evidence, source, text)
        if statement is not None:
            observations.append(statement)

    assessment: list[ReasoningStatement] = [
        _make_statement(
            "The reported behavior is consistent with suspicious email activity.",
            _ids_for_sources(evidence, _SRC_ALERT_TYPE, _SRC_DESCRIPTION),
        ),
        _make_statement(
            "The normalized evidence does not establish whether the message "
            "was delivered, whether the recipient interacted with it, or "
            "whether credentials were submitted."
        ),
    ]

    alternatives: list[ReasoningStatement] = [
        _make_statement("A spoofed or lookalike sender."),
        _make_statement(
            "A legitimate message incorrectly classified by the security product."
        ),
        _make_statement(
            "A benign message containing a URL that matched a detection rule."
        ),
    ]

    gaps: list[ReasoningStatement] = [
        _make_statement("No email-delivery confirmation is included."),
        _make_statement("No user-click telemetry is included."),
        _make_statement(
            "No credential-submission or authenticated-session telemetry is included."
        ),
    ]

    return _finalize(observations, assessment, alternatives, gaps, evidence)


def _build_suspicious_process_reasoning(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> AnalystReasoning:
    observations: list[ReasoningStatement] = []
    observations.extend(
        _alert_type_observation(
            evidence,
            "The normalized alert reports suspicious process activity.",
        )
    )
    for source, text in (
        (_SRC_PROCESS, "The alert contains a process name."),
        (_SRC_FILE_HASH, "The alert contains a file hash."),
        (_SRC_USERNAME, "The alert contains a username."),
        (_SRC_HOSTNAME, "The alert contains a hostname."),
        (_SRC_URL, "The alert contains a URL."),
        (_SRC_SOURCE_IP, "The alert contains a source IP."),
    ):
        statement = _field_observation(evidence, source, text)
        if statement is not None:
            observations.append(statement)

    assessment: list[ReasoningStatement] = [
        _make_statement(
            "The security source reported the process activity as suspicious.",
            _ids_for_sources(evidence, _SRC_ALERT_TYPE, _SRC_DESCRIPTION),
        ),
        _make_statement(
            "The normalized evidence does not establish whether a payload "
            "executed successfully, persistence was created, or additional "
            "hosts were affected."
        ),
    ]

    alternatives: list[ReasoningStatement] = [
        _make_statement("Authorized administrative or scripted activity."),
        _make_statement("Security testing or software-deployment activity."),
        _make_statement("A false-positive process detection."),
    ]

    gaps: list[ReasoningStatement] = [
        _make_statement(
            "No full process command line is present in normalized observables."
        ),
        _make_statement("No parent-child process relationship is included."),
        _make_statement("No endpoint containment status is included."),
        _make_statement("No confirmed network-session telemetry is included."),
    ]

    return _finalize(observations, assessment, alternatives, gaps, evidence)


def _build_unknown_reasoning(
    _alert: AlertInput,
    evidence: list[EvidenceItem],
) -> AnalystReasoning:
    observations: list[ReasoningStatement] = []
    type_refs = _ids_for_sources(evidence, _SRC_ALERT_TYPE, _SRC_DESCRIPTION)
    if type_refs:
        observations.append(
            _make_statement(
                "The normalized alert reports an alert type without a "
                "scenario-specific reasoning template.",
                type_refs,
            )
        )

    added = 0
    for source in _FALLBACK_OBSERVABLE_SOURCES:
        if added >= 3:
            break
        text = _OBSERVABLE_OBSERVATION_TEXT.get(source)
        if text is None:
            continue
        statement = _field_observation(evidence, source, text)
        if statement is not None:
            observations.append(statement)
            added += 1

    assessment_refs = _ids_for_sources(evidence, _SRC_ALERT_TYPE)
    assessment: list[ReasoningStatement] = [
        _make_statement(
            "The available normalized evidence requires analyst validation "
            "because no scenario-specific reasoning template exists for this "
            "alert type.",
            assessment_refs if assessment_refs else None,
        ),
    ]

    gaps: list[ReasoningStatement] = [
        _make_statement(
            "No scenario-specific corroborating telemetry is represented in "
            "the current normalized alert model."
        ),
    ]

    return _finalize(observations, assessment, [], gaps, evidence)


REASONING_BUILDERS: dict[
    str,
    Callable[[AlertInput, list[EvidenceItem]], AnalystReasoning],
] = {
    "ssh_failed_login": _build_ssh_reasoning,
    "phishing_email": _build_phishing_reasoning,
    "suspicious_process": _build_suspicious_process_reasoning,
}


def build_analyst_reasoning(
    alert: AlertInput,
    evidence: list[EvidenceItem],
) -> AnalystReasoning:
    """Build structured analyst reasoning from alert + extracted evidence.

    Deterministic, side-effect free, and independent of InvestigationOutput.
    Does not parse raw_event or mutate inputs.
    """
    normalized = _normalize_alert_type(alert.alert_type)
    builder = REASONING_BUILDERS.get(normalized, _build_unknown_reasoning)
    return builder(alert, evidence)
