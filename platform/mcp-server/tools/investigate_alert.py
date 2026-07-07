from schemas.alert_schema import AlertInput, InvestigationOutput
from tools.mitre_mapper import map_alert_to_mitre
from tools.query_generator import generate_queries

_SEVERITY_RANK = {
    "informational": 1,
    "info": 1,
    "low": 2,
    "medium": 3,
    "moderate": 3,
    "high": 4,
    "critical": 5,
    "severe": 5,
}

_DETECTION_OPPORTUNITIES: dict[str, list[str]] = {
    "ssh_failed_login": [
        "Threshold-based detection for repeated SSH authentication failures from a single source IP.",
        "Correlation rule linking failed logins to successful logins from the same source within a short window.",
        "Geo-velocity or impossible-travel check if successful authentication follows brute-force patterns.",
    ],
    "suspicious_process": [
        "Detect curl/wget piped to shell interpreters (bash, sh, powershell).",
        "Alert on unsigned binaries spawning network download utilities.",
        "Parent-child process anomaly: office apps spawning script interpreters.",
    ],
    "phishing_email": [
        "URL reputation and newly registered domain checks at email ingress.",
        "Detect click-through events on flagged URLs within 24 hours of delivery.",
        "Impersonation detection for lookalike sender domains.",
    ],
    "dlp_alert": [
        "Combine DLP hits with unusual egress volume or rare destination hosts.",
        "Alert when sensitive label data is accessed by accounts with recent auth anomalies.",
    ],
    "aws_iam_change": [
        "Detect creation of access keys on privileged IAM users.",
        "Alert on policy attachments granting AdminAccess outside change windows.",
        "Correlate IAM changes with console logins from new geographies.",
    ],
}

_NEXT_STEPS: dict[str, list[str]] = {
    "ssh_failed_login": [
        "Validate whether any successful SSH logins occurred from the source IP after failures.",
        "Check if the targeted username is a valid local account or a common brute-force target (root, admin).",
        "Review firewall and geo-IP context; block or rate-limit if attack volume is sustained.",
        "Search for lateral movement or credential reuse if a successful login is confirmed.",
    ],
    "suspicious_process": [
        "Collect full process tree, command line, and parent process for the flagged execution.",
        "Check file hash reputation and whether the binary was downloaded or dropped.",
        "Review network connections initiated by the process within ±15 minutes.",
        "Isolate the host if execution matches known malware patterns or C2 behavior.",
    ],
    "phishing_email": [
        "Confirm delivery action (blocked, quarantined, delivered) and user click activity.",
        "Search for other recipients of the same campaign or sender domain.",
        "Inspect URL/domain reputation and any downloaded payloads from linked sites.",
        "Contact the recipient to verify whether credentials were submitted.",
    ],
    "dlp_alert": [
        "Validate data classification, volume, and business justification with data owner.",
        "Review destination (email, cloud storage, USB) and user role appropriateness.",
        "Correlate with endpoint and network logs before treating as exfiltration.",
    ],
    "aws_iam_change": [
        "Identify the actor (user, role, assumed-role session) and change ticket.",
        "Review CloudTrail for related API calls (CreateAccessKey, AttachUserPolicy, etc.).",
        "Assess blast radius: new permissions, affected resources, and recent API activity.",
        "Rotate credentials if unauthorized change is suspected.",
    ],
}


def _normalize_alert_type(alert_type: str) -> str:
    return alert_type.strip().lower().replace("-", "_").replace(" ", "_")


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.strip().lower(), 3)


def _build_summary(alert: AlertInput) -> str:
    obs = alert.observables
    parts = [
        f"{alert.platform} reported a {alert.alert_type} alert ({alert.severity} severity).",
        alert.description,
    ]
    observable_bits: list[str] = []
    if obs.source_ip:
        observable_bits.append(f"source IP {obs.source_ip}")
    if obs.destination_ip:
        observable_bits.append(f"destination IP {obs.destination_ip}")
    if obs.hostname:
        observable_bits.append(f"host {obs.hostname}")
    if obs.username:
        observable_bits.append(f"user {obs.username}")
    if obs.process_name:
        observable_bits.append(f"process {obs.process_name}")
    if obs.file_hash:
        observable_bits.append(f"hash {obs.file_hash[:16]}...")
    if obs.url:
        observable_bits.append(f"URL {obs.url}")
    if obs.sender:
        observable_bits.append(f"sender {obs.sender}")
    if obs.recipient:
        observable_bits.append(f"recipient {obs.recipient}")

    if observable_bits:
        parts.append("Key observables: " + ", ".join(observable_bits) + ".")
    return " ".join(parts)


def _assess_severity(alert: AlertInput) -> str:
    rank = _severity_rank(alert.severity)
    normalized = _normalize_alert_type(alert.alert_type)

    if rank >= 4:
        base = f"Vendor severity '{alert.severity}' indicates elevated priority."
    elif rank == 3:
        base = f"Vendor severity '{alert.severity}' suggests moderate priority pending enrichment."
    else:
        base = f"Vendor severity '{alert.severity}' is relatively low; context may change priority."

    if normalized == "ssh_failed_login":
        return (
            f"{base} Failed SSH logins warrant review for brute-force activity, but impact depends "
            "on whether authentication eventually succeeded and which accounts were targeted."
        )
    if normalized == "suspicious_process":
        return (
            f"{base} Suspicious process execution may indicate compromise; priority increases if "
            "the command line involves download-and-execute patterns or known malicious tooling."
        )
    if normalized == "phishing_email":
        return (
            f"{base} Phishing alerts require rapid triage if the message was delivered and users "
            "may have interacted with links or attachments."
        )
    return base


def _compute_confidence(alert: AlertInput, mitre_mappings: list) -> int:
    """Derive an overall confidence score (0-100) from mapping quality and observable richness."""
    score = 40

    normalized = _normalize_alert_type(alert.alert_type)
    if normalized in {"ssh_failed_login", "suspicious_process", "phishing_email", "aws_iam_change"}:
        score += 20
    elif normalized == "dlp_alert":
        score += 5

    # Count populated observables.
    obs = alert.observables
    populated = sum(
        1
        for value in (
            obs.source_ip,
            obs.destination_ip,
            obs.hostname,
            obs.username,
            obs.process_name,
            obs.file_hash,
            obs.url,
            obs.sender,
            obs.recipient,
        )
        if value
    )
    score += min(populated * 4, 24)

    if alert.raw_event:
        score += 6

    if mitre_mappings and mitre_mappings[0].confidence == "low":
        score -= 15
    elif mitre_mappings and mitre_mappings[0].confidence == "high":
        score += 10

    return max(0, min(100, score))


def _limitations(alert: AlertInput) -> list[str]:
    limits = [
        "Offline v1 framework — no live SIEM, EDR, or email security API queries were executed.",
        "MITRE mappings are deterministic templates, not ML-classified or vendor-validated attributions.",
        "Recommended queries are example pivots; field names and log sources vary by deployment.",
    ]
    if not alert.raw_event:
        limits.append("No raw_event payload provided; analysis is based on normalized fields only.")
    obs = alert.observables
    if not any(
        (
            obs.source_ip,
            obs.destination_ip,
            obs.hostname,
            obs.username,
            obs.process_name,
            obs.file_hash,
            obs.url,
            obs.sender,
            obs.recipient,
        )
    ):
        limits.append("Sparse observables limit pivot quality and confidence.")
    return limits


def investigate_alert(alert: AlertInput) -> InvestigationOutput:
    """
    Accept a structured alert and return an analyst-ready investigation package.

    Designed for MCP-style tool invocation; v1 runs entirely offline with sample data.
    """
    normalized = _normalize_alert_type(alert.alert_type)
    mitre = map_alert_to_mitre(alert)
    queries = generate_queries(alert)

    next_steps = list(_NEXT_STEPS.get(normalized, [
        "Review alert context and validate observables against authoritative log sources.",
        "Escalate per organizational severity matrix if business-critical assets are involved.",
        "Document findings and close or convert to incident per playbook.",
    ]))

    detection_opportunities = list(_DETECTION_OPPORTUNITIES.get(normalized, [
        "Add correlation between this alert type and related authentication or execution events.",
        "Tune thresholds to reduce noise while preserving coverage for high-fidelity patterns.",
    ]))

    return InvestigationOutput(
        summary=_build_summary(alert),
        severity_assessment=_assess_severity(alert),
        mitre=mitre,
        recommended_queries=queries,
        next_steps=next_steps,
        detection_opportunities=detection_opportunities,
        confidence=_compute_confidence(alert, mitre),
        limitations=_limitations(alert),
    )
