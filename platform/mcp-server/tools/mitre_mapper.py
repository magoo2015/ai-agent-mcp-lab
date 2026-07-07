from schemas.alert_schema import AlertInput, MitreMapping

# Deterministic alert_type → MITRE mappings for offline v1.
# Confidence is intentionally conservative; callers should not overstate certainty.
_ALERT_TYPE_MAPPINGS: dict[str, dict[str, str]] = {
    "ssh_failed_login": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "medium",
        "rationale": (
            "Repeated or failed SSH authentication attempts align with credential "
            "brute-force behavior; confirm volume, targeting, and success before escalation."
        ),
    },
    "suspicious_process": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "confidence": "medium",
        "rationale": (
            "Suspicious process or command-line activity suggests scripted or "
            "interpreter-based execution; parent process and command line need validation."
        ),
    },
    "phishing_email": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "confidence": "medium",
        "rationale": (
            "Email-based lure or malicious link delivery is consistent with phishing; "
            "user interaction and downstream payload execution are not confirmed from the alert alone."
        ),
    },
    "dlp_alert": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "confidence": "low",
        "rationale": (
            "DLP alerts may indicate policy violations or benign transfers; mapping to "
            "exfiltration over C2 is speculative without network, endpoint, and data-classification context."
        ),
    },
    "aws_iam_change": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "confidence": "medium",
        "rationale": (
            "IAM or account permission changes can support persistence or privilege expansion; "
            "change ticket, actor identity, and blast radius require verification."
        ),
    },
}


def map_alert_to_mitre(alert: AlertInput) -> list[MitreMapping]:
    """Return deterministic MITRE mappings for a normalized alert type."""
    normalized_type = alert.alert_type.strip().lower().replace("-", "_").replace(" ", "_")
    mapping = _ALERT_TYPE_MAPPINGS.get(normalized_type)

    if mapping is None:
        return [
            MitreMapping(
                technique_id="UNKNOWN",
                technique_name="Unmapped alert type",
                tactic="Unknown",
                confidence="low",
                rationale=(
                    f"No offline mapping exists for alert_type '{alert.alert_type}'. "
                    "Manual analyst review and additional context are required."
                ),
            )
        ]

    return [MitreMapping(**mapping)]
