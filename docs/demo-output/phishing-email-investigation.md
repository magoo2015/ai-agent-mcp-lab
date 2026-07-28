# SOC Investigation Report

## Alert Overview
- **Platform:** proofpoint
- **Alert type:** phishing_email
- **Vendor severity:** medium
- **Confidence:** 82

## Evidence

| ID | Kind | Category | Evidence | Value | Source | Context |
|---|---|---|---|---|---|---|
| EVID-001 | metadata | Alert Metadata | Platform | proofpoint | alert.platform | Platform that generated the normalized alert. |
| EVID-002 | metadata | Alert Metadata | Alert type | phishing_email | alert.alert_type | Normalized alert type. |
| EVID-003 | metadata | Alert Metadata | Vendor severity | medium | alert.severity | Severity reported by the alert source. |
| EVID-004 | metadata | Alert Metadata | Description | Phishing email detected with credential-harvesting URL impersonating corporate IT password reset. | alert.description | Description supplied with the normalized alert. |
| EVID-005 | observable | Host | Hostname | mail-gateway-01 | alert.observables.hostname | Host associated with the alert. |
| EVID-006 | observable | Indicator | URL | https://corp-secure-login.example/reset?token=abc123 | alert.observables.url | URL associated with the alert. |
| EVID-007 | observable | Email | Sender | it-support@corp-secure-login.example | alert.observables.sender | Email sender associated with the alert. |
| EVID-008 | observable | Email | Recipient | analyst@example.com | alert.observables.recipient | Email recipient associated with the alert. |

## Analyst Reasoning

### Observations

- **OBS-001:** The normalized alert reports suspicious email activity.
  Evidence: `EVID-002`, `EVID-004`

- **OBS-002:** The alert contains an email sender.
  Evidence: `EVID-007`

- **OBS-003:** The alert contains an email recipient.
  Evidence: `EVID-008`

- **OBS-004:** The alert contains a URL.
  Evidence: `EVID-006`

- **OBS-005:** The alert contains a hostname or mail gateway.
  Evidence: `EVID-005`

### Assessment

- **ASM-001:** The reported behavior is consistent with suspicious email activity.
  Evidence: `EVID-002`, `EVID-004`

- **ASM-002:** The normalized evidence does not establish whether the message was delivered, whether the recipient interacted with it, or whether credentials were submitted.

### Alternative Explanations

- **ALT-001:** A spoofed or lookalike sender.

- **ALT-002:** A legitimate message incorrectly classified by the security product.

- **ALT-003:** A benign message containing a URL that matched a detection rule.

### Evidence Gaps

- **GAP-001:** No email-delivery confirmation is included.

- **GAP-002:** No user-click telemetry is included.

- **GAP-003:** No credential-submission or authenticated-session telemetry is included.

## Confidence Rationale

### Supporting Factors

- **SUP-001:** Suspicious email activity is reported in the normalized alert.
  Evidence: `EVID-002`, `EVID-004`

- **SUP-002:** An email sender is identified.
  Evidence: `EVID-007`

- **SUP-003:** An email recipient is identified.
  Evidence: `EVID-008`

- **SUP-004:** A URL is identified.
  Evidence: `EVID-006`

- **SUP-005:** A related hostname is identified.
  Evidence: `EVID-005`

### Limiting Factors

- **LIM-001:** Message-delivery outcome cannot be confirmed from normalized evidence alone.

- **LIM-002:** User interaction is not available in the normalized alert.

- **LIM-003:** Credential submission cannot be confirmed from normalized evidence alone.

### Overall

The available normalized email identifiers provide grounding for the phishing investigation, while delivery, interaction, and credential outcomes remain unconfirmed. These factors provide context for the reported confidence score but do not reproduce its calculation.

## Recommended Disposition

**Disposition:** Suspicious Activity

The normalized alert contains suspicious email indicators that warrant continued analyst investigation. Delivery, user interaction, and credential impact remain unconfirmed.

**Supporting Evidence:** `EVID-002`, `EVID-004`, `EVID-007`, `EVID-008`, `EVID-006`, `EVID-005`

**Analyst Review Required:** Yes

## Executive Summary

proofpoint reported a phishing_email alert (medium severity). Phishing email detected with credential-harvesting URL impersonating corporate IT password reset. Key observables: host mail-gateway-01, URL https://corp-secure-login.example/reset?token=abc123, sender it-support@corp-secure-login.example, recipient analyst@example.com.

## Severity Assessment

Vendor severity 'medium' suggests moderate priority pending enrichment. Phishing alerts require rapid triage if the message was delivered and users may have interacted with links or attachments.

## MITRE ATT&CK Mapping

- **Technique ID:** T1566
- **Technique name:** Phishing
- **Tactic:** Initial Access
- **Confidence:** medium
- **Rationale:** Email-based lure or malicious link delivery is consistent with phishing; user interaction and downstream payload execution are not confirmed from the alert alone.

## Recommended Investigation Queries

### QRadar AQL

```text
SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime, category FROM events WHERE devicename ILIKE '%mail-gateway-01%' LAST 7 DAYS
```

```text
SELECT sourceip, username, LOGSOURCETYPENAME(devicetype), starttime FROM events WHERE UTF8(payload) ILIKE '%https://corp-secure-login.example/reset?token=abc123%' LAST 7 DAYS
```

```text
SELECT sender, recipient, subject, starttime FROM events WHERE sender ILIKE '%it-support@corp-secure-login.example%' AND recipient ILIKE '%analyst@example.com%' LAST 7 DAYS
```

### Microsoft Sentinel KQL

```text
Heartbeat
| where TimeGenerated > ago(7d)
| where Computer contains "mail-gateway-01"
| summarize arg_max(TimeGenerated, *) by Computer
```

```text
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemoteUrl contains "https://corp-secure-login.example/reset?token=abc123" or Url contains "https://corp-secure-login.example/reset?token=abc123"
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName
```

```text
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress contains "it-support@corp-secure-login.example" and RecipientEmailAddress contains "analyst@example.com"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction
```

```text
EmailUrlInfo
| where TimeGenerated > ago(7d)
| where Url contains "http"
| summarize ClickCount = count() by RecipientEmailAddress, Url
```

### Microsoft Defender Advanced Hunting KQL

```text
DeviceInfo
| where DeviceName contains "mail-gateway-01"
| project Timestamp, DeviceName, OSPlatform, PublicIP, ExposureLevel
```

```text
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "https://corp-secure-login.example/reset?token=abc123"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
```

```text
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress contains "it-support@corp-secure-login.example" and RecipientEmailAddress contains "analyst@example.com"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
```

```text
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| summarize MessageCount = count() by SenderFromAddress, RecipientEmailAddress
```

### OpenSearch / DQL

```text
host.name: "mail-gateway-01" AND @timestamp:[now-7d TO now]
```

```text
url.full: "*https://corp-secure-login.example/reset?token=abc123*" AND @timestamp:[now-7d TO now]
```

```text
email.from.address: "it-support@corp-secure-login.example" AND email.to.address: "analyst@example.com" AND @timestamp:[now-7d TO now]
```

## Next Investigation Steps

- Confirm delivery action (blocked, quarantined, delivered) and user click activity.
- Search for other recipients of the same campaign or sender domain.
- Inspect URL/domain reputation and any downloaded payloads from linked sites.
- Contact the recipient to verify whether credentials were submitted.

## Detection Engineering Opportunities

- URL reputation and newly registered domain checks at email ingress.
- Detect click-through events on flagged URLs within 24 hours of delivery.
- Impersonation detection for lookalike sender domains.

## Analysis Limitations

- Offline v1 framework — no live SIEM, EDR, or email security API queries were executed.
- MITRE mappings are deterministic templates, not ML-classified or vendor-validated attributions.
- Recommended queries are example pivots; field names and log sources vary by deployment.

---

Generated by the offline SOC Investigation Tools MCP server.
