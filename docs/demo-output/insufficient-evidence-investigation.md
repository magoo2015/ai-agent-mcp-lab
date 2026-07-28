# SOC Investigation Report

## Alert Overview
- **Platform:** lab
- **Alert type:** unclassified_alert
- **Vendor severity:** low
- **Confidence:** 39

## Evidence

| ID | Kind | Category | Evidence | Value | Source | Context |
|---|---|---|---|---|---|---|
| EVID-001 | metadata | Alert Metadata | Platform | lab | alert.platform | Platform that generated the normalized alert. |
| EVID-002 | metadata | Alert Metadata | Alert type | unclassified_alert | alert.alert_type | Normalized alert type. |
| EVID-003 | metadata | Alert Metadata | Vendor severity | low | alert.severity | Severity reported by the alert source. |
| EVID-004 | metadata | Alert Metadata | Description | Generic security alert with limited normalized context and no scenario-specific investigation template. | alert.description | Description supplied with the normalized alert. |
| EVID-005 | observable | Host | Hostname | host-01 | alert.observables.hostname | Host associated with the alert. |
| EVID-006 | observable | Network | Source IP | 198.51.100.77 | alert.observables.source_ip | Source IP associated with the alert. |

## Analyst Reasoning

### Observations

- **OBS-001:** The normalized alert reports an alert type without a scenario-specific reasoning template.
  Evidence: `EVID-002`, `EVID-004`

- **OBS-002:** The alert contains a source IP.
  Evidence: `EVID-006`

- **OBS-003:** The alert contains a hostname.
  Evidence: `EVID-005`

### Assessment

- **ASM-001:** The available normalized evidence requires analyst validation because no scenario-specific reasoning template exists for this alert type.
  Evidence: `EVID-002`

### Evidence Gaps

- **GAP-001:** No scenario-specific corroborating telemetry is represented in the current normalized alert model.

## Confidence Rationale

### Supporting Factors

- **SUP-001:** An alert type is identified in the normalized alert.
  Evidence: `EVID-002`

- **SUP-002:** A description is identified in the normalized alert.
  Evidence: `EVID-004`

- **SUP-003:** A source IP is identified in the normalized evidence.
  Evidence: `EVID-006`

- **SUP-004:** A hostname is identified.
  Evidence: `EVID-005`

### Limiting Factors

- **LIM-001:** Scenario-specific corroborating telemetry is not represented in the current normalized alert model.

- **LIM-002:** Analyst validation is required before treating the reported confidence as high-fidelity.

### Overall

The available normalized fields provide limited grounding for the investigation. Scenario-specific corroboration is unavailable, and these factors do not reproduce the numeric confidence calculation.

## Recommended Disposition

**Disposition:** Insufficient Evidence

The normalized alert does not provide enough scenario-specific evidence to support a stronger disposition.

**Analyst Review Required:** Yes

## Executive Summary

lab reported a unclassified_alert alert (low severity). Generic security alert with limited normalized context and no scenario-specific investigation template. Key observables: source IP 198.51.100.77, host host-01.

## Severity Assessment

Vendor severity 'low' is relatively low; context may change priority.

## MITRE ATT&CK Mapping

- **Technique ID:** UNKNOWN
- **Technique name:** Unmapped alert type
- **Tactic:** Unknown
- **Confidence:** low
- **Rationale:** No offline mapping exists for alert_type 'unclassified_alert'. Manual analyst review and additional context are required.

## Recommended Investigation Queries

### QRadar AQL

```text
SELECT sourceip, destinationip, username, LOGSOURCETYPENAME(devicetype), starttime, category, qid FROM events WHERE sourceip = '198.51.100.77' LAST 24 HOURS
```

```text
SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime, category FROM events WHERE devicename ILIKE '%host-01%' LAST 7 DAYS
```

### Microsoft Sentinel KQL

```text
SecurityEvent
| where TimeGenerated > ago(24h)
| where IpAddress == "198.51.100.77" or SourceIP == "198.51.100.77"
| project TimeGenerated, Computer, Account, IpAddress, Activity
```

```text
Heartbeat
| where TimeGenerated > ago(7d)
| where Computer contains "host-01"
| summarize arg_max(TimeGenerated, *) by Computer
```

### Microsoft Defender Advanced Hunting KQL

```text
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIP == "198.51.100.77" or InitiatingProcessRemoteIP == "198.51.100.77"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessFileName
```

```text
DeviceInfo
| where DeviceName contains "host-01"
| project Timestamp, DeviceName, OSPlatform, PublicIP, ExposureLevel
```

### OpenSearch / DQL

```text
source.ip: "198.51.100.77" AND @timestamp:[now-24h TO now]
```

```text
host.name: "host-01" AND @timestamp:[now-7d TO now]
```

## Next Investigation Steps

- Review alert context and validate observables against authoritative log sources.
- Escalate per organizational severity matrix if business-critical assets are involved.
- Document findings and close or convert to incident per playbook.

## Detection Engineering Opportunities

- Add correlation between this alert type and related authentication or execution events.
- Tune thresholds to reduce noise while preserving coverage for high-fidelity patterns.

## Analysis Limitations

- Offline v1 framework — no live SIEM, EDR, or email security API queries were executed.
- MITRE mappings are deterministic templates, not ML-classified or vendor-validated attributions.
- Recommended queries are example pivots; field names and log sources vary by deployment.

---

Generated by the offline SOC Investigation Tools MCP server.
