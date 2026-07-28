# SOC Investigation Report

## Alert Overview
- **Platform:** wazuh
- **Alert type:** ssh_failed_login
- **Vendor severity:** high
- **Confidence:** 82

## Evidence

| ID | Kind | Category | Evidence | Value | Source | Context |
|---|---|---|---|---|---|---|
| EVID-001 | metadata | Alert Metadata | Platform | wazuh | alert.platform | Platform that generated the normalized alert. |
| EVID-002 | metadata | Alert Metadata | Alert type | ssh_failed_login | alert.alert_type | Normalized alert type. |
| EVID-003 | metadata | Alert Metadata | Vendor severity | high | alert.severity | Severity reported by the alert source. |
| EVID-004 | metadata | Alert Metadata | Description | Multiple SSH authentication failures detected against privileged account root from external source. | alert.description | Description supplied with the normalized alert. |
| EVID-005 | observable | Identity | Username | root | alert.observables.username | Account associated with the alert. |
| EVID-006 | observable | Host | Hostname | prod-web-01 | alert.observables.hostname | Host associated with the alert. |
| EVID-007 | observable | Network | Source IP | 203.0.113.45 | alert.observables.source_ip | Source IP associated with the alert. |
| EVID-008 | observable | Network | Destination IP | 10.0.1.15 | alert.observables.destination_ip | Destination IP associated with the alert. |

## Analyst Reasoning

### Observations

- **OBS-001:** The normalized alert reports SSH authentication failures.
  Evidence: `EVID-002`, `EVID-004`

- **OBS-002:** The alert contains a source IP.
  Evidence: `EVID-007`

- **OBS-003:** The alert contains a destination IP.
  Evidence: `EVID-008`

- **OBS-004:** The alert contains a username.
  Evidence: `EVID-005`

- **OBS-005:** The alert contains a hostname.
  Evidence: `EVID-006`

### Assessment

- **ASM-001:** The reported behavior is consistent with repeated SSH authentication failures.
  Evidence: `EVID-002`, `EVID-004`

- **ASM-002:** The normalized evidence does not establish that authentication succeeded.

### Alternative Explanations

- **ALT-001:** Automated internet scanning or password guessing.

- **ALT-002:** Authorized security testing or administrative validation.

- **ALT-003:** A vendor detection triggered on repeated but unsuccessful authentication activity.

### Evidence Gaps

- **GAP-001:** No successful-authentication telemetry is included in the normalized alert.

- **GAP-002:** No post-authentication process telemetry is included.

- **GAP-003:** No lateral-movement telemetry is included.

## Confidence Rationale

### Supporting Factors

- **SUP-001:** Authentication-failure activity is reported in the normalized alert.
  Evidence: `EVID-002`, `EVID-004`

- **SUP-002:** A source IP is identified in the normalized evidence.
  Evidence: `EVID-007`

- **SUP-003:** A target username is identified.
  Evidence: `EVID-005`

- **SUP-004:** A destination host is identified.
  Evidence: `EVID-006`

- **SUP-005:** A destination IP is identified.
  Evidence: `EVID-008`

### Limiting Factors

- **LIM-001:** Successful authentication cannot be confirmed from normalized evidence alone.

- **LIM-002:** Post-authentication endpoint activity is not available in the normalized alert.

- **LIM-003:** Containment or response status is not available.

### Overall

The available normalized identifiers provide grounding for the authentication investigation, while successful-login and post-authentication telemetry remain unavailable. These factors provide context for the reported confidence score but do not reproduce its calculation.

## Recommended Disposition

**Disposition:** Suspicious Activity

The normalized alert contains authentication-failure activity and identifying network, account, or host context. Successful access or downstream compromise cannot be confirmed from the available evidence.

**Supporting Evidence:** `EVID-002`, `EVID-004`, `EVID-007`, `EVID-005`, `EVID-006`, `EVID-008`

**Analyst Review Required:** Yes

## Executive Summary

wazuh reported a ssh_failed_login alert (high severity). Multiple SSH authentication failures detected against privileged account root from external source. Key observables: source IP 203.0.113.45, destination IP 10.0.1.15, host prod-web-01, user root.

## Severity Assessment

Vendor severity 'high' indicates elevated priority. Failed SSH logins warrant review for brute-force activity, but impact depends on whether authentication eventually succeeded and which accounts were targeted.

## MITRE ATT&CK Mapping

- **Technique ID:** T1110
- **Technique name:** Brute Force
- **Tactic:** Credential Access
- **Confidence:** medium
- **Rationale:** Repeated or failed SSH authentication attempts align with credential brute-force behavior; confirm volume, targeting, and success before escalation.

## Recommended Investigation Queries

### QRadar AQL

```text
SELECT sourceip, destinationip, username, LOGSOURCETYPENAME(devicetype), starttime, category, qid FROM events WHERE sourceip = '203.0.113.45' LAST 24 HOURS
```

```text
SELECT sourceip, destinationip, destinationport, starttime FROM events WHERE destinationip = '10.0.1.15' LAST 24 HOURS
```

```text
SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime, category FROM events WHERE devicename ILIKE '%prod-web-01%' LAST 7 DAYS
```

```text
SELECT username, sourceip, LOGSOURCETYPENAME(devicetype), starttime, category FROM events WHERE username ILIKE '%root%' LAST 7 DAYS
```

```text
SELECT sourceip, username, COUNT(*) AS failures FROM events WHERE category = 1515 AND LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%' LAST 24 HOURS GROUP BY sourceip, username HAVING COUNT(*) > 10
```

### Microsoft Sentinel KQL

```text
SecurityEvent
| where TimeGenerated > ago(24h)
| where IpAddress == "203.0.113.45" or SourceIP == "203.0.113.45"
| project TimeGenerated, Computer, Account, IpAddress, Activity
```

```text
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DestinationIP == "10.0.1.15"
| summarize count() by DeviceVendor, DeviceProduct, Activity
```

```text
Heartbeat
| where TimeGenerated > ago(7d)
| where Computer contains "prod-web-01"
| summarize arg_max(TimeGenerated, *) by Computer
```

```text
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName contains "root" or Account contains "root"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName
```

```text
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailureCount = count() by IpAddress, Account
| where FailureCount > 10
```

### Microsoft Defender Advanced Hunting KQL

```text
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIP == "203.0.113.45" or InitiatingProcessRemoteIP == "203.0.113.45"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessFileName
```

```text
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIP == "10.0.1.15"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

```text
DeviceInfo
| where DeviceName contains "prod-web-01"
| project Timestamp, DeviceName, OSPlatform, PublicIP, ExposureLevel
```

```text
DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountName contains "root"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
```

```text
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType in ('RemoteInteractive', 'Network')
| where ActionType == 'LogonFailed'
| summarize FailureCount = count() by RemoteIP, AccountName
```

### OpenSearch / DQL

```text
source.ip: "203.0.113.45" AND @timestamp:[now-24h TO now]
```

```text
destination.ip: "10.0.1.15" AND @timestamp:[now-24h TO now]
```

```text
host.name: "prod-web-01" AND @timestamp:[now-7d TO now]
```

```text
user.name: "root" AND @timestamp:[now-7d TO now]
```

```text
event.action: "authentication_failure" AND event.category: "authentication" AND @timestamp:[now-24h TO now]
```

## Next Investigation Steps

- Validate whether any successful SSH logins occurred from the source IP after failures.
- Check if the targeted username is a valid local account or a common brute-force target (root, admin).
- Review firewall and geo-IP context; block or rate-limit if attack volume is sustained.
- Search for lateral movement or credential reuse if a successful login is confirmed.

## Detection Engineering Opportunities

- Threshold-based detection for repeated SSH authentication failures from a single source IP.
- Correlation rule linking failed logins to successful logins from the same source within a short window.
- Geo-velocity or impossible-travel check if successful authentication follows brute-force patterns.

## Analysis Limitations

- Offline v1 framework — no live SIEM, EDR, or email security API queries were executed.
- MITRE mappings are deterministic templates, not ML-classified or vendor-validated attributions.
- Recommended queries are example pivots; field names and log sources vary by deployment.

---

Generated by the offline SOC Investigation Tools MCP server.
