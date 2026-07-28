# SOC Investigation Report

## Alert Overview
- **Platform:** microsoft_defender
- **Alert type:** suspicious_process
- **Vendor severity:** high
- **Confidence:** 90

## Evidence

| ID | Kind | Category | Evidence | Value | Source | Context |
|---|---|---|---|---|---|---|
| EVID-001 | metadata | Alert Metadata | Platform | microsoft_defender | alert.platform | Platform that generated the normalized alert. |
| EVID-002 | metadata | Alert Metadata | Alert type | suspicious_process | alert.alert_type | Normalized alert type. |
| EVID-003 | metadata | Alert Metadata | Vendor severity | high | alert.severity | Severity reported by the alert source. |
| EVID-004 | metadata | Alert Metadata | Description | Suspicious command-line execution detected: curl piped to bash, consistent with download-and-execute behavior. | alert.description | Description supplied with the normalized alert. |
| EVID-005 | observable | Identity | Username | jsmith | alert.observables.username | Account associated with the alert. |
| EVID-006 | observable | Host | Hostname | WORKSTATION-42 | alert.observables.hostname | Host associated with the alert. |
| EVID-007 | observable | Network | Source IP | 10.0.2.88 | alert.observables.source_ip | Source IP associated with the alert. |
| EVID-008 | observable | Indicator | URL | http://evil.example/payload.sh | alert.observables.url | URL associated with the alert. |
| EVID-009 | observable | Indicator | File hash | a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90 | alert.observables.file_hash | File hash associated with the alert. |
| EVID-010 | observable | Process | Process name | bash | alert.observables.process_name | Process name associated with the alert. |

## Analyst Reasoning

### Observations

- **OBS-001:** The normalized alert reports suspicious process activity.
  Evidence: `EVID-002`, `EVID-004`

- **OBS-002:** The alert contains a process name.
  Evidence: `EVID-010`

- **OBS-003:** The alert contains a file hash.
  Evidence: `EVID-009`

- **OBS-004:** The alert contains a username.
  Evidence: `EVID-005`

- **OBS-005:** The alert contains a hostname.
  Evidence: `EVID-006`

- **OBS-006:** The alert contains a URL.
  Evidence: `EVID-008`

- **OBS-007:** The alert contains a source IP.
  Evidence: `EVID-007`

### Assessment

- **ASM-001:** The security source reported the process activity as suspicious.
  Evidence: `EVID-002`, `EVID-004`

- **ASM-002:** The normalized evidence does not establish whether a payload executed successfully, persistence was created, or additional hosts were affected.

### Alternative Explanations

- **ALT-001:** Authorized administrative or scripted activity.

- **ALT-002:** Security testing or software-deployment activity.

- **ALT-003:** A false-positive process detection.

### Evidence Gaps

- **GAP-001:** No full process command line is present in normalized observables.

- **GAP-002:** No parent-child process relationship is included.

- **GAP-003:** No endpoint containment status is included.

- **GAP-004:** No confirmed network-session telemetry is included.

## Confidence Rationale

### Supporting Factors

- **SUP-001:** Suspicious process activity is reported in the normalized alert.
  Evidence: `EVID-002`, `EVID-004`

- **SUP-002:** A process name is identified.
  Evidence: `EVID-010`

- **SUP-003:** A host is identified.
  Evidence: `EVID-006`

- **SUP-004:** A file hash is identified.
  Evidence: `EVID-009`

- **SUP-005:** An associated username is identified.
  Evidence: `EVID-005`

- **SUP-006:** A related URL is identified.
  Evidence: `EVID-008`

- **SUP-007:** A source IP is identified.
  Evidence: `EVID-007`

### Limiting Factors

- **LIM-001:** A full process command line is not available in normalized observables.

- **LIM-002:** Parent-child process context is not available.

- **LIM-003:** Endpoint containment status is not available.

- **LIM-004:** Confirmed network-session telemetry is not available.

### Overall

The available normalized process and host identifiers provide grounding for the process investigation, while execution depth, process ancestry, network confirmation, and containment status remain unavailable. These factors provide context for the reported confidence score but do not reproduce its calculation.

## Recommended Disposition

**Disposition:** Suspicious Activity

The normalized alert identifies suspicious process activity and related endpoint or indicator context. Malicious execution and endpoint compromise cannot be confirmed from the available evidence.

**Supporting Evidence:** `EVID-002`, `EVID-004`, `EVID-010`, `EVID-006`, `EVID-009`, `EVID-005`, `EVID-008`, `EVID-007`

**Analyst Review Required:** Yes

## Executive Summary

microsoft_defender reported a suspicious_process alert (high severity). Suspicious command-line execution detected: curl piped to bash, consistent with download-and-execute behavior. Key observables: source IP 10.0.2.88, host WORKSTATION-42, user jsmith, process bash, hash a1b2c3d4e5f67890..., URL http://evil.example/payload.sh.

## Severity Assessment

Vendor severity 'high' indicates elevated priority. Suspicious process execution may indicate compromise; priority increases if the command line involves download-and-execute patterns or known malicious tooling.

## MITRE ATT&CK Mapping

- **Technique ID:** T1059
- **Technique name:** Command and Scripting Interpreter
- **Tactic:** Execution
- **Confidence:** medium
- **Rationale:** Suspicious process or command-line activity suggests scripted or interpreter-based execution; parent process and command line need validation.

## Recommended Investigation Queries

### QRadar AQL

```text
SELECT sourceip, destinationip, username, LOGSOURCETYPENAME(devicetype), starttime, category, qid FROM events WHERE sourceip = '10.0.2.88' LAST 24 HOURS
```

```text
SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime, category FROM events WHERE devicename ILIKE '%WORKSTATION-42%' LAST 7 DAYS
```

```text
SELECT username, sourceip, LOGSOURCETYPENAME(devicetype), starttime, category FROM events WHERE username ILIKE '%jsmith%' LAST 7 DAYS
```

```text
SELECT username, sourceip, LOGSOURCETYPENAME(devicetype), starttime, category FROM events WHERE UTF8(payload) ILIKE '%bash%' LAST 7 DAYS
```

```text
SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime FROM events WHERE UTF8(payload) ILIKE '%a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90%' LAST 30 DAYS
```

```text
SELECT sourceip, username, LOGSOURCETYPENAME(devicetype), starttime FROM events WHERE UTF8(payload) ILIKE '%http://evil.example/payload.sh%' LAST 7 DAYS
```

### Microsoft Sentinel KQL

```text
SecurityEvent
| where TimeGenerated > ago(24h)
| where IpAddress == "10.0.2.88" or SourceIP == "10.0.2.88"
| project TimeGenerated, Computer, Account, IpAddress, Activity
```

```text
Heartbeat
| where TimeGenerated > ago(7d)
| where Computer contains "WORKSTATION-42"
| summarize arg_max(TimeGenerated, *) by Computer
```

```text
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName contains "jsmith" or Account contains "jsmith"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName
```

```text
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName contains "bash" or ProcessCommandLine contains "bash"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
```

```text
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where SHA256 == "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90" or SHA1 == "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90" or MD5 == "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
```

```text
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemoteUrl contains "http://evil.example/payload.sh" or Url contains "http://evil.example/payload.sh"
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName
```

```text
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("curl", "wget", "powershell -enc", "bash -c")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### Microsoft Defender Advanced Hunting KQL

```text
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIP == "10.0.2.88" or InitiatingProcessRemoteIP == "10.0.2.88"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessFileName
```

```text
DeviceInfo
| where DeviceName contains "WORKSTATION-42"
| project Timestamp, DeviceName, OSPlatform, PublicIP, ExposureLevel
```

```text
DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountName contains "jsmith"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
```

```text
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName contains "bash" or ProcessCommandLine contains "bash"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```text
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90" or SHA1 == "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90" or MD5 == "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
```

```text
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "http://evil.example/payload.sh"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
```

```text
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("curl", "wget", "powershell -enc", "bash -c")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### OpenSearch / DQL

```text
source.ip: "10.0.2.88" AND @timestamp:[now-24h TO now]
```

```text
host.name: "WORKSTATION-42" AND @timestamp:[now-7d TO now]
```

```text
user.name: "jsmith" AND @timestamp:[now-7d TO now]
```

```text
process.name: "bash" AND @timestamp:[now-7d TO now]
```

```text
file.hash.sha256: "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90" OR file.hash.sha1: "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90" OR file.hash.md5: "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90"
```

```text
url.full: "*http://evil.example/payload.sh*" AND @timestamp:[now-7d TO now]
```

## Next Investigation Steps

- Collect full process tree, command line, and parent process for the flagged execution.
- Check file hash reputation and whether the binary was downloaded or dropped.
- Review network connections initiated by the process within ±15 minutes.
- Isolate the host if execution matches known malware patterns or C2 behavior.

## Detection Engineering Opportunities

- Detect curl/wget piped to shell interpreters (bash, sh, powershell).
- Alert on unsigned binaries spawning network download utilities.
- Parent-child process anomaly: office apps spawning script interpreters.

## Analysis Limitations

- Offline v1 framework — no live SIEM, EDR, or email security API queries were executed.
- MITRE mappings are deterministic templates, not ML-classified or vendor-validated attributions.
- Recommended queries are example pivots; field names and log sources vary by deployment.

---

Generated by the offline SOC Investigation Tools MCP server.
