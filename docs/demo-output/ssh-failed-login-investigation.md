# SOC Investigation Report

## Alert Overview
- **Platform:** wazuh
- **Alert type:** ssh_failed_login
- **Vendor severity:** high
- **Confidence:** 82

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
