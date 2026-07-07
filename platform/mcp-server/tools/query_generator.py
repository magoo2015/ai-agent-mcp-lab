from schemas.alert_schema import AlertInput


def _non_empty(*values: str | None) -> list[str]:
    return [v for v in values if v]


def generate_queries(alert: AlertInput) -> dict[str, list[str]]:
    """
    Generate offline example investigation pivots for common SIEM/EDR query languages.

    These are illustrative templates for analyst handoff — not guaranteed production-ready.
    """
    obs = alert.observables
    alert_type = alert.alert_type.strip().lower().replace("-", "_").replace(" ", "_")

    queries: dict[str, list[str]] = {
        "qradar_aql": [],
        "sentinel_kql": [],
        "defender_advanced_hunting_kql": [],
        "opensearch_dql": [],
    }

    if obs.source_ip:
        queries["qradar_aql"].append(
            f"SELECT sourceip, destinationip, username, LOGSOURCETYPENAME(devicetype), "
            f"starttime, category, qid FROM events "
            f"WHERE sourceip = '{obs.source_ip}' LAST 24 HOURS"
        )
        queries["sentinel_kql"].append(
            f"SecurityEvent\n"
            f"| where TimeGenerated > ago(24h)\n"
            f"| where IpAddress == \"{obs.source_ip}\" or SourceIP == \"{obs.source_ip}\"\n"
            f"| project TimeGenerated, Computer, Account, IpAddress, Activity"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceNetworkEvents\n"
            f"| where Timestamp > ago(24h)\n"
            f"| where RemoteIP == \"{obs.source_ip}\" or InitiatingProcessRemoteIP == \"{obs.source_ip}\"\n"
            f"| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessFileName"
        )
        queries["opensearch_dql"].append(
            f'source.ip: "{obs.source_ip}" AND @timestamp:[now-24h TO now]'
        )

    if obs.destination_ip:
        queries["qradar_aql"].append(
            f"SELECT sourceip, destinationip, destinationport, starttime "
            f"FROM events WHERE destinationip = '{obs.destination_ip}' LAST 24 HOURS"
        )
        queries["sentinel_kql"].append(
            f"CommonSecurityLog\n"
            f"| where TimeGenerated > ago(24h)\n"
            f"| where DestinationIP == \"{obs.destination_ip}\"\n"
            f"| summarize count() by DeviceVendor, DeviceProduct, Activity"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceNetworkEvents\n"
            f"| where Timestamp > ago(24h)\n"
            f"| where RemoteIP == \"{obs.destination_ip}\"\n"
            f"| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName"
        )
        queries["opensearch_dql"].append(
            f'destination.ip: "{obs.destination_ip}" AND @timestamp:[now-24h TO now]'
        )

    if obs.hostname:
        queries["qradar_aql"].append(
            f"SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime, category "
            f"FROM events WHERE devicename ILIKE '%{obs.hostname}%' LAST 7 DAYS"
        )
        queries["sentinel_kql"].append(
            f"Heartbeat\n"
            f"| where TimeGenerated > ago(7d)\n"
            f"| where Computer contains \"{obs.hostname}\"\n"
            f"| summarize arg_max(TimeGenerated, *) by Computer"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceInfo\n"
            f"| where DeviceName contains \"{obs.hostname}\"\n"
            f"| project Timestamp, DeviceName, OSPlatform, PublicIP, ExposureLevel"
        )
        queries["opensearch_dql"].append(
            f'host.name: "{obs.hostname}" AND @timestamp:[now-7d TO now]'
        )

    if obs.username:
        queries["qradar_aql"].append(
            f"SELECT username, sourceip, LOGSOURCETYPENAME(devicetype), starttime, category "
            f"FROM events WHERE username ILIKE '%{obs.username}%' LAST 7 DAYS"
        )
        queries["sentinel_kql"].append(
            f"SigninLogs\n"
            f"| where TimeGenerated > ago(7d)\n"
            f"| where UserPrincipalName contains \"{obs.username}\" or Account contains \"{obs.username}\"\n"
            f"| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceLogonEvents\n"
            f"| where Timestamp > ago(7d)\n"
            f"| where AccountName contains \"{obs.username}\"\n"
            f"| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP"
        )
        queries["opensearch_dql"].append(
            f'user.name: "{obs.username}" AND @timestamp:[now-7d TO now]'
        )

    if obs.process_name:
        queries["qradar_aql"].append(
            f"SELECT username, sourceip, LOGSOURCETYPENAME(devicetype), starttime, category "
            f"FROM events WHERE UTF8(payload) ILIKE '%{obs.process_name}%' LAST 7 DAYS"
        )
        queries["sentinel_kql"].append(
            f"DeviceProcessEvents\n"
            f"| where TimeGenerated > ago(7d)\n"
            f"| where FileName contains \"{obs.process_name}\" or ProcessCommandLine contains \"{obs.process_name}\"\n"
            f"| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceProcessEvents\n"
            f"| where Timestamp > ago(7d)\n"
            f"| where FileName contains \"{obs.process_name}\" or ProcessCommandLine contains \"{obs.process_name}\"\n"
            f"| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName"
        )
        queries["opensearch_dql"].append(
            f'process.name: "{obs.process_name}" AND @timestamp:[now-7d TO now]'
        )

    if obs.file_hash:
        queries["qradar_aql"].append(
            f"SELECT LOGSOURCETYPENAME(devicetype), sourceip, username, starttime "
            f"FROM events WHERE UTF8(payload) ILIKE '%{obs.file_hash}%' LAST 30 DAYS"
        )
        queries["sentinel_kql"].append(
            f"DeviceFileEvents\n"
            f"| where TimeGenerated > ago(30d)\n"
            f"| where SHA256 == \"{obs.file_hash}\" or SHA1 == \"{obs.file_hash}\" or MD5 == \"{obs.file_hash}\"\n"
            f"| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceFileEvents\n"
            f"| where Timestamp > ago(30d)\n"
            f"| where SHA256 == \"{obs.file_hash}\" or SHA1 == \"{obs.file_hash}\" or MD5 == \"{obs.file_hash}\"\n"
            f"| project Timestamp, DeviceName, FileName, FolderPath, SHA256"
        )
        queries["opensearch_dql"].append(
            f'file.hash.sha256: "{obs.file_hash}" OR file.hash.sha1: "{obs.file_hash}" OR file.hash.md5: "{obs.file_hash}"'
        )

    if obs.url:
        queries["qradar_aql"].append(
            f"SELECT sourceip, username, LOGSOURCETYPENAME(devicetype), starttime "
            f"FROM events WHERE UTF8(payload) ILIKE '%{obs.url}%' LAST 7 DAYS"
        )
        queries["sentinel_kql"].append(
            f"DeviceNetworkEvents\n"
            f"| where TimeGenerated > ago(7d)\n"
            f"| where RemoteUrl contains \"{obs.url}\" or Url contains \"{obs.url}\"\n"
            f"| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"DeviceNetworkEvents\n"
            f"| where Timestamp > ago(7d)\n"
            f"| where RemoteUrl contains \"{obs.url}\"\n"
            f"| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"
        )
        queries["opensearch_dql"].append(
            f'url.full: "*{obs.url}*" AND @timestamp:[now-7d TO now]'
        )

    if obs.sender or obs.recipient:
        sender = obs.sender or "*"
        recipient = obs.recipient or "*"
        queries["qradar_aql"].append(
            f"SELECT sender, recipient, subject, starttime "
            f"FROM events WHERE sender ILIKE '%{sender}%' AND recipient ILIKE '%{recipient}%' LAST 7 DAYS"
        )
        queries["sentinel_kql"].append(
            f"EmailEvents\n"
            f"| where TimeGenerated > ago(7d)\n"
            f"| where SenderFromAddress contains \"{sender}\" and RecipientEmailAddress contains \"{recipient}\"\n"
            f"| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction"
        )
        queries["defender_advanced_hunting_kql"].append(
            f"EmailEvents\n"
            f"| where Timestamp > ago(7d)\n"
            f"| where SenderFromAddress contains \"{sender}\" and RecipientEmailAddress contains \"{recipient}\"\n"
            f"| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes"
        )
        queries["opensearch_dql"].append(
            f'email.from.address: "{sender}" AND email.to.address: "{recipient}" AND @timestamp:[now-7d TO now]'
        )

    # Alert-type-specific pivots when observables are sparse.
    if alert_type == "ssh_failed_login":
        queries["qradar_aql"].append(
            "SELECT sourceip, username, COUNT(*) AS failures "
            "FROM events WHERE category = 1515 AND LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%' "
            "LAST 24 HOURS GROUP BY sourceip, username HAVING COUNT(*) > 10"
        )
        queries["sentinel_kql"].append(
            "SecurityEvent\n"
            "| where TimeGenerated > ago(24h)\n"
            "| where EventID == 4625\n"
            "| summarize FailureCount = count() by IpAddress, Account\n"
            "| where FailureCount > 10"
        )
        queries["defender_advanced_hunting_kql"].append(
            "DeviceLogonEvents\n"
            "| where Timestamp > ago(24h)\n"
            "| where LogonType in ('RemoteInteractive', 'Network')\n"
            "| where ActionType == 'LogonFailed'\n"
            "| summarize FailureCount = count() by RemoteIP, AccountName"
        )
        queries["opensearch_dql"].append(
            'event.action: "authentication_failure" AND event.category: "authentication" AND @timestamp:[now-24h TO now]'
        )

    if alert_type == "suspicious_process":
        queries["sentinel_kql"].append(
            "DeviceProcessEvents\n"
            "| where TimeGenerated > ago(24h)\n"
            "| where ProcessCommandLine has_any (\"curl\", \"wget\", \"powershell -enc\", \"bash -c\")\n"
            "| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName"
        )
        queries["defender_advanced_hunting_kql"].append(
            "DeviceProcessEvents\n"
            "| where Timestamp > ago(24h)\n"
            "| where ProcessCommandLine has_any (\"curl\", \"wget\", \"powershell -enc\", \"bash -c\")\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName"
        )

    if alert_type == "phishing_email":
        queries["sentinel_kql"].append(
            "EmailUrlInfo\n"
            "| where TimeGenerated > ago(7d)\n"
            "| where Url contains \"http\"\n"
            "| summarize ClickCount = count() by RecipientEmailAddress, Url"
        )
        queries["defender_advanced_hunting_kql"].append(
            "EmailEvents\n"
            "| where Timestamp > ago(7d)\n"
            "| where ThreatTypes has \"Phish\"\n"
            "| summarize MessageCount = count() by SenderFromAddress, RecipientEmailAddress"
        )

    # Drop empty query lists for cleaner output.
    return {platform: examples for platform, examples in queries.items() if examples}
