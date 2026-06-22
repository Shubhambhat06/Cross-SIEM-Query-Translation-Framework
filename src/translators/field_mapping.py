"""
Field Mapping — canonical IR field names → per-SIEM field names.

Every SIEM uses different field names for the same concept.
This file is the single source of truth for all field translations.

Canonical field names are defined by the IR schema (src/ir/schema.py).
Each SIEM translator calls `resolve(field, platform)` to get the correct name.

Place at: src/translators/field_mapping.py
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# Master field mapping table
# canonical_name → { platform: platform_field_name }
# ─────────────────────────────────────────────────────────────────────────────

FIELD_MAP: dict[str, dict[str, str]] = {
    # ── Identity / Authentication ─────────────────────────────────────────
    "user": {
        "splunk":   "user",
        "qradar":   "username",
        "elastic":  "user.name",
        "sentinel": "Account",
        "wazuh":    "dstuser",
    },
    "src_ip": {
        "splunk":   "src_ip",
        "qradar":   "sourceip",
        "elastic":  "source.ip",
        "sentinel": "IpAddress",
        "wazuh":    "srcip",
    },
    "dest_ip": {
        "splunk":   "dest_ip",
        "qradar":   "destinationip",
        "elastic":  "destination.ip",
        "sentinel": "DestinationIp",
        "wazuh":    "dstip",
    },
    "src_port": {
        "splunk":   "src_port",
        "qradar":   "sourceport",
        "elastic":  "source.port",
        "sentinel": "SourcePort",
        "wazuh":    "srcport",
    },
    "dest_port": {
        "splunk":   "dest_port",
        "qradar":   "destinationport",
        "elastic":  "destination.port",
        "sentinel": "DestinationPort",
        "wazuh":    "dstport",
    },
    "hostname": {
        "splunk":   "host",
        "qradar":   "logsourcename",
        "elastic":  "host.name",
        "sentinel": "Computer",
        "wazuh":    "hostname",
    },
    "host": {
        "splunk":   "host",
        "qradar":   "logsourcename",
        "elastic":  "host.name",
        "sentinel": "Computer",
        "wazuh":    "hostname",
    },

    # ── Event metadata ────────────────────────────────────────────────────
    "event_id": {
        "splunk":   "EventCode",
        "qradar":   "eventid",
        "elastic":  "event.code",
        "sentinel": "EventID",
        "wazuh":    "id",
    },
    "event_type": {
        "splunk":   "source",
        "qradar":   "QIDNAME(qid)",
        "elastic":  "event.category",
        "sentinel": "EventID",
        "wazuh":    "category",
    },
    "status": {
        "splunk":   "status",
        "qradar":   "eventdirection",
        "elastic":  "event.outcome",
        "sentinel": "Status",
        "wazuh":    "status",
    },
    "action": {
        "splunk":   "action",
        "qradar":   "eventdirection",
        "elastic":  "event.action",
        "sentinel": "Activity",
        "wazuh":    "action",
    },
    "category": {
        "splunk":   "category",
        "qradar":   "categoryname",
        "elastic":  "event.category",
        "sentinel": "EventID",
        "wazuh":    "group",
    },
    "severity": {
        "splunk":   "severity",
        "qradar":   "severity",
        "elastic":  "event.severity",
        "sentinel": "Level",
        "wazuh":    "level",
    },
    "timestamp": {
        "splunk":   "_time",
        "qradar":   "starttime",
        "elastic":  "@timestamp",
        "sentinel": "TimeGenerated",
        "wazuh":    "timestamp",
    },
    "_time": {
        "splunk":   "_time",
        "qradar":   "starttime",
        "elastic":  "@timestamp",
        "sentinel": "TimeGenerated",
        "wazuh":    "timestamp",
    },

    # ── Process ───────────────────────────────────────────────────────────
    "process_name": {
        "splunk":   "process_name",
        "qradar":   "filename",
        "elastic":  "process.name",
        "sentinel": "Process",
        "wazuh":    "program_name",
    },
    "process_id": {
        "splunk":   "pid",
        "qradar":   "pid",
        "elastic":  "process.pid",
        "sentinel": "ProcessId",
        "wazuh":    "pid",
    },
    "parent_process": {
        "splunk":   "parent_process",
        "qradar":   "parentpid",
        "elastic":  "process.parent.name",
        "sentinel": "ParentProcessName",
        "wazuh":    "ppid",
    },
    "command_line": {
        "splunk":   "CommandLine",
        "qradar":   "commandline",
        "elastic":  "process.command_line",
        "sentinel": "CommandLine",
        "wazuh":    "cmdline",
    },
    "target_process": {
        "splunk":   "TargetProcessName",
        "qradar":   "targetfilename",
        "elastic":  "Target.process.name",
        "sentinel": "TargetProcessName",
        "wazuh":    "target_process",
    },
    "src_process": {
        "splunk":   "process_name",
        "qradar":   "filename",
        "elastic":  "process.name",
        "sentinel": "InitiatingProcessFileName",
        "wazuh":    "program_name",
    },

    # ── Network ───────────────────────────────────────────────────────────
    "protocol": {
        "splunk":   "protocol",
        "qradar":   "protocolid",
        "elastic":  "network.transport",
        "sentinel": "Protocol",
        "wazuh":    "protocol",
    },
    "direction": {
        "splunk":   "direction",
        "qradar":   "eventdirection",
        "elastic":  "network.direction",
        "sentinel": "CommunicationDirection",
        "wazuh":    "direction",
    },
    "bytes_out": {
        "splunk":   "bytes_out",
        "qradar":   "destinationbytes",
        "elastic":  "destination.bytes",
        "sentinel": "SentBytes",
        "wazuh":    "bytes_out",
    },
    "bytes_in": {
        "splunk":   "bytes_in",
        "qradar":   "sourcebytes",
        "elastic":  "source.bytes",
        "sentinel": "ReceivedBytes",
        "wazuh":    "bytes_in",
    },

    # ── File ──────────────────────────────────────────────────────────────
    "file_name": {
        "splunk":   "file_name",
        "qradar":   "filename",
        "elastic":  "file.name",
        "sentinel": "FileName",
        "wazuh":    "file",
    },
    "file_path": {
        "splunk":   "file_path",
        "qradar":   "filepath",
        "elastic":  "file.path",
        "sentinel": "FilePath",
        "wazuh":    "path",
    },
    "file_hash": {
        "splunk":   "file_hash",
        "qradar":   "filehash",
        "elastic":  "file.hash.sha256",
        "sentinel": "FileHash",
        "wazuh":    "md5",
    },

    # ── DNS ───────────────────────────────────────────────────────────────
    "query_domain": {
        "splunk":   "query",
        "qradar":   "domainname",
        "elastic":  "dns.question.name",
        "sentinel": "Name",
        "wazuh":    "dns.question.name",
    },
    "response_size": {
        "splunk":   "answer_count",
        "qradar":   "payloadlength",
        "elastic":  "dns.response_code",
        "sentinel": "ResponseCode",
        "wazuh":    "dns.response_size",
    },

    # ── Auth-specific ─────────────────────────────────────────────────────
    "auth_type": {
        "splunk":   "LogonType",
        "qradar":   "authtype",
        "elastic":  "winlog.logon.type",
        "sentinel": "LogonType",
        "wazuh":    "auth_type",
    },
    "domain": {
        "splunk":   "user_domain",
        "qradar":   "domain",
        "elastic":  "user.domain",
        "sentinel": "SubjectDomainName",
        "wazuh":    "domain",
    },
    
    "country": {
        "splunk":   "country",
        "qradar":   "geographic",
        "elastic":  "source.geo.country_name",
        "sentinel": "LocationDetails",
        "wazuh":    "geoip.country_name",
    },

    # ── Aggregation output aliases ────────────────────────────────────────
    "attempt_count": {
        "splunk":   "attempt_count",
        "qradar":   "attempt_count",
        "elastic":  "attempt_count",
        "sentinel": "attempt_count",
        "wazuh":    "frequency",
    },
    "event_count": {
        "splunk":   "event_count",
        "qradar":   "event_count",
        "elastic":  "event_count",
        "sentinel": "event_count",
        "wazuh":    "frequency",
    },
    "unique_targets": {
        "splunk":   "unique_targets",
        "qradar":   "unique_targets",
        "elastic":  "unique_targets",
        "sentinel": "unique_targets",
        "wazuh":    "frequency",
    },

    # ── Task / Scheduled jobs ─────────────────────────────────────────────
    "task_name": {
        "splunk":   "TaskName",
        "qradar":   "taskname",
        "elastic":  "winlog.event_data.TaskName",
        "sentinel": "TaskName",
        "wazuh":    "task_name",
    },
}

# ── Platforms ─────────────────────────────────────────────────────────────────
PLATFORMS = {"splunk", "qradar", "elastic", "sentinel", "wazuh"}


def resolve(canonical: str, platform: str) -> str:
    """
    Resolve a canonical field name to its platform-specific equivalent.

    Args:
        canonical: Canonical field name from IR schema.
        platform:  Target SIEM platform (splunk/qradar/elastic/sentinel/wazuh).

    Returns:
        Platform-specific field name, or the canonical name as fallback.
    """
    platform = platform.lower().strip()
    entry = FIELD_MAP.get(canonical)
    if entry is None:
        return canonical          # unknown field — pass through as-is
    return entry.get(platform, canonical)


def resolve_all(fields: list[str], platform: str) -> list[str]:
    """
    Resolve a list of canonical field names for a given platform.

    Args:
        fields:   List of canonical field names.
        platform: Target SIEM platform.

    Returns:
        List of platform-specific field names.
    """
    return [resolve(f, platform) for f in fields]


def get_canonical_fields() -> list[str]:
    """Return all known canonical field names."""
    return list(FIELD_MAP.keys())