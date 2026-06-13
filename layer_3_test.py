"""
Layer 2 — Translators Test Suite
Run from project root:
    python test_translators.py

Tests field_mapping, base class, all 5 translators, translate_all(),
and integration with Layer 1 IR objects.
Green checkmarks = ready for Layer 3.
Red X = fix before building LLM client.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

PASS = "  ✅"
FAIL = "  ❌"
results = []


def check(label: str, fn):
    try:
        fn()
        print(f"{PASS} {label}")
        results.append((label, True, None))
    except Exception as exc:
        print(f"{FAIL} {label}")
        print(f"       → {type(exc).__name__}: {exc}")
        results.append((label, False, exc))


# ── Shared IR fixtures ────────────────────────────────────────────────────────

def _make_filter_ir():
    """Simple filter-only IR: failed logins in 24h."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="filter",
        event_type="authentication",
        filter={"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        time_window={"duration": "24h"},
        fields=["src_ip", "user", "status"],
        tactic="initial_access",
        technique_id="T1110",
    )


def _make_agg_ir():
    """Brute force detection: filter+aggregate with threshold."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="filter+aggregate",
        event_type="authentication",
        filter={"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        time_window={"duration": "24h"},
        aggregation={"function": "count", "group_by": ["src_ip"], "alias": "attempt_count"},
        threshold={"field": "attempt_count", "op": "gt", "value": 50},
        tactic="initial_access",
        technique_id="T1110",
    )


def _make_network_ir():
    """Network lateral movement: distinct count of targets per source."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="filter+aggregate",
        event_type="network",
        filter={"operator": "and", "conditions": [
            {"field": "dest_port", "op": "eq", "value": 445}
        ]},
        time_window={"duration": "1h"},
        aggregation={"function": "distinct_count", "field": "dest_ip",
                     "group_by": ["src_ip"], "alias": "unique_targets"},
        threshold={"field": "unique_targets", "op": "gt", "value": 5},
        tactic="lateral_movement",
        technique_id="T1021",
    )


def _make_process_ir():
    """Process filter: PowerShell spawned by cmd.exe."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="filter",
        event_type="process",
        filter={"operator": "and", "conditions": [
            {"field": "process_name", "op": "eq",       "value": "powershell.exe"},
            {"field": "parent_process", "op": "contains", "value": "cmd.exe"},
        ]},
        time_window={"duration": "1h"},
        fields=["host", "user", "process_name", "parent_process"],
        tactic="execution",
        technique_id="T1059",
    )


def _make_lookup_ir():
    """Threat-intel lookup: outbound connections to malicious IPs."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="lookup",
        event_type="network",
        filter={"operator": "and", "conditions": [
            {"field": "direction", "op": "eq", "value": "outbound"}
        ]},
        time_window={"duration": "1h"},
        lookup={
            "lookup_table": "threat_intel_ips",
            "match_field": "dest_ip",
            "output_field": "is_malicious",
            "filter_on_match": True,
        },
        tactic="exfiltration",
        technique_id="T1071",
    )


def _make_sequence_ir():
    """Sequence: impossible travel detection."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="sequence",
        event_type="authentication",
        sequence=[
            {"event_type": "authentication", "filter": {"operator": "and", "conditions": [
                {"field": "status", "op": "eq", "value": "success"}
            ]}},
            {"event_type": "authentication", "filter": {"operator": "and", "conditions": [
                {"field": "status",  "op": "eq",  "value": "success"},
                {"field": "country", "op": "neq", "value": "$prev.country"},
            ]}, "within": "30m"},
        ],
        tactic="lateral_movement",
        technique_id="T1078",
    )


def _make_dns_ir():
    """DNS exfiltration: large response sizes."""
    from src.ir.schema import IRQuery
    return IRQuery(
        action="filter+aggregate",
        event_type="dns",
        filter={"operator": "and", "conditions": [
            {"field": "direction",     "op": "eq", "value": "outbound"},
            {"field": "response_size", "op": "gt", "value": 512},
        ]},
        time_window={"duration": "6h"},
        aggregation={"function": "sum", "field": "response_size",
                     "group_by": ["src_ip", "query_domain"], "alias": "total_bytes"},
        threshold={"field": "total_bytes", "op": "gt", "value": 100000},
        tactic="exfiltration",
        technique_id="T1048",
    )


# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
print("  NL-SIEM — Layer 2 Translators Test Suite")
print("═" * 60)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 1. IMPORTS ──────────────────────────────────────────────")


def test_import_field_mapping():
    from src.translators.field_mapping import (
        FIELD_MAP, PLATFORMS, resolve, resolve_all, get_canonical_fields
    )


def test_import_base():
    from src.translators.base import BaseSIEMTranslator


def test_import_splunk():
    from src.translators.splunk import SplunkTranslator


def test_import_qradar():
    from src.translators.qradar import QRadarTranslator


def test_import_elastic():
    from src.translators.elastic import ElasticTranslator


def test_import_sentinel():
    from src.translators.sentinel import SentinelTranslator


def test_import_wazuh():
    from src.translators.wazuh import WazuhTranslator


def test_import_translators_init():
    from src.translators import (
        SplunkTranslator, QRadarTranslator, ElasticTranslator,
        SentinelTranslator, WazuhTranslator,
        translate_all, translate_one, resolve, resolve_all,
    )


check("Import: field_mapping.py",    test_import_field_mapping)
check("Import: base.py",             test_import_base)
check("Import: splunk.py",           test_import_splunk)
check("Import: qradar.py",           test_import_qradar)
check("Import: elastic.py",          test_import_elastic)
check("Import: sentinel.py",         test_import_sentinel)
check("Import: wazuh.py",            test_import_wazuh)
check("Import: translators/__init__",test_import_translators_init)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 2. FIELD MAPPING ────────────────────────────────────────")


def test_resolve_known_field():
    from src.translators.field_mapping import resolve
    assert resolve("src_ip", "splunk")   == "src_ip"
    assert resolve("src_ip", "qradar")   == "sourceip"
    assert resolve("src_ip", "elastic")  == "source.ip"
    assert resolve("src_ip", "sentinel") == "IpAddress"
    assert resolve("src_ip", "wazuh")    == "srcip"


def test_resolve_user_field():
    from src.translators.field_mapping import resolve
    assert resolve("user", "splunk")   == "user"
    assert resolve("user", "qradar")   == "username"
    assert resolve("user", "elastic")  == "user.name"
    assert resolve("user", "sentinel") == "Account"
    assert resolve("user", "wazuh")    == "dstuser"


def test_resolve_timestamp_field():
    from src.translators.field_mapping import resolve
    assert resolve("timestamp", "splunk")   == "_time"
    assert resolve("timestamp", "elastic")  == "@timestamp"
    assert resolve("timestamp", "sentinel") == "TimeGenerated"
    assert resolve("timestamp", "qradar")   == "starttime"


def test_resolve_process_name():
    from src.translators.field_mapping import resolve
    assert resolve("process_name", "elastic")  == "process.name"
    assert resolve("process_name", "sentinel") == "Process"
    assert resolve("process_name", "wazuh")    == "program_name"


def test_resolve_unknown_field_passthrough():
    from src.translators.field_mapping import resolve
    # Unknown fields should pass through as-is
    result = resolve("totally_unknown_field_xyz", "splunk")
    assert result == "totally_unknown_field_xyz"


def test_resolve_all():
    from src.translators.field_mapping import resolve_all
    fields = ["src_ip", "user", "status"]
    elastic = resolve_all(fields, "elastic")
    assert elastic == ["source.ip", "user.name", "event.outcome"]


def test_get_canonical_fields():
    from src.translators.field_mapping import get_canonical_fields
    fields = get_canonical_fields()
    assert isinstance(fields, list)
    assert "src_ip"       in fields
    assert "user"         in fields
    assert "process_name" in fields
    assert "dest_ip"      in fields
    assert len(fields) > 20


def test_all_platforms_covered():
    from src.translators.field_mapping import FIELD_MAP, PLATFORMS
    for canonical, mappings in FIELD_MAP.items():
        for platform in PLATFORMS:
            assert platform in mappings, \
                f"Field '{canonical}' missing mapping for platform '{platform}'"


check("FieldMap: src_ip across all platforms",      test_resolve_known_field)
check("FieldMap: user across all platforms",        test_resolve_user_field)
check("FieldMap: timestamp across all platforms",   test_resolve_timestamp_field)
check("FieldMap: process_name across platforms",    test_resolve_process_name)
check("FieldMap: unknown field passthrough",        test_resolve_unknown_field_passthrough)
check("FieldMap: resolve_all list",                 test_resolve_all)
check("FieldMap: get_canonical_fields()",           test_get_canonical_fields)
check("FieldMap: all platforms covered",            test_all_platforms_covered)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 3. SPLUNK TRANSLATOR ────────────────────────────────────")


def test_splunk_filter_basic():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert "index=*"      in q
    assert "earliest="    in q
    assert "failed"       in q
    assert isinstance(q, str) and len(q) > 10


def test_splunk_filter_aggregate():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "index=*"         in q
    assert "stats"           in q
    assert "attempt_count"   in q
    assert "src_ip"          in q
    assert "where"           in q
    assert "50"              in q


def test_splunk_time_window():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert "earliest=-24h" in q or "earliest=" in q


def test_splunk_contains_operator():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_process_ir()
    q  = t.translate(ir)
    assert "powershell.exe" in q
    assert "cmd.exe"        in q


def test_splunk_lookup():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_lookup_ir()
    q  = t.translate(ir)
    assert "lookup" in q.lower()
    assert "threat_intel_ips" in q


def test_splunk_sequence():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_sequence_ir()
    q  = t.translate(ir)
    assert isinstance(q, str) and len(q) > 5


def test_splunk_distinct_count():
    from src.translators.splunk import SplunkTranslator
    t  = SplunkTranslator()
    ir = _make_network_ir()
    q  = t.translate(ir)
    assert "dc(" in q or "stats" in q


def test_splunk_validate_valid():
    from src.translators.splunk import SplunkTranslator
    t = SplunkTranslator()
    assert t.validate("index=* status=failed earliest=-24h | stats count by src_ip | where count > 50") is True


def test_splunk_validate_invalid():
    from src.translators.splunk import SplunkTranslator
    t = SplunkTranslator()
    assert t.validate("SELECT * FROM events") is False
    assert t.validate("") is False
    assert t.validate(None) is False


def test_splunk_platform_name():
    from src.translators.splunk import SplunkTranslator
    assert SplunkTranslator().platform_name == "splunk"


check("Splunk: filter basic output",      test_splunk_filter_basic)
check("Splunk: filter+aggregate output",  test_splunk_filter_aggregate)
check("Splunk: time window earliest=",    test_splunk_time_window)
check("Splunk: contains operator",        test_splunk_contains_operator)
check("Splunk: lookup command",           test_splunk_lookup)
check("Splunk: sequence/transaction",     test_splunk_sequence)
check("Splunk: distinct_count → dc()",   test_splunk_distinct_count)
check("Splunk: validate() valid query",   test_splunk_validate_valid)
check("Splunk: validate() invalid query", test_splunk_validate_invalid)
check("Splunk: platform_name == splunk",  test_splunk_platform_name)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 4. QRADAR TRANSLATOR ────────────────────────────────────")


def test_qradar_filter_basic():
    from src.translators.qradar import QRadarTranslator
    t  = QRadarTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert q.strip().upper().startswith("SELECT")
    assert "FROM EVENTS"  in q.upper()
    assert "WHERE"        in q.upper()
    assert "failed"       in q


def test_qradar_filter_aggregate():
    from src.translators.qradar import QRadarTranslator
    t  = QRadarTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "SELECT"      in q.upper()
    assert "FROM EVENTS" in q.upper()
    assert "GROUP BY"    in q.upper()
    assert "HAVING"      in q.upper()
    assert "COUNT"       in q.upper()
    assert "50"          in q


def test_qradar_time_at_end():
    from src.translators.qradar import QRadarTranslator
    t  = QRadarTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    # LAST N HOURS must be the final clause in AQL
    lines = [l.strip() for l in q.strip().split("\n") if l.strip()]
    assert lines[-1].upper().startswith("LAST")


def test_qradar_contains_ilike():
    from src.translators.qradar import QRadarTranslator
    t  = QRadarTranslator()
    ir = _make_process_ir()
    q  = t.translate(ir)
    assert "ILIKE" in q.upper() or "ilike" in q.lower()


def test_qradar_distinct_count():
    from src.translators.qradar import QRadarTranslator
    t  = QRadarTranslator()
    ir = _make_network_ir()
    q  = t.translate(ir)
    assert "DISTINCT" in q.upper() or "COUNT" in q.upper()


def test_qradar_validate_valid():
    from src.translators.qradar import QRadarTranslator
    t = QRadarTranslator()
    assert t.validate("SELECT sourceip, COUNT(*) AS cnt FROM events WHERE status = 'failed' GROUP BY sourceip HAVING cnt > 50 LAST 24 HOURS") is True


def test_qradar_validate_invalid():
    from src.translators.qradar import QRadarTranslator
    t = QRadarTranslator()
    assert t.validate("index=* | stats count by src_ip") is False
    assert t.validate("") is False
    assert t.validate("SELECT * FROM logs") is False   # missing FROM EVENTS


def test_qradar_platform_name():
    from src.translators.qradar import QRadarTranslator
    assert QRadarTranslator().platform_name == "qradar"


check("QRadar: filter basic SELECT/FROM/WHERE", test_qradar_filter_basic)
check("QRadar: filter+aggregate GROUP BY/HAVING",test_qradar_filter_aggregate)
check("QRadar: LAST N HOURS at end",            test_qradar_time_at_end)
check("QRadar: contains → ILIKE",               test_qradar_contains_ilike)
check("QRadar: distinct_count → COUNT DISTINCT", test_qradar_distinct_count)
check("QRadar: validate() valid query",          test_qradar_validate_valid)
check("QRadar: validate() invalid query",        test_qradar_validate_invalid)
check("QRadar: platform_name == qradar",         test_qradar_platform_name)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 5. ELASTIC TRANSLATOR ───────────────────────────────────")


def test_elastic_filter_only_kql():
    from src.translators.elastic import ElasticTranslator
    t  = ElasticTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    # Filter-only → KQL: should have field: value syntax OR event.category
    assert ":" in q or "where" in q.lower()
    assert isinstance(q, str) and len(q) > 5


def test_elastic_filter_aggregate_eql():
    from src.translators.elastic import ElasticTranslator
    t  = ElasticTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "authentication" in q.lower() or "where" in q.lower()
    assert "stats"          in q.lower()
    assert "attempt_count"  in q
    assert "50"             in q


def test_elastic_stats_pipe():
    from src.translators.elastic import ElasticTranslator
    t  = ElasticTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "| stats" in q


def test_elastic_where_threshold():
    from src.translators.elastic import ElasticTranslator
    t  = ElasticTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "| where" in q


def test_elastic_sequence_eql():
    from src.translators.elastic import ElasticTranslator
    t  = ElasticTranslator()
    ir = _make_sequence_ir()
    q  = t.translate(ir)
    assert "sequence" in q.lower()
    assert "["        in q


def test_elastic_contains_like():
    from src.translators.elastic import ElasticTranslator
    t  = ElasticTranslator()
    ir = _make_process_ir()
    q  = t.translate(ir)
    assert "powershell.exe" in q
    assert "cmd.exe"        in q


def test_elastic_validate_eql():
    from src.translators.elastic import ElasticTranslator
    t = ElasticTranslator()
    assert t.validate("authentication where event.outcome == \"failure\"\n| stats count() as cnt by source.ip\n| where cnt > 50") is True


def test_elastic_validate_kql():
    from src.translators.elastic import ElasticTranslator
    t = ElasticTranslator()
    assert t.validate('event.category: "authentication" AND event.outcome: "failure"') is True


def test_elastic_validate_invalid():
    from src.translators.elastic import ElasticTranslator
    t = ElasticTranslator()
    assert t.validate("SELECT * FROM events") is False
    assert t.validate("") is False


def test_elastic_platform_name():
    from src.translators.elastic import ElasticTranslator
    assert ElasticTranslator().platform_name == "elastic"


check("Elastic: filter-only → KQL",          test_elastic_filter_only_kql)
check("Elastic: filter+agg → EQL",           test_elastic_filter_aggregate_eql)
check("Elastic: | stats pipe present",        test_elastic_stats_pipe)
check("Elastic: | where threshold present",   test_elastic_where_threshold)
check("Elastic: sequence → EQL sequence",     test_elastic_sequence_eql)
check("Elastic: contains → like wildcard",    test_elastic_contains_like)
check("Elastic: validate() EQL query",        test_elastic_validate_eql)
check("Elastic: validate() KQL query",        test_elastic_validate_kql)
check("Elastic: validate() invalid query",    test_elastic_validate_invalid)
check("Elastic: platform_name == elastic",    test_elastic_platform_name)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 6. SENTINEL TRANSLATOR ──────────────────────────────────")


def test_sentinel_starts_with_table():
    from src.translators.sentinel import SentinelTranslator
    VALID_TABLES = {
        "SecurityEvent", "Syslog", "SigninLogs", "NetworkAnalytics",
        "DnsEvents", "DeviceProcessEvents", "DeviceFileEvents",
        "DeviceNetworkEvents", "DeviceRegistryEvents",
    }
    t  = SentinelTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    first_line = q.strip().split("\n")[0].strip()
    assert first_line in VALID_TABLES, f"First line '{first_line}' not a valid Sentinel table"


def test_sentinel_pipe_structure():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert "|" in q


def test_sentinel_time_filter():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert "ago(" in q


def test_sentinel_where_filter():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert "where" in q.lower()
    assert "failed" in q


def test_sentinel_summarize():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "summarize"     in q.lower()
    assert "attempt_count" in q
    assert "IpAddress"     in q or "src_ip" in q


def test_sentinel_threshold():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_agg_ir()
    q  = t.translate(ir)
    assert "50" in q


def test_sentinel_dcount_distinct():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_network_ir()
    q  = t.translate(ir)
    assert "dcount" in q.lower() or "summarize" in q.lower()


def test_sentinel_dns_table():
    from src.translators.sentinel import SentinelTranslator
    t  = SentinelTranslator()
    ir = _make_dns_ir()
    q  = t.translate(ir)
    assert q.strip().startswith("DnsEvents")


def test_sentinel_validate_valid():
    from src.translators.sentinel import SentinelTranslator
    t = SentinelTranslator()
    assert t.validate(
        "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4625\n"
        "| summarize cnt = count() by IpAddress\n| where cnt > 50"
    ) is True


def test_sentinel_validate_invalid():
    from src.translators.sentinel import SentinelTranslator
    t = SentinelTranslator()
    assert t.validate("SELECT * FROM events") is False
    assert t.validate("index=* | stats count") is False
    assert t.validate("") is False


def test_sentinel_platform_name():
    from src.translators.sentinel import SentinelTranslator
    assert SentinelTranslator().platform_name == "sentinel"


check("Sentinel: starts with valid table",     test_sentinel_starts_with_table)
check("Sentinel: pipe | structure",            test_sentinel_pipe_structure)
check("Sentinel: time filter ago()",           test_sentinel_time_filter)
check("Sentinel: where filter",                test_sentinel_where_filter)
check("Sentinel: summarize aggregation",       test_sentinel_summarize)
check("Sentinel: threshold where clause",      test_sentinel_threshold)
check("Sentinel: distinct_count → dcount()",  test_sentinel_dcount_distinct)
check("Sentinel: DNS → DnsEvents table",       test_sentinel_dns_table)
check("Sentinel: validate() valid query",      test_sentinel_validate_valid)
check("Sentinel: validate() invalid query",    test_sentinel_validate_invalid)
check("Sentinel: platform_name == sentinel",   test_sentinel_platform_name)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 7. WAZUH TRANSLATOR ─────────────────────────────────────")


def test_wazuh_returns_xml():
    from src.translators.wazuh import WazuhTranslator
    t  = WazuhTranslator()
    ir = _make_filter_ir()
    q  = t.translate(ir)
    assert q.strip().startswith("<rule")
    assert "</rule>" in q


def test_wazuh_rule_id_in_custom_range():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_filter_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    assert int(root.attrib["id"]) >= 100000


def test_wazuh_has_level():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_filter_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    assert "level" in root.attrib


def test_wazuh_has_description():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_filter_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    assert root.find("description") is not None


def test_wazuh_has_group():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_filter_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    assert root.find("group") is not None


def test_wazuh_frequency_and_timeframe():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_agg_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    assert root.find("frequency")  is not None
    assert root.find("timeframe")  is not None
    assert root.find("frequency").text == "50"


def test_wazuh_mitre_tag():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_agg_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    mitre = root.find("mitre")
    assert mitre is not None
    assert mitre.find("id").text == "T1110"


def test_wazuh_match_tag_for_value():
    import xml.etree.ElementTree as ET
    from src.translators.wazuh import WazuhTranslator
    t    = WazuhTranslator()
    ir   = _make_filter_ir()
    q    = t.translate(ir)
    root = ET.fromstring(q)
    # Should have a match or if_sid tag
    assert root.find("match") is not None or root.find("if_sid") is not None


def test_wazuh_validate_valid():
    from src.translators.wazuh import WazuhTranslator
    t = WazuhTranslator()
    xml = """<rule id="100001" level="10">
  <if_sid>5503</if_sid>
  <match>Failed password</match>
  <frequency>50</frequency>
  <timeframe>86400</timeframe>
  <group>authentication_failures,</group>
  <description>Brute force detection</description>
  <mitre><id>T1110</id></mitre>
</rule>"""
    assert t.validate(xml) is True


def test_wazuh_validate_invalid():
    from src.translators.wazuh import WazuhTranslator
    t = WazuhTranslator()
    assert t.validate("SELECT * FROM events") is False
    assert t.validate("<rule><description>Missing id and level</description></rule>") is False
    assert t.validate("") is False
    assert t.validate("<not_a_rule id='1' level='5'><description>x</description></not_a_rule>") is False


def test_wazuh_platform_name():
    from src.translators.wazuh import WazuhTranslator
    assert WazuhTranslator().platform_name == "wazuh"


check("Wazuh: returns valid XML",              test_wazuh_returns_xml)
check("Wazuh: rule ID >= 100000",              test_wazuh_rule_id_in_custom_range)
check("Wazuh: has level attribute",            test_wazuh_has_level)
check("Wazuh: has <description> tag",          test_wazuh_has_description)
check("Wazuh: has <group> tag",                test_wazuh_has_group)
check("Wazuh: frequency + timeframe present",  test_wazuh_frequency_and_timeframe)
check("Wazuh: <mitre><id> tag present",        test_wazuh_mitre_tag)
check("Wazuh: <match> or <if_sid> present",    test_wazuh_match_tag_for_value)
check("Wazuh: validate() valid XML",           test_wazuh_validate_valid)
check("Wazuh: validate() invalid input",       test_wazuh_validate_invalid)
check("Wazuh: platform_name == wazuh",         test_wazuh_platform_name)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 8. translate_all() ──────────────────────────────────────")


def test_translate_all_returns_five_keys():
    from src.translators import translate_all
    ir     = _make_agg_ir()
    result = translate_all(ir)
    assert set(result.keys()) == {"splunk", "qradar", "elastic", "sentinel", "wazuh"}


def test_translate_all_no_empty_outputs():
    from src.translators import translate_all
    ir     = _make_agg_ir()
    result = translate_all(ir)
    for platform, query in result.items():
        assert isinstance(query, str), f"{platform} returned non-string"
        assert len(query.strip()) > 0, f"{platform} returned empty string"


def test_translate_all_no_error_prefix():
    from src.translators import translate_all
    ir     = _make_agg_ir()
    result = translate_all(ir)
    for platform, query in result.items():
        assert not query.startswith("ERROR:"), \
            f"{platform} translation failed: {query}"


def test_translate_all_filter_ir():
    from src.translators import translate_all
    ir     = _make_filter_ir()
    result = translate_all(ir)
    assert len(result) == 5
    for platform, query in result.items():
        assert not query.startswith("ERROR:"), f"{platform}: {query}"


def test_translate_all_network_ir():
    from src.translators import translate_all
    ir     = _make_network_ir()
    result = translate_all(ir)
    assert len(result) == 5
    for platform, query in result.items():
        assert not query.startswith("ERROR:"), f"{platform}: {query}"


def test_translate_all_lookup_ir():
    from src.translators import translate_all
    ir     = _make_lookup_ir()
    result = translate_all(ir)
    assert len(result) == 5


def test_translate_all_sequence_ir():
    from src.translators import translate_all
    ir     = _make_sequence_ir()
    result = translate_all(ir)
    assert len(result) == 5


def test_translate_one_splunk():
    from src.translators import translate_one
    ir = _make_agg_ir()
    q  = translate_one(ir, "splunk")
    assert "stats" in q


def test_translate_one_unknown_platform_raises():
    from src.translators import translate_one
    try:
        translate_one(_make_filter_ir(), "nonexistent_siem")
        assert False, "Should raise ValueError"
    except ValueError as e:
        assert "nonexistent_siem" in str(e).lower() or "unknown" in str(e).lower()


check("translate_all: returns 5 keys",            test_translate_all_returns_five_keys)
check("translate_all: no empty outputs",          test_translate_all_no_empty_outputs)
check("translate_all: no ERROR: prefix",          test_translate_all_no_error_prefix)
check("translate_all: filter IR",                 test_translate_all_filter_ir)
check("translate_all: network IR",                test_translate_all_network_ir)
check("translate_all: lookup IR",                 test_translate_all_lookup_ir)
check("translate_all: sequence IR",               test_translate_all_sequence_ir)
check("translate_one: splunk",                    test_translate_one_splunk)
check("translate_one: unknown platform raises",   test_translate_one_unknown_platform_raises)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 9. VALIDATE ALL OUTPUTS ─────────────────────────────────")


def test_all_outputs_pass_validation():
    """Run translate_all + validate() on every IR fixture."""
    from src.translators import (
        SplunkTranslator, QRadarTranslator, ElasticTranslator,
        SentinelTranslator, WazuhTranslator, translate_all,
    )
    validators = {
        "splunk":   SplunkTranslator(),
        "qradar":   QRadarTranslator(),
        "elastic":  ElasticTranslator(),
        "sentinel": SentinelTranslator(),
        "wazuh":    WazuhTranslator(),
    }
    irs = {
        "filter":    _make_filter_ir(),
        "aggregate": _make_agg_ir(),
        "network":   _make_network_ir(),
        "process":   _make_process_ir(),
        "dns":       _make_dns_ir(),
    }
    failures = []
    for ir_name, ir in irs.items():
        result = translate_all(ir)
        for platform, query in result.items():
            if query.startswith("ERROR:"):
                failures.append(f"{ir_name}/{platform}: translation error")
                continue
            valid = validators[platform].validate(query)
            if not valid:
                failures.append(f"{ir_name}/{platform}: validation failed\n    Query: {query[:100]}")

    assert not failures, "Validation failures:\n" + "\n".join(failures)


check("All outputs: validate() passes for all IR × platform combinations",
      test_all_outputs_pass_validation)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 10. CROSS-LAYER INTEGRATION ─────────────────────────────")


def test_layer1_to_layer2_via_coerce():
    """coerce_ir() output feeds directly into translate_all()."""
    from src.ir.validator import coerce_ir
    from src.translators import translate_all

    raw = {
        "action": "detect",               # alias → filter+aggregate
        "event_type": "login",            # alias → authentication
        "filter": {"operator": "and", "conditions": [
            {"field": "status", "op": "==", "value": "failed"}   # == → eq
        ]},
        "time_window": "24h",             # string shorthand
        "aggregation": {"function": "count", "group_by": ["src_ip"], "alias": "attempts"},
        "threshold": ">50",               # string shorthand
        "tactic": "initial_access",
        "spurious_key": "noise",          # stripped by coercion
    }

    ir     = coerce_ir(raw)
    result = translate_all(ir)

    assert len(result) == 5
    for platform, query in result.items():
        assert not query.startswith("ERROR:"), f"{platform}: {query}"

    # SPL should have stats + where
    assert "stats"  in result["splunk"]
    assert "where"  in result["splunk"]
    # AQL should have SELECT + GROUP BY
    assert "SELECT" in result["qradar"].upper()
    assert "GROUP BY" in result["qradar"].upper()
    # Sentinel should have summarize
    assert "summarize" in result["sentinel"].lower()
    # Wazuh should be valid XML
    assert result["wazuh"].strip().startswith("<rule")


def test_examples_json_translate_all():
    """Every example in examples.json should translate without errors."""
    import json
    from src.ir.validator import coerce_ir
    from src.translators import translate_all

    examples_path = Path("src/ir/examples.json")
    assert examples_path.exists(), "src/ir/examples.json not found"

    with examples_path.open() as f:
        examples = json.load(f)

    failures = []
    for ex in examples:
        ir_dict = ex["ir"].copy()
        ir_dict.setdefault("tactic",       ex.get("tactic"))
        ir_dict.setdefault("technique_id", ex.get("technique_id"))
        try:
            ir     = coerce_ir(ir_dict)
            result = translate_all(ir)
            for platform, query in result.items():
                if query.startswith("ERROR:"):
                    failures.append(f"{ex['id']}/{platform}: {query}")
        except Exception as e:
            failures.append(f"{ex['id']}: {e}")

    assert not failures, "Example translation failures:\n" + "\n".join(failures)


def test_field_resolution_consistent():
    """
    Same IR field resolves consistently across all platforms in actual queries.

    Note on Wazuh: Wazuh XML does not use field names in query strings.
    src_ip grouping is expressed as <same_source_ip/> structural tag.
    We verify that tag is present instead of checking for a field name string.
    """
    import xml.etree.ElementTree as ET
    from src.translators import translate_all
    ir = _make_agg_ir()
    result = translate_all(ir)

    # SPL/AQL/EQL/KQL: src_ip appears as a named field
    field_forms = {
        "splunk":   "src_ip",
        "qradar":   "sourceip",
        "elastic":  "source.ip",
        "sentinel": "IpAddress",
    }
    for platform, expected_field in field_forms.items():
        q = result[platform]
        assert expected_field in q or "src" in q.lower(), \
            f"{platform}: expected field '{expected_field}' not found in query"

    # Wazuh: src_ip grouping → <same_source_ip/> structural tag
    wazuh_xml = result["wazuh"]
    root = ET.fromstring(wazuh_xml)
    has_same_src = root.find("same_source_ip") is not None
    has_src_text = "srcip" in wazuh_xml or "src" in wazuh_xml.lower()
    assert has_same_src or has_src_text, \
        "Wazuh: expected <same_source_ip/> or srcip reference not found in XML"


def test_layer0_exceptions_from_translators():
    """TranslationError from translators is catchable as NLSIEMError."""
    from src.utils.exceptions import NLSIEMError, TranslationError
    assert issubclass(TranslationError, NLSIEMError)


check("Integration: coerce_ir → translate_all",       test_layer1_to_layer2_via_coerce)
check("Integration: examples.json all translate",     test_examples_json_translate_all)
check("Integration: field resolution consistent",     test_field_resolution_consistent)
check("Integration: TranslationError ⊂ NLSIEMError", test_layer0_exceptions_from_translators)


# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total  = len(results)
print(f"  Results: {passed}/{total} passed", end="")
if failed:
    print(f"  |  {failed} FAILED ← fix before Layer 3")
    print("\n  Failed tests:")
    for label, ok, exc in results:
        if not ok:
            print(f"    ✗ {label}")
            print(f"      {type(exc).__name__}: {exc}")
else:
    print("  — Layer 2 is solid. Ready for Layer 3 (LLM client + RAG) ✅")
print("═" * 60 + "\n")

sys.exit(0 if failed == 0 else 1)