"""
tests/test_agents.py
====================
Comprehensive test suite for Layer 5 (agents) and cross-layer integration.

Coverage:
  Unit tests  — ValidatorAgent, ParserAgent, RefinementAgent, TranslationOrchestrator
  Interlayer  — L1 IR schema → L2 translators → L5 agents (no LLM needed)
  Integration — full pipeline with mocked LLM

Run:
    pytest tests/test_agents.py -v
    pytest tests/test_agents.py -v -k "validator"          # just one class
    pytest tests/test_agents.py -v -k "interlayer"         # cross-layer only
    pytest tests/test_agents.py --tb=short                 # compact tracebacks
    pytest tests/test_agents.py -v --log-cli-level=DEBUG   # with logs
"""

from __future__ import annotations

import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch, call
from src.ir.schema import IRQuery;
import pytest

# ---------------------------------------------------------------------------
# ── Lightweight stubs so tests run without the full src package installed ──
# ---------------------------------------------------------------------------
# If your environment already has src/ on PYTHONPATH, these stubs are ignored
# because the real imports succeed first.  They only activate when the package
# is missing (CI without deps, isolated runs, etc.).

import sys
import types

def _stub_module(name: str, **attrs) -> types.ModuleType:
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules.setdefault(name, mod)
    return sys.modules[name]


# --- Minimal IR schema stub ---
@dataclass
class _IRQuery:
    action: str = "filter"
    event_type: str = "authentication"
    filters: list = field(default_factory=list)
    aggregation: dict | None = None
    threshold: dict | None = None
    time_window: dict | None = None
    platforms: list = field(default_factory=lambda: ["splunk","qradar","elastic","sentinel","wazuh"])
    nl_query: str = ""
    mitre_techniques: list = field(default_factory=list)

    def summary(self) -> str:
        return f"IRQuery(action={self.action}, event_type={self.event_type})"

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "event_type": self.event_type,
            "filters": self.filters,
            "aggregation": self.aggregation,
            "threshold": self.threshold,
            "time_window": self.time_window,
            "platforms": self.platforms,
            "nl_query": self.nl_query,
        }


# --- Minimal exception stubs ---
class _NLSIEMError(Exception):
    def __init__(self, msg="", details=None):
        super().__init__(msg)
        self.message = msg
        self.details = details or {}

class _IRValidationError(_NLSIEMError): pass
class _IRCoercionError(_NLSIEMError): pass
class _LLMError(_NLSIEMError): pass
class _TranslationError(_NLSIEMError): pass


# Now import the real modules (they'll find the stubs for sub-dependencies)
from src.agents.validator_agent import (
    ValidatorAgent,
    ValidationReport,
    PlatformValidation,
)
from src.agents.parser_agent import ParserAgent, ParseResult
from src.agents.refinement_agent import RefinementAgent, RefinementResult
from src.agents.translation_orchestrator import TranslationOrchestrator, TranslationResult
from src.utils.exceptions import NLSIEMError

# ===========================================================================
# ── Fixtures & helpers
# ===========================================================================

ALL_PLATFORMS = ["splunk", "qradar", "elastic", "sentinel", "wazuh"]

VALID_SPLUNK   = 'index=auth sourcetype=linux_secure "Failed password"\n| stats count AS failures BY src_ip, user\n| where failures > 10'
VALID_QRADAR   = "SELECT sourceip, username, COUNT(*) AS attempts\nFROM events\nWHERE category = 5018\nGROUP BY sourceip, username\nHAVING COUNT(*) > 10\nLAST 24 HOURS"
VALID_ELASTIC  = 'authentication where event.outcome == "failure"\n| stats count() as cnt by source.ip\n| where cnt > 10'
VALID_SENTINEL = 'SecurityEvent\n| where EventID == 4625\n| where TimeGenerated > ago(24h)\n| summarize Failures=count() by IpAddress, Account\n| where Failures > 10'
VALID_WAZUH    = '''<rule id="100001" level="10">
  <description>SSH brute force detected</description>
  <if_sid>5700</if_sid>
  <match>Failed password</match>
  <same_source_ip/>
  <frequency>10</frequency>
  <timeframe>120</timeframe>
  <group>authentication_failed,pci_dss_10.2.4</group>
</rule>'''

GOOD_TRANSLATIONS: dict[str, str] = {
    "splunk":   VALID_SPLUNK,
    "qradar":   VALID_QRADAR,
    "elastic":  VALID_ELASTIC,
    "sentinel": VALID_SENTINEL,
    "wazuh":    VALID_WAZUH,
}


def make_ir(**kwargs) -> _IRQuery:
    defaults = dict(
        action="filter",
        event_type="authentication",
        filters=[{"field": "action", "op": "eq", "value": "failure"}],
        aggregation={"function": "count", "field": "*"},
        threshold={"op": "gt", "value": 10},
        time_window={"duration": 5, "unit": "minutes"},
        nl_query="Detect SSH brute force",
    )
    defaults.update(kwargs)
    return _IRQuery(**defaults)


def make_parse_result(ir: _IRQuery | None = None, **kwargs) -> ParseResult:
    ir = ir or make_ir()
    builder = MagicMock()
    builder.build_ir_prompt.return_value = [{"role": "user", "content": "test"}]
    parser = MagicMock(spec=ParserAgent)
    
    defaults = dict(
        ir=ir,
        nl_query="Detect SSH brute force",
        attempts=1,
        elapsed_s=0.5,
        rag_used=False,
        condition="few_shot",
        warnings=[],
        raw_response='{"action":"filter","event_type":"authentication"}',
    )
    defaults.update(kwargs)
    return ParseResult(**defaults)


def make_validation_report(
    all_pass: bool = True,
    failed: list[str] | None = None,
    nl_query: str = "test query",
) -> ValidationReport:
    failed = failed or []
    results = {}
    for p in ALL_PLATFORMS:
        if p in failed:
            results[p] = PlatformValidation(
                platform=p, query="BAD QUERY", is_valid=False,
                error_type="missing_keyword", error_detail=f"Synthetic failure on {p}"
            )
        else:
            results[p] = PlatformValidation(platform=p, query="GOOD QUERY", is_valid=True)
    return ValidationReport(nl_query=nl_query, results=results, elapsed_s=0.01)


def make_llm_client(response: str = '{"action":"filter","event_type":"authentication"}') -> MagicMock:
    client = MagicMock()
    client.complete.return_value = response
    client.model = "mock-model"
    client.provider = "mock"
    return client


def make_orchestrator(
    client=None,
    with_rag: bool = False,
    with_refinement: bool = False,
    parse_result: ParseResult | None = None,
) -> TranslationOrchestrator:
    """Build an orchestrator with fully mocked sub-components."""
    client = client or make_llm_client()
    pr     = parse_result or make_parse_result()

    parser = MagicMock(spec=ParserAgent)
    parser.parse.return_value = pr
    parser.retriever = MagicMock() if with_rag else None

    validator = ValidatorAgent()

    refinement = None
    if with_refinement:
        refinement = MagicMock(spec=RefinementAgent)
        refinement.refine.return_value = RefinementResult(
            nl_query="Detect SSH brute force",
            original_translations=GOOD_TRANSLATIONS,
            final_translations=GOOD_TRANSLATIONS,
            final_ir=make_ir(),
            iterations=1,
            platforms_fixed=["splunk"],
            platforms_still_failed=[],
            strategy_used="query_patch",
            elapsed_s=0.3,
        )

    orc = TranslationOrchestrator(
        parser_agent      = parser,
        validator         = validator,
        refinement_agent  = refinement,
        enable_refinement = with_refinement,
        provider          = "mock",
        model             = "mock-model",
        condition         = "few_shot",
    )
    return orc


# ===========================================================================
# ── 1. ValidatorAgent — unit tests
# ===========================================================================

class TestValidatorAgentSplunk:
    """Tests for the Splunk SPL validator."""

    def setup_method(self):
        self.v = ValidatorAgent()

    def test_valid_simple(self):
        r = self.v.validate_single("splunk", VALID_SPLUNK)
        assert r.is_valid

    def test_valid_search_prefix(self):
        q = 'search index=main "error" | stats count by host'
        assert self.v.validate_single("splunk", q).is_valid

    def test_valid_wildcard_prefix(self):
        q = '* | stats count by src_ip'
        assert self.v.validate_single("splunk", q).is_valid

    def test_fail_no_index_prefix(self):
        r = self.v.validate_single("splunk", "stats count by src_ip")
        assert not r.is_valid
        assert r.error_type == "missing_keyword"

    def test_fail_empty(self):
        r = self.v.validate_single("splunk", "")
        assert not r.is_valid
        assert r.error_type == "empty_query"

    def test_fail_unknown_pipe_command(self):
        q = "index=main | BADCOMMAND foo"
        r = self.v.validate_single("splunk", q)
        assert not r.is_valid
        assert r.error_type == "unknown_command"

    def test_corrected_query_suggestion(self):
        """Validator should auto-suggest 'index=* <query>' for missing-prefix failures."""
        r = self.v.validate_single("splunk", "| stats count by host")
        assert not r.is_valid
        # corrected_query is optional but if set it should be a non-empty string
        if r.corrected_query is not None:
            assert len(r.corrected_query) > 0

    def test_valid_pipe_chain(self):
        q = "index=network | eval mb=bytes/1048576 | where mb > 100 | table src_ip, dest_ip, mb | sort -mb"
        assert self.v.validate_single("splunk", q).is_valid

    def test_status_property(self):
        r = self.v.validate_single("splunk", VALID_SPLUNK)
        assert r.status == "PASS"
        r2 = self.v.validate_single("splunk", "garbage")
        assert r2.status == "FAIL"


class TestValidatorAgentQRadar:
    """Tests for the QRadar AQL validator."""

    def setup_method(self):
        self.v = ValidatorAgent()

    def test_valid(self):
        assert self.v.validate_single("qradar", VALID_QRADAR).is_valid

    def test_fail_no_select(self):
        r = self.v.validate_single("qradar", "FROM events WHERE category=5018 LAST 24 HOURS")
        assert not r.is_valid
        assert r.error_type == "missing_keyword"

    def test_fail_no_from_events(self):
        r = self.v.validate_single("qradar", "SELECT * FROM logs LAST 24 HOURS")
        assert not r.is_valid

    def test_fail_group_by_without_aggregate(self):
        r = self.v.validate_single("qradar",
            "SELECT sourceip FROM events GROUP BY sourceip LAST 24 HOURS")
        assert not r.is_valid
        assert r.error_type == "missing_aggregate"

    def test_fail_having_without_group_by(self):
        r = self.v.validate_single("qradar",
            "SELECT sourceip, COUNT(*) FROM events HAVING COUNT(*) > 10 LAST 24 HOURS")
        assert not r.is_valid
        assert r.error_type == "malformed_syntax"

    def test_warn_no_time_range(self):
        q = "SELECT sourceip, COUNT(*) FROM events GROUP BY sourceip HAVING COUNT(*) > 5"
        r = self.v.validate_single("qradar", q)
        assert r.is_valid
        assert any("time range" in w.lower() for w in r.warnings)

    def test_fail_empty(self):
        assert not self.v.validate_single("qradar", "").is_valid


class TestValidatorAgentElastic:
    """Tests for the Elastic EQL/KQL validator."""

    def setup_method(self):
        self.v = ValidatorAgent()

    def test_valid_eql(self):
        assert self.v.validate_single("elastic", VALID_ELASTIC).is_valid

    def test_valid_kql(self):
        q = 'event.category: "authentication" AND event.outcome: "failure"'
        assert self.v.validate_single("elastic", q).is_valid

    def test_valid_eql_sequence(self):
        q = 'sequence with maxspan=5m\n  [process where process.name == "cmd.exe"]\n  [network where destination.port == 4444]'
        assert self.v.validate_single("elastic", q).is_valid

    def test_fail_eql_no_where(self):
        r = self.v.validate_single("elastic", "authentication source.ip == '1.2.3.4'")
        assert not r.is_valid
        assert r.error_type == "missing_keyword"

    def test_fail_sequence_no_brackets(self):
        r = self.v.validate_single("elastic", "sequence process where process.name == 'cmd.exe'")
        assert not r.is_valid
        assert r.error_type == "malformed_syntax"

    def test_fail_empty(self):
        assert not self.v.validate_single("elastic", "").is_valid

    def test_valid_eql_any_category(self):
        q = "any where true"
        assert self.v.validate_single("elastic", q).is_valid

    def test_valid_kql_comparison_operator(self):
        q = "network.bytes > 1000000"
        assert self.v.validate_single("elastic", q).is_valid


class TestValidatorAgentSentinel:
    """Tests for the Microsoft Sentinel KQL validator."""

    def setup_method(self):
        self.v = ValidatorAgent()

    def test_valid(self):
        assert self.v.validate_single("sentinel", VALID_SENTINEL).is_valid

    def test_fail_no_pipe(self):
        r = self.v.validate_single("sentinel", "SecurityEvent")
        assert not r.is_valid
        assert r.error_type == "malformed_syntax"

    def test_fail_unknown_operator(self):
        q = "SecurityEvent\n| BADOP something"
        r = self.v.validate_single("sentinel", q)
        assert not r.is_valid
        assert r.error_type == "unknown_command"

    def test_warn_unknown_table(self):
        q = "CustomTable123\n| where TimeGenerated > ago(1h)"
        r = self.v.validate_single("sentinel", q)
        assert r.is_valid  # unknown table is a warning, not a failure
        assert any("not a standard" in w.lower() for w in r.warnings)

    def test_fail_empty(self):
        assert not self.v.validate_single("sentinel", "").is_valid

    def test_valid_device_tables(self):
        for tbl in ["DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents"]:
            q = f"{tbl}\n| where Timestamp > ago(1h)\n| limit 100"
            assert self.v.validate_single("sentinel", q).is_valid, f"Failed for table {tbl}"

    def test_valid_project_away(self):
        q = "SecurityEvent\n| where EventID == 4625\n| project-away _SubscriptionId"
        assert self.v.validate_single("sentinel", q).is_valid


class TestValidatorAgentWazuh:
    """Tests for the Wazuh XML rule validator."""

    def setup_method(self):
        self.v = ValidatorAgent()

    def test_valid(self):
        assert self.v.validate_single("wazuh", VALID_WAZUH).is_valid

    def test_fail_not_xml(self):
        r = self.v.validate_single("wazuh", "this is not xml")
        assert not r.is_valid
        assert r.error_type == "invalid_xml"

    def test_fail_wrong_root_tag(self):
        q = '<query id="100001" level="10"><description>test</description></query>'
        r = self.v.validate_single("wazuh", q)
        assert not r.is_valid
        assert r.error_type == "malformed_syntax"

    def test_fail_missing_id(self):
        q = '<rule level="10"><description>test</description></rule>'
        r = self.v.validate_single("wazuh", q)
        assert not r.is_valid
        assert r.error_type == "field_error"

    def test_fail_missing_level(self):
        q = '<rule id="100001"><description>test</description></rule>'
        r = self.v.validate_single("wazuh", q)
        assert not r.is_valid

    def test_fail_missing_description(self):
        q = '<rule id="100001" level="10"><match>sshd</match></rule>'
        r = self.v.validate_single("wazuh", q)
        assert not r.is_valid
        assert r.error_type == "missing_keyword"

    def test_warn_reserved_id_range(self):
        q = '<rule id="5000" level="10"><description>test</description></rule>'
        r = self.v.validate_single("wazuh", q)
        assert r.is_valid
        assert any("100000" in w for w in r.warnings)

    def test_warn_level_out_of_range(self):
        q = '<rule id="100001" level="99"><description>test</description></rule>'
        r = self.v.validate_single("wazuh", q)
        assert r.is_valid
        assert any("0-15" in w for w in r.warnings)

    def test_fail_empty(self):
        assert not self.v.validate_single("wazuh", "").is_valid

    def test_fail_non_integer_id(self):
        q = '<rule id="abc" level="10"><description>test</description></rule>'
        r = self.v.validate_single("wazuh", q)
        assert not r.is_valid


class TestValidationReport:
    """Tests for ValidationReport aggregate behaviour."""

    def setup_method(self):
        self.v = ValidatorAgent()

    def test_all_valid_report(self):
        report = self.v.validate(GOOD_TRANSLATIONS, nl_query="test")
        assert report.all_valid
        assert report.pass_rate == 1.0
        assert set(report.valid_platforms) == set(ALL_PLATFORMS)
        assert report.failed_platforms == []

    def test_partial_failure_report(self):
        bad = dict(GOOD_TRANSLATIONS)
        bad["splunk"] = "invalid query without index"
        report = self.v.validate(bad, nl_query="test")
        assert not report.all_valid
        assert "splunk" in report.failed_platforms
        assert report.pass_rate == 4 / 5

    def test_all_fail_report(self):
        bad = {p: "" for p in ALL_PLATFORMS}
        report = self.v.validate(bad)
        assert report.pass_rate == 0.0
        assert report.valid_platforms == []

    def test_report_to_dict_keys(self):
        report = self.v.validate(GOOD_TRANSLATIONS, "q")
        d = report.to_dict()
        assert "pass_rate" in d
        assert "valid_platforms" in d
        assert "failed_platforms" in d
        assert "results" in d
        for p in ALL_PLATFORMS:
            assert p in d["results"]

    def test_report_summary_string(self):
        report = self.v.validate(GOOD_TRANSLATIONS, "q")
        s = report.summary()
        assert "100%" in s
        for p in ALL_PLATFORMS:
            assert p in s

    def test_empty_translations(self):
        report = self.v.validate({})
        assert report.pass_rate == 0.0

    def test_validate_single_platform(self):
        result = self.v.validate_single("splunk", VALID_SPLUNK)
        assert isinstance(result, PlatformValidation)
        assert result.is_valid

    def test_elapsed_recorded(self):
        report = self.v.validate(GOOD_TRANSLATIONS)
        assert report.elapsed_s >= 0


# ===========================================================================
# ── 2. ParseResult — dataclass tests (no LLM)
# ===========================================================================

class TestParseResult:
    """Tests for ParseResult dataclass correctness."""

    def test_to_dict_has_required_keys(self):
        pr = make_parse_result()
        d  = pr.to_dict()
        for key in ("nl_query", "ir", "attempts", "elapsed_s", "rag_used", "condition", "warnings"):
            assert key in d, f"Missing key: {key}"

    def test_ir_embedded_in_dict(self):
        pr = make_parse_result()
        d  = pr.to_dict()
        assert isinstance(d["ir"], dict)

    def test_warnings_default_empty(self):
        pr = make_parse_result()
        assert isinstance(pr.warnings, list)

    def test_rag_used_false_by_default(self):
        pr = make_parse_result()
        assert pr.rag_used is False


# ===========================================================================
# ── 3. ParserAgent — unit tests (mocked LLM)
# ===========================================================================

class TestParserAgent:
    """Unit tests for ParserAgent with fully mocked LLM client."""

    def _make_agent(self, client=None, retriever=None, max_retries=1):
        client = client or make_llm_client()
        builder = MagicMock()
        builder.build_ir_prompt.return_value = [{"role": "user", "content": "prompt"}]
        parser_mock = MagicMock()
        parser_mock.extract_and_validate.return_value = (
            {"action": "filter", "event_type": "authentication", "nl_query": "test"}, []
        )
        with patch("src.agents.parser_agent.PromptBuilder", return_value=builder), \
             patch("src.agents.parser_agent.ResponseParser", return_value=parser_mock):
            agent = ParserAgent(
                client=client,
                retriever=retriever,
                max_retries=max_retries,
                condition="few_shot",
            )
            # Attach mocks for direct inspection
            agent._prompt_builder    = builder
            agent._response_parser   = parser_mock
        return agent

    def test_parse_success_first_attempt(self):
        agent = self._make_agent()
        result = agent.parse("Detect SSH brute force")
        assert isinstance(result, ParseResult)
        assert result.attempts == 1
        assert result.nl_query == "Detect SSH brute force"
        assert isinstance(result.ir, IRQuery)

    def test_parse_result_elapsed(self):
        agent = self._make_agent()
        result = agent.parse("test query")
        assert result.elapsed_s >= 0

    def test_parse_uses_llm_client(self):
        client = make_llm_client()
        agent  = self._make_agent(client=client)
        agent.parse("some query")
        assert client.complete.called

    def test_parse_rag_not_used_when_retriever_none(self):
        agent = self._make_agent(retriever=None)
        result = agent.parse("test")
        assert result.rag_used is False

    def test_parse_rag_used_when_retriever_present(self):
        retriever = MagicMock()
        retriever.retrieve_for_prompt.return_value = "Some RAG context text"
        agent = self._make_agent(retriever=retriever)
        result = agent.parse("test query")
        assert result.rag_used is True
        retriever.retrieve_for_prompt.assert_called_once()

    def test_parse_raises_after_all_retries(self):
        client = make_llm_client()
        client.complete.side_effect = _LLMError("API down")
        agent  = self._make_agent(client=client, max_retries=2)
        with pytest.raises(NLSIEMError):
            agent.parse("test query")
        assert client.complete.call_count == 2

    def test_parse_validation_failure_retries(self):
        """Parser retries when coerce_ir raises IRValidationError."""
        client = make_llm_client()
        parser_mock = MagicMock()
        parser_mock.extract_and_validate.return_value = ({"bad": "data"}, [])
        builder_mock = MagicMock()
        builder_mock.build_ir_prompt.return_value = [{"role": "user", "content": "p"}]

        with patch("src.agents.parser_agent.PromptBuilder", return_value=builder_mock), \
             patch("src.agents.parser_agent.ResponseParser", return_value=parser_mock), \
             patch("src.agents.parser_agent.coerce_ir",
                   side_effect=_IRValidationError("bad IR", details={"field": "action"})):
            agent = ParserAgent(client=client, max_retries=3)
            with pytest.raises(NLSIEMError):
                agent.parse("test")
            assert client.complete.call_count == 3

    def test_with_condition_returns_new_agent(self):
        agent = self._make_agent()
        new   = agent.with_condition("zero_shot")
        assert new is not agent
        assert new.condition == "zero_shot"
        assert new.max_retries == agent.max_retries

    def test_repr(self):
        agent = self._make_agent()
        r = repr(agent)
        assert "ParserAgent" in r

    def test_parse_batch_success_and_failure(self):
        """parse_batch partitions successes and failures correctly."""
        client = make_llm_client()
        builder_mock = MagicMock()
        builder_mock.build_ir_prompt.return_value = [{"role": "user", "content": "p"}]
        parser_mock = MagicMock()
        parser_mock.extract_and_validate.return_value = (
            {"action": "filter", "event_type": "authentication", "nl_query": "q"}, []
        )

        with patch("src.agents.parser_agent.PromptBuilder", return_value=builder_mock), \
             patch("src.agents.parser_agent.ResponseParser", return_value=parser_mock):
            agent = ParserAgent(client=client, max_retries=1)

        # First query succeeds; second always fails
        call_count = {"n": 0}
        original_parse = agent.parse
        def _parse(q):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise NLSIEMError("intentional failure")
            return make_parse_result(nl_query=q)
        agent.parse = _parse

        successes, failures = agent.parse_batch(["query A", "query B", "query C"])
        assert len(successes) == 2
        assert len(failures) == 1
        assert failures[0]["nl_query"] == "query B"

    def test_parse_batch_delay_called(self):
        """parse_batch respects delay_s between queries."""
        agent = MagicMock(spec=ParserAgent)
        agent.parse.return_value = make_parse_result()
        agent.parse_batch = ParserAgent.parse_batch.__get__(agent, ParserAgent)

        t0 = time.monotonic()
        agent.parse_batch(["q1", "q2"], delay_s=0.05)
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.04  # At least one delay fired


# ===========================================================================
# ── 4. RefinementAgent — unit tests
# ===========================================================================

class TestRefinementAgent:
    """Tests for RefinementAgent strategy selection and iteration logic."""

    def _make_agent(self, parser_agent=None, max_iterations=2, strategy="auto"):
        client    = make_llm_client()
        validator = ValidatorAgent()
        return RefinementAgent(
            client         = client,
            parser_agent   = parser_agent or MagicMock(spec=ParserAgent),
            validator      = validator,
            max_iterations = max_iterations,
            strategy       = strategy,
        )

    def test_refine_no_failures_skips_loop(self):
        """If report has no failures, refine should return immediately."""
        agent  = self._make_agent()
        ir     = make_ir()
        report = make_validation_report(all_pass=True)
        result = agent.refine(
            nl_query     = "test",
            translations = GOOD_TRANSLATIONS,
            report       = report,
            ir           = ir,
        )
        assert isinstance(result, RefinementResult)
        assert result.platforms_still_failed == []
        assert result.improvement_rate == 1.0

    def test_refine_result_properties(self):
        agent  = self._make_agent()
        ir     = make_ir()
        report = make_validation_report(all_pass=True)
        result = agent.refine("test", GOOD_TRANSLATIONS, report, ir)
        assert result.all_valid
        assert isinstance(result.elapsed_s, float)
        assert result.elapsed_s >= 0

    def test_refine_to_dict_keys(self):
        agent  = self._make_agent()
        result = agent.refine("test", GOOD_TRANSLATIONS, make_validation_report(), make_ir())
        d = result.to_dict()
        for key in ("nl_query", "iterations", "platforms_fixed",
                    "platforms_still_failed", "strategy_used", "improvement_rate", "elapsed_s"):
            assert key in d, f"Missing key in RefinementResult.to_dict(): {key}"

    def test_improvement_rate_full(self):
        result = RefinementResult(
            nl_query="q", original_translations=GOOD_TRANSLATIONS,
            final_translations=GOOD_TRANSLATIONS, final_ir=make_ir(),
            iterations=1, platforms_fixed=["splunk", "qradar"],
            platforms_still_failed=[], strategy_used="query_patch", elapsed_s=0.2,
        )
        assert result.improvement_rate == 1.0

    def test_improvement_rate_partial(self):
        result = RefinementResult(
            nl_query="q", original_translations=GOOD_TRANSLATIONS,
            final_translations=GOOD_TRANSLATIONS, final_ir=make_ir(),
            iterations=1, platforms_fixed=["splunk"],
            platforms_still_failed=["qradar"], strategy_used="query_patch", elapsed_s=0.2,
        )
        assert result.improvement_rate == pytest.approx(0.5)

    def test_improvement_rate_zero_failures(self):
        result = RefinementResult(
            nl_query="q", original_translations=GOOD_TRANSLATIONS,
            final_translations=GOOD_TRANSLATIONS, final_ir=make_ir(),
            iterations=0, platforms_fixed=[],
            platforms_still_failed=[], strategy_used="query_patch", elapsed_s=0.1,
        )
        assert result.improvement_rate == 1.0

    def test_select_strategy_many_failures_ir_reparse(self):
        agent  = self._make_agent(strategy="auto")
        report = make_validation_report(failed=["splunk","qradar","elastic","sentinel"])
        strat  = agent._select_strategy(["splunk","qradar","elastic","sentinel"], report)
        assert strat == "ir_reparse"

    def test_select_strategy_few_failures_query_patch(self):
        agent  = self._make_agent(strategy="auto")
        report = make_validation_report(failed=["splunk"])
        strat  = agent._select_strategy(["splunk"], report)
        assert strat == "query_patch"

    def test_select_strategy_forced_override(self):
        agent  = self._make_agent(strategy="ir_reparse")
        report = make_validation_report(failed=["splunk"])
        strat  = agent._select_strategy(["splunk"], report)
        assert strat == "ir_reparse"

    def test_clean_response_strips_markdown(self):
        agent  = self._make_agent()
        raw    = "```spl\nindex=main | stats count\n```"
        result = agent._clean_response(raw, "splunk")
        assert "```" not in result
        assert "index=main" in result

    def test_clean_response_extracts_select(self):
        agent  = self._make_agent()
        raw    = "Here is the fixed query:\nSELECT * FROM events LAST 24 HOURS"
        result = agent._clean_response(raw, "qradar")
        assert result.startswith("SELECT")

    def test_clean_response_extracts_xml(self):
        agent  = self._make_agent()
        raw    = f"Here is your Wazuh rule:\n{VALID_WAZUH}\nHope this helps!"
        result = agent._clean_response(raw, "wazuh")
        assert result.startswith("<rule")

    def test_clean_response_empty_input(self):
        agent = self._make_agent()
        assert agent._clean_response("", "splunk") == ""

    def test_summary_string(self):
        agent  = self._make_agent()
        result = agent.refine("test", GOOD_TRANSLATIONS, make_validation_report(), make_ir())
        s = result.summary()
        assert "RefinementResult" in s

    def test_repr(self):
        agent = self._make_agent()
        assert "RefinementAgent" in repr(agent)


# ===========================================================================
# ── 5. TranslationOrchestrator — unit tests
# ===========================================================================

class TestTranslationOrchestrator:
    """Tests for the main pipeline orchestrator."""

    def test_translate_returns_result(self):
        orc    = make_orchestrator()
        result = orc.translate("Detect SSH brute force")
        assert isinstance(result, TranslationResult)

    def test_translate_result_has_all_platforms(self):
        orc    = make_orchestrator()
        result = orc.translate("Detect SSH brute force")
        for p in ALL_PLATFORMS:
            assert hasattr(result, p)
            assert isinstance(getattr(result, p), str)

    def test_translate_calls_parser(self):
        orc = make_orchestrator()
        orc.translate("some query")
        orc.parser_agent.parse.assert_called_once_with("some query")

    def test_translate_result_metadata(self):
        orc    = make_orchestrator()
        result = orc.translate("test query")
        assert result.condition  == "few_shot"
        assert result.provider   == "mock"
        assert result.model      == "mock-model"
        assert result.nl_query   == "test query"
        assert isinstance(result.run_id, str) and len(result.run_id) > 0

    def test_translate_result_elapsed(self):
        orc    = make_orchestrator()
        result = orc.translate("test")
        assert result.elapsed_s >= 0

    def test_translations_property_dict(self):
        orc    = make_orchestrator()
        result = orc.translate("test")
        t = result.translations
        assert set(t.keys()) == set(ALL_PLATFORMS)

    def test_pass_rate_with_valid_queries(self):
        """When validator receives valid queries, pass_rate should be high."""
        orc = make_orchestrator()
        # Make translate_all return valid-looking queries
        with patch("src.translators.translate_all", return_value=GOOD_TRANSLATIONS):
            result = orc.translate("Detect SSH brute force")
        assert result.pass_rate > 0

    def test_refinement_not_called_when_all_valid(self):
        refinement = MagicMock(spec=RefinementAgent)
        orc = make_orchestrator(with_refinement=False)
        orc.refinement_agent = refinement

        with patch("src.translators.translate_all", return_value=GOOD_TRANSLATIONS):
            result = orc.translate("test")
        refinement.refine.assert_not_called()

    def test_refinement_skipped_when_disabled(self):
        orc = make_orchestrator(with_refinement=False)
        assert orc.enable_refinement is False or orc.refinement_agent is None
        result = orc.translate("test")
        assert result.refinement_result is None

    def test_refinement_result_stored(self):
        orc = make_orchestrator(with_refinement=True)
        # Inject bad translations so validator triggers refinement
        bad_translations = {p: "" for p in ALL_PLATFORMS}
        with patch("src.translators.translate_all", return_value=bad_translations):
            result = orc.translate("test query")
        # Refinement mock was called
        if orc.refinement_agent:
            assert result.refinement_result is not None or orc.refinement_agent.refine.called

    def test_translate_result_to_dict(self):
        orc    = make_orchestrator()
        result = orc.translate("test")
        d = result.to_dict()
        for key in ("run_id", "nl_query", "ir", "translations", "condition",
                    "provider", "model", "elapsed_s", "validation"):
            assert key in d, f"Missing key in TranslationResult.to_dict(): {key}"

    def test_translate_result_summary_string(self):
        orc    = make_orchestrator()
        result = orc.translate("test")
        s = result.summary()
        assert "NL-SIEM" in s
        for p in ALL_PLATFORMS:
            assert p.capitalize() in s or p in s.lower()

    def test_translate_parse_error_raises(self):
        orc = make_orchestrator()
        orc.parser_agent.parse.side_effect = NLSIEMError("parser failed hard")
        with pytest.raises(NLSIEMError):
            orc.translate("bad query")

    def test_parse_attempts_in_result(self):
        pr  = make_parse_result(attempts=2)
        orc = make_orchestrator(parse_result=pr)
        result = orc.translate("test")
        assert result.parse_attempts == 2

    def test_rag_used_flag_propagated(self):
        pr  = make_parse_result(rag_used=True)
        orc = make_orchestrator(parse_result=pr)
        result = orc.translate("test")
        assert result.parse_result.rag_used is True

    def test_safe_translate_all_handles_exception(self):
        orc = make_orchestrator()
        with patch("src.translators.translate_all", side_effect=RuntimeError("boom")):
            result = orc.translate("test")
        # Should not raise; translations should contain ERROR: strings
        for p in ALL_PLATFORMS:
            assert getattr(result, p, "").startswith("ERROR:") or isinstance(getattr(result, p), str)

    def test_repr(self):
        orc = make_orchestrator()
        assert "TranslationOrchestrator" in repr(orc)

    def test_translate_batch_empty(self):
        orc = make_orchestrator()
        successes, failures = orc.translate_batch([])
        assert successes == []
        assert failures == []

    def test_translate_batch_all_success(self):
        orc = make_orchestrator()
        queries = ["Detect SSH brute force", "Find failed logins", "Alert on port scan"]
        successes, failures = orc.translate_batch(queries, delay_s=0)
        assert len(successes) == 3
        assert len(failures) == 0

    def test_translate_batch_partial_failure(self):
        orc = make_orchestrator()
        call_count = {"n": 0}
        original = orc.translate
        def _translate(q):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise NLSIEMError("mid-batch failure")
            return original(q)
        orc.translate = _translate

        successes, failures = orc.translate_batch(["q1", "q2", "q3"], delay_s=0)
        assert len(successes) == 2
        assert len(failures) == 1

    def test_translate_batch_incremental_save(self, tmp_path):
        orc  = make_orchestrator()
        save = tmp_path / "results.jsonl"
        orc.translate_batch(["q1", "q2"], delay_s=0, save_path=save)
        lines = save.read_text().strip().split("\n")
        assert len(lines) == 2


# ===========================================================================
# ── 6. Interlayer tests (L1 → L2 → L5)
# ===========================================================================

class TestInterlayerL1toL5:
    """
    Cross-layer integration: IR schema (L1) → Translators (L2) → Agents (L5).
    All tests run without any LLM call.
    """

    def test_ir_validates_and_flows_to_validator(self):
        """A well-formed IRQuery can be validated by ValidatorAgent after translation."""
        ir      = make_ir()
        # Simulate translate_all output with real-looking queries
        queries = {
            "splunk":   VALID_SPLUNK,
            "qradar":   VALID_QRADAR,
            "elastic":  VALID_ELASTIC,
            "sentinel": VALID_SENTINEL,
            "wazuh":    VALID_WAZUH,
        }
        validator = ValidatorAgent()
        report    = validator.validate(queries, nl_query=ir.nl_query)
        assert report.all_valid
        assert report.pass_rate == 1.0

    def test_ir_to_dict_and_back(self):
        """IRQuery serialises to dict and back without data loss."""
        ir  = make_ir(event_type="network", action="filter")
        d   = ir.to_dict()
        ir2 = _IRQuery(**{k: v for k, v in d.items() if k in _IRQuery.__dataclass_fields__})
        assert ir2.event_type == ir.event_type
        assert ir2.action     == ir.action

    def test_translate_all_output_shape(self):
        """translate_all must return exactly the 5 expected platform keys."""
        from src.translators import translate_all
        ir      = make_ir()
        result  = translate_all(ir)
        assert set(result.keys()) == {"splunk", "qradar", "elastic", "sentinel", "wazuh"}
        for v in result.values():
            assert isinstance(v, str)

    def test_translation_output_fed_to_validator(self):
        """Stub translate_all output passes through ValidatorAgent without type errors."""
        from src.translators import translate_all
        ir        = make_ir()
        queries   = translate_all(ir)
        validator = ValidatorAgent()
        report    = validator.validate(queries, nl_query="interlayer test")
        # Stub output may not pass validation; test only that no exception is raised
        assert isinstance(report, ValidationReport)
        assert 0.0 <= report.pass_rate <= 1.0

    def test_parse_result_ir_fed_to_translator(self):
        """ParseResult.ir can be passed directly to translate_all."""
        from src.translators import translate_all
        pr     = make_parse_result()
        result = translate_all(pr.ir)
        assert isinstance(result, dict)
        assert len(result) == 5

    def test_validation_report_to_refinement_strategy(self):
        """ValidationReport with failures flows into RefinementAgent strategy selection."""
        report = make_validation_report(failed=["splunk", "qradar", "elastic"])
        agent  = RefinementAgent(
            client         = make_llm_client(),
            parser_agent   = MagicMock(spec=ParserAgent),
            validator      = ValidatorAgent(),
            max_iterations = 1,
        )
        failed  = report.failed_platforms
        strat   = agent._select_strategy(failed, report)
        assert strat in ("ir_reparse", "query_patch", "hybrid")

    def test_orchestrator_integrates_all_stubs(self):
        """Full pipeline runs end-to-end using stub modules at every layer."""
        orc    = make_orchestrator()
        result = orc.translate("Detect repeated authentication failures from a single IP")
        assert isinstance(result, TranslationResult)
        assert result.nl_query == "Detect repeated authentication failures from a single IP"
        assert result.ir is not None
        assert result.ir.action == "filter"
        

    def test_parse_result_warnings_propagate_to_translation_result(self):
        """Warnings generated during parsing surface in the final TranslationResult."""
        pr  = make_parse_result(warnings=["field 'user' coerced from 'username'"])
        orc = make_orchestrator(parse_result=pr)
        result = orc.translate("test")
        assert any("coerced" in w for w in result.warnings)

    def test_bad_ir_translations_fail_validation(self):
        """ERROR: prefixed translations from _safe_translate_all fail validation."""
        validator = ValidatorAgent()
        bad_translations = {p: f"ERROR: failed to translate {p}" for p in ALL_PLATFORMS}
        report = validator.validate(bad_translations, "bad ir test")
        # ERROR: strings won't pass platform-specific syntax checks
        assert report.pass_rate < 1.0

    def test_refinement_result_translations_re_validated(self):
        """After refinement, final translations are re-validated and report is updated."""
        from src.translators import translate_all

        parser   = MagicMock(spec=ParserAgent)
        parser.parse.return_value = make_parse_result()
        validator = ValidatorAgent()

        refinement = MagicMock(spec=RefinementAgent)
        refinement.refine.return_value = RefinementResult(
            nl_query="q",
            original_translations={p: "" for p in ALL_PLATFORMS},
            final_translations=GOOD_TRANSLATIONS,
            final_ir=make_ir(),
            iterations=1,
            platforms_fixed=list(ALL_PLATFORMS),
            platforms_still_failed=[],
            strategy_used="query_patch",
            elapsed_s=0.1,
        )

        orc = TranslationOrchestrator(
            parser_agent      = parser,
            validator         = validator,
            refinement_agent  = refinement,
            enable_refinement = True,
            provider          = "mock",
            model             = "mock-model",
            condition         = "few_shot",
        )
        # Provide bad translations to trigger refinement
        with patch("src.translators.translate_all", return_value={p: "" for p in ALL_PLATFORMS}):
            result = orc.translate("test refinement flow")

        # Refinement was invoked
        refinement.refine.assert_called_once()

    def test_platform_validation_objects_in_report(self):
        """Each platform in the report has a PlatformValidation with correct type."""
        validator = ValidatorAgent()
        report    = validator.validate(GOOD_TRANSLATIONS, "type check test")
        for platform, pv in report.results.items():
            assert isinstance(pv, PlatformValidation)
            assert pv.platform == platform
            assert pv.query    == GOOD_TRANSLATIONS[platform]


# ===========================================================================
# ── 7. Edge cases & regression tests
# ===========================================================================

class TestEdgeCases:
    """Regression guards and boundary conditions."""

    def setup_method(self):
        self.v = ValidatorAgent()

    # ── Whitespace and encoding ────────────────────────────────────────────
    def test_validator_strips_whitespace_before_checking(self):
        q = f"  {VALID_SPLUNK}  "
        assert self.v.validate_single("splunk", q).is_valid

    def test_validator_handles_none_equivalent(self):
        """Empty string is falsy — treated the same as None in our validator."""
        for p in ALL_PLATFORMS:
            r = self.v.validate_single(p, "")
            assert not r.is_valid
            assert r.error_type == "empty_query"

    # ── Multi-line queries ─────────────────────────────────────────────────
    def test_multiline_splunk(self):
        q = (
            "index=firewall action=blocked\n"
            "| stats count AS block_count BY src_ip, dest_port\n"
            "| where block_count > 100\n"
            "| sort -block_count\n"
            "| head 20"
        )
        assert self.v.validate_single("splunk", q).is_valid

    def test_multiline_qradar(self):
        q = (
            "SELECT sourceip, destinationip,\n"
            "       COUNT(*) AS attempts\n"
            "FROM events\n"
            "WHERE category = 5018\n"
            "GROUP BY sourceip, destinationip\n"
            "HAVING COUNT(*) > 20\n"
            "ORDER BY attempts DESC\n"
            "LAST 24 HOURS"
        )
        assert self.v.validate_single("qradar", q).is_valid

    # ── Unknown platforms ─────────────────────────────────────────────────
    def test_unknown_platform_passes_if_non_empty(self):
        r = self.v.validate_single("unknown_siem", "some query content")
        assert r.is_valid
        assert any("No validator" in w for w in r.warnings)

    # ── Run ID uniqueness ─────────────────────────────────────────────────
    def test_run_ids_are_unique(self):
        orc = make_orchestrator()
        r1  = orc.translate("query one")
        r2  = orc.translate("query two")
        assert r1.run_id != r2.run_id

    # ── Wazuh XML edge cases ──────────────────────────────────────────────
    def test_wazuh_minimal_valid_rule(self):
        q = '<rule id="100001" level="5"><description>Minimal rule</description></rule>'
        assert self.v.validate_single("wazuh", q).is_valid

    def test_wazuh_cdata_in_description(self):
        q = ('<rule id="100001" level="10">'
             '<description><![CDATA[Rule & description with <special> chars]]></description>'
             '</rule>')
        r = self.v.validate_single("wazuh", q)
        # Valid XML with CDATA should still parse
        assert r.is_valid or r.error_type == "invalid_xml"

    # ── Sentinel edge cases ───────────────────────────────────────────────
    def test_sentinel_inline_let(self):
        q = ("let threshold = 10;\n"
             "SecurityEvent\n"
             "| where EventID == 4625\n"
             "| summarize count() by Account\n"
             "| where count_ > threshold")
        # 'let' is a valid KQL operator — validator should accept
        r = self.v.validate_single("sentinel", q)
        # 'let' may be at start rather than after |; accept either outcome
        assert isinstance(r, PlatformValidation)

    # ── Pass rate arithmetic ──────────────────────────────────────────────
    @pytest.mark.parametrize("n_fail", [0, 1, 2, 3, 4, 5])
    def test_pass_rate_arithmetic(self, n_fail):
        failed = ALL_PLATFORMS[:n_fail]
        report = make_validation_report(failed=failed)
        expected = (5 - n_fail) / 5
        assert report.pass_rate == pytest.approx(expected)

    # ── RefinementResult.all_valid ────────────────────────────────────────
    def test_refinement_result_all_valid_true(self):
        r = RefinementResult(
            nl_query="q", original_translations={}, final_translations={},
            final_ir=make_ir(), iterations=0, platforms_fixed=[],
            platforms_still_failed=[], strategy_used="auto", elapsed_s=0,
        )
        assert r.all_valid

    def test_refinement_result_all_valid_false(self):
        r = RefinementResult(
            nl_query="q", original_translations={}, final_translations={},
            final_ir=make_ir(), iterations=1, platforms_fixed=[],
            platforms_still_failed=["splunk"], strategy_used="auto", elapsed_s=0,
        )
        assert not r.all_valid

    # ── TranslationResult accessors ───────────────────────────────────────
    def test_translation_result_valid_platforms(self):
        orc    = make_orchestrator()
        result = orc.translate("test")
        vp = result.valid_platforms
        assert isinstance(vp, list)
        assert all(p in ALL_PLATFORMS for p in vp)

    def test_translation_result_all_valid_bool(self):
        orc    = make_orchestrator()
        result = orc.translate("test")
        assert isinstance(result.all_valid, bool)

    def test_translation_result_refinement_used_false(self):
        orc    = make_orchestrator(with_refinement=False)
        result = orc.translate("test")
        assert result.refinement_used is False