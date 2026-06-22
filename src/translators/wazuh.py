"""
Wazuh XML Translator — IR → Wazuh rule XML format.

Wazuh rules are XML-based detection rules, not query languages.
Each rule has:
  - A unique rule ID (100000+ for custom rules)
  - A level (0-15, severity)
  - match/regex conditions on log fields
  - frequency + timeframe for aggregation/threshold
  - same_source_ip / same_user for grouping

Reference: documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

Place at: src/translators/wazuh.py

Example output:
    <rule id="100001" level="10">
      <if_sid>5503</if_sid>
      <match>Failed password</match>
      <same_source_ip/>
      <frequency>50</frequency>
      <timeframe>86400</timeframe>
      <group>authentication_failures,</group>
      <description>Brute force: failed SSH logins from same IP</description>
      <mitre>
        <id>T1110</id>
      </mitre>
    </rule>
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.dom import minidom

from src.ir.schema import (
    ActionType,
    ComparisonOperator,
    EventType,
    FilterCondition,
    FilterGroup,
    IRQuery,
)
from src.translators.base import BaseSIEMTranslator
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Wazuh event type → group tag + base SID mapping ──────────────────────
EVENT_CONFIG: dict[str, dict] = {
    EventType.AUTHENTICATION: {
        "group":  "authentication_failures",
        "if_sid": "5503",      # SSH failed auth (Wazuh built-in)
        "level":  "10",
    },
    EventType.NETWORK: {
        "group":  "network_scan",
        "if_sid": "40101",
        "level":  "8",
    },
    EventType.PROCESS: {
        "group":  "syscheck",
        "if_sid": "554",
        "level":  "12",
    },
    EventType.FILE: {
        "group":  "syscheck",
        "if_sid": "554",
        "level":  "10",
    },
    EventType.REGISTRY: {
        "group":  "windows_registry",
        "if_sid": "750",
        "level":  "10",
    },
    EventType.DNS: {
        "group":  "dns_query",
        "if_sid": "82200",
        "level":  "6",
    },
    EventType.HTTP: {
        "group":  "web,attack",
        "if_sid": "31100",
        "level":  "8",
    },
    EventType.ANY: {
        "group":  "local",
        "if_sid": None,
        "level":  "5",
    },
}

# Base rule ID for generated custom rules
BASE_RULE_ID = 100002


class WazuhTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into Wazuh XML rule definitions."""

    PLATFORM = "wazuh"

    # Wazuh uses match/regex — no comparison operators in the SQL sense
    # We map field conditions to match/regex/field tags

    def _translate(self, ir: IRQuery) -> str:
        """Generate a Wazuh XML rule from an IRQuery."""

        config = EVENT_CONFIG.get(ir.event_type, EVENT_CONFIG[EventType.ANY])
        rule_id = BASE_RULE_ID

        # Build rule element
        rule = ET.Element("rule", attrib={
            "id":    str(rule_id),
            "level": config["level"],
        })

        # ── Parent rule reference ─────────────────────────────────────────
        if config["if_sid"]:
            ET.SubElement(rule, "if_sid").text = config["if_sid"]

        # ── Filter conditions → match/regex/field tags ─────────────────────
        if ir.filter:
            self._add_filter_conditions(rule, ir.filter)

        # ── Aggregation: same_* grouping tags ─────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation:
            for group_field in ir.aggregation.group_by:
                wazuh_field = self._resolve(group_field)
                tag = self._get_same_tag(wazuh_field)
                ET.SubElement(rule, tag)

        # ── Threshold → frequency + timeframe ─────────────────────────────
        if ir.threshold:
            ET.SubElement(rule, "frequency").text = str(ir.threshold.value)

        if ir.time_window:
            ET.SubElement(rule, "timeframe").text = str(ir.time_window.to_seconds)

        # ── Group tag ─────────────────────────────────────────────────────
        ET.SubElement(rule, "group").text = config["group"] + ","

        # ── Description ───────────────────────────────────────────────────
        desc = self._build_description(ir)
        ET.SubElement(rule, "description").text = desc

        # ── MITRE ATT&CK ──────────────────────────────────────────────────
        if ir.technique_id:
            mitre_el = ET.SubElement(rule, "mitre")
            ET.SubElement(mitre_el, "id").text = ir.technique_id

        return self._pretty_xml(rule)

    # ─────────────────────────────────────────────
    # Filter condition → Wazuh XML tags
    # ─────────────────────────────────────────────

    def _add_filter_conditions(self, rule: ET.Element, group: FilterGroup) -> None:
        """
        Recursively add filter conditions as Wazuh XML tags.

        Wazuh match/regex tags are ANDed implicitly.
        OR logic is limited — we handle it by adding multiple match tags.
        """
        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                self._add_condition_tag(rule, cond)
            elif isinstance(cond, FilterGroup):
                self._add_filter_conditions(rule, cond)

    def _add_condition_tag(self, rule: ET.Element, cond: FilterCondition) -> None:
        """Convert a single FilterCondition into Wazuh XML tag(s)."""
        field   = self._resolve(cond.field)
        op      = cond.op
        value   = cond.value

        if op == ComparisonOperator.EQ:
            if cond.field in ("event_id", "event_type", "category"):
                ET.SubElement(rule, "id").text = str(value)
            else:
                tag = ET.SubElement(rule, "match")
                tag.text = str(value)
                if cond.negate:
                    tag.set("negate", "yes")

        elif op == ComparisonOperator.CONTAINS:
            tag = ET.SubElement(rule, "match")
            tag.text = str(value)
            if cond.negate:
                tag.set("negate", "yes")

        elif op == ComparisonOperator.REGEX:
            tag = ET.SubElement(rule, "regex")
            tag.text = str(value)
            if cond.negate:
                tag.set("negate", "yes")

        elif op == ComparisonOperator.GT:
            # Wazuh handles numeric thresholds via frequency — log a note
            log.debug(
                "GT condition mapped to frequency in Wazuh",
                extra={"field": field, "value": value},
            )

        elif op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            negate = (op == ComparisonOperator.NOT_IN) or cond.negate
            if isinstance(value, list):
                for v in value:
                    tag = ET.SubElement(rule, "match")
                    tag.text = str(v)
                    if negate:
                        tag.set("negate", "yes")

        else:
            # Fallback — use field tag with value
            tag = ET.SubElement(rule, "field", attrib={"name": field})
            tag.text = str(value)
            if cond.negate:
                tag.set("negate", "yes")

    def _get_same_tag(self, field: str) -> str:
        """Map a field name to a Wazuh same_* grouping tag."""
        mapping = {
            "srcip":    "same_source_ip",
            "dstip":    "same_destination_ip",
            "dstuser":  "same_user",
            "hostname": "same_location",
        }
        return mapping.get(field, "same_source_ip")

    def _build_description(self, ir: IRQuery) -> str:
        """Generate a human-readable rule description."""
        if ir.nl_query:
            # Truncate long NL queries
            return ir.nl_query[:120]

        parts = []
        if ir.tactic:
            parts.append(ir.tactic.replace("_", " ").title())
        if ir.event_type and ir.event_type != "any":
            parts.append(ir.event_type + " event")
        if ir.threshold:
            parts.append(f"threshold {ir.threshold.value}")
        if ir.time_window:
            parts.append(f"in {ir.time_window.duration}")

        return " — ".join(parts) if parts else "Custom detection rule"

    def _pretty_xml(self, element: ET.Element) -> str:
        """Return a pretty-printed XML string."""
        raw = ET.tostring(element, encoding="unicode")
        parsed = minidom.parseString(raw)
        pretty = parsed.toprettyxml(indent="  ")
        # Remove the XML declaration line minidom adds
        lines = pretty.split("\n")
        if lines[0].startswith("<?xml"):
            lines = lines[1:]
        return "\n".join(l for l in lines if l.strip())

    # ─────────────────────────────────────────────
    # Syntax validator
    # ─────────────────────────────────────────────

    def validate(self, query: str) -> bool:
        """Validate generated Wazuh XML rule structure."""
        if not query or not isinstance(query, str):
            return False
        q = query.strip()

        # Must be valid XML
        try:
            root = ET.fromstring(q)
        except ET.ParseError as exc:
            log.warning("Wazuh XML parse error", extra={"error": str(exc)})
            return False

        # Must be a <rule> element
        if root.tag != "rule":
            return False

        # Must have id and level attributes
        if "id" not in root.attrib or "level" not in root.attrib:
            return False

        # Must have a <description>
        if root.find("description") is None:
            return False

        # Rule ID must be in custom range (>= 100000)
        try:
            rule_id = int(root.attrib["id"])
            if rule_id < 100000:
                log.warning(
                    "Wazuh rule ID in reserved range",
                    extra={"id": rule_id},
                )
        except ValueError:
            return False

        return True