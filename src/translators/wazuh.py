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

Example output (failed SSH logins, 10 in 60 s, same source IP):
    <rule id="100001" level="10">
      <if_matched_sid>5716</if_matched_sid>
      <same_source_ip/>
      <frequency>10</frequency>
      <timeframe>60</timeframe>
      <group>authentication_failures,</group>
      <description>SSH brute force: failed logins from one source IP</description>
      <mitre>
        <id>T1110.001</id>
      </mitre>
    </rule>

CHANGES vs. previous version (validated against a real syslog auth.log):
  1. Parent SID: 5710 is "attempt to login using a NON-EXISTENT user" — it does
     not cover ordinary failed passwords. Failed SSH logins are 5716, accepted
     logins are 5715. The parent is now chosen from the IR outcome.
  2. Threshold rules use <if_matched_sid> (Wazuh pairs frequency/timeframe with
     if_matched_*), plain rules keep <if_sid>.
  3. IR conditions that the parent rule already guarantees (status=failed,
     service=ssh) are no longer emitted as <match>failed</match> — that text was
     lower-case, Wazuh match is case-sensitive, and the real log says "Failed",
     so the rule could never fire.
  4. At most one <match> and one <regex> per rule. IN-lists are merged into one
     OR-ed pattern ("a|b") instead of several <match> tags, which are ANDed.
  5. Source/destination IP equality uses <srcip>/<dstip> instead of <match>.
"""

from __future__ import annotations

import itertools
import re
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
# NOTE: the AUTHENTICATION default assumes sshd (Linux auth.log). Other log
# sources (Windows 4625, RDP, web apps) need their own parent SIDs.
EVENT_CONFIG: dict[str, dict] = {
    EventType.AUTHENTICATION: {
        "group":  "authentication_failures",
        "if_sid": "5716",      # sshd: authentication failed (5710 = non-existent user only)
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

# Authentication: parent SID by outcome found in the IR filter (sshd).
AUTH_PARENT_BY_OUTCOME: dict[str, str] = {
    "failed":  "5716",   # sshd: authentication failed
    "success": "5715",   # sshd: authentication success
}

# IR filter conditions the parent rule already guarantees → not re-emitted.
_OUTCOME_FIELDS = {"status", "outcome", "event_outcome", "result"}
_FAILED_VALUES  = {"failed", "failure", "fail", "denied", "unsuccessful"}
_SUCCESS_VALUES = {"success", "successful", "succeeded", "accepted", "ok"}
_SSH_FIELDS     = {"service", "protocol", "app", "application", "program",
                   "program_name", "process_name", "auth_type"}
_SSH_VALUES     = {"ssh", "sshd"}

# Base rule ID for generated custom rules.
# Incrementing counter (module-level, persists across calls in a process) so
# two generated rules never share one id. For reproducible regeneration of the
# *same* detection, an ID derived from ir.id is preferred (see _derive_rule_id).
_rule_id_counter = itertools.count(100002)


class WazuhTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into Wazuh XML rule definitions."""

    PLATFORM = "wazuh"

    def _translate(self, ir: IRQuery) -> str:
        """Generate a Wazuh XML rule from an IRQuery."""

        config = EVENT_CONFIG.get(ir.event_type, EVENT_CONFIG[EventType.ANY])
        rule_id = self._derive_rule_id(ir.id) if ir.id else next(_rule_id_counter)

        rule = ET.Element("rule", attrib={
            "id":    str(rule_id),
            "level": config["level"],
        })

        # ── Parent rule reference ─────────────────────────────────────────
        # Pick the parent from the IR outcome (failed/success) and remember
        # which IR conditions that parent already covers.
        outcome, covered = self._scan_filter(ir)
        parent_sid = AUTH_PARENT_BY_OUTCOME.get(outcome) or config["if_sid"]
        if parent_sid:
            # Wazuh pairs frequency/timeframe with if_matched_sid.
            parent_tag = "if_matched_sid" if ir.threshold else "if_sid"
            ET.SubElement(rule, parent_tag).text = parent_sid

        # ── Filter conditions → match/regex/field tags ─────────────────────
        if ir.filter:
            self._add_filter_conditions(rule, ir.filter, covered)

        # ── Aggregation: same_* grouping tags ─────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation:
            for group_field in ir.aggregation.group_by:
                wazuh_field = self._resolve(group_field)
                tag = self._get_same_tag(wazuh_field)
                ET.SubElement(rule, tag)

        # ── Threshold → frequency + timeframe ─────────────────────────────
        # <timeframe> only has effect paired with <frequency>. Wazuh rules
        # trigger on live event streams; there is no "query the last N hours".
        if ir.threshold:
            ET.SubElement(rule, "frequency").text = str(ir.threshold.value)
            if ir.time_window:
                ET.SubElement(rule, "timeframe").text = str(ir.time_window.to_seconds)
        elif ir.time_window:
            log.warning(
                "time_window with no threshold has no Wazuh XML equivalent "
                "— <timeframe> only has effect paired with <frequency> — "
                "condition dropped from generated rule",
                extra={"duration": ir.time_window.duration},
            )
            rule.append(ET.Comment(
                f" NOTE: time_window={ir.time_window.duration} has no Wazuh "
                f"XML equivalent without a threshold — Wazuh rules trigger "
                f"on live events, not a bounded historical query; verify "
                f"manually "
            ))

        # ── Group tag ─────────────────────────────────────────────────────
        group = "authentication_success" if outcome == "success" else config["group"]
        ET.SubElement(rule, "group").text = group + ","

        # ── Description ───────────────────────────────────────────────────
        ET.SubElement(rule, "description").text = self._build_description(ir)

        # ── MITRE ATT&CK ──────────────────────────────────────────────────
        if ir.attck_mappings:
            mitre_el = ET.SubElement(rule, "mitre")
            seen = set()
            for m in ir.attck_mappings:
                tid = m.sub_technique_id or m.technique_id
                if tid and tid not in seen:
                    seen.add(tid)
                    ET.SubElement(mitre_el, "id").text = tid
        elif ir.technique_id:
            mitre_el = ET.SubElement(rule, "mitre")
            ET.SubElement(mitre_el, "id").text = ir.technique_id

        return self._pretty_xml(rule)

    # ─────────────────────────────────────────────
    # Parent-rule helpers
    # ─────────────────────────────────────────────

    def _scan_filter(self, ir: IRQuery) -> tuple[str | None, set[int]]:
        """
        Look at the top-level AND-ed IR filter conditions of an authentication
        query and return (outcome, ids_of_conditions_the_parent_rule_covers).

        outcome is "failed", "success" or None. Conditions such as
        status == failed or service == ssh are implied by parent rule
        5716 / 5715, so emitting them again as <match> only adds ways for the
        rule to silently never fire (case sensitivity, wording).
        """
        outcome: str | None = None
        covered: set[int] = set()
        if ir.event_type != EventType.AUTHENTICATION or not ir.filter:
            return outcome, covered
        # Only skip conditions when they are AND-ed; inside an OR they are not
        # implied by the parent rule.
        if not str(getattr(ir.filter, "operator", "and")).lower().endswith("and"):
            return outcome, covered

        for cond in ir.filter.conditions:
            if (not isinstance(cond, FilterCondition)
                    or cond.negate
                    or cond.op != ComparisonOperator.EQ):
                continue
            val = str(cond.value).strip().lower()
            if cond.field in _OUTCOME_FIELDS and val in _FAILED_VALUES:
                outcome = "failed"
                covered.add(id(cond))
            elif cond.field in _OUTCOME_FIELDS and val in _SUCCESS_VALUES:
                outcome = "success"
                covered.add(id(cond))
            elif cond.field in _SSH_FIELDS and val in _SSH_VALUES:
                covered.add(id(cond))
        return outcome, covered

    # ─────────────────────────────────────────────
    # Filter condition → Wazuh XML tags
    # ─────────────────────────────────────────────

    def _add_filter_conditions(
        self,
        rule: ET.Element,
        group: FilterGroup,
        covered: frozenset[int] | set[int] = frozenset(),
    ) -> None:
        """
        Recursively add filter conditions as Wazuh XML tags.

        Wazuh tags are ANDed implicitly. OR logic is limited: IN-lists are
        merged into one pattern with "|".
        """
        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                if id(cond) in covered:
                    continue
                self._add_condition_tag(rule, cond)
            elif isinstance(cond, FilterGroup):
                self._add_filter_conditions(rule, cond, covered)

    def _add_condition_tag(self, rule: ET.Element, cond: FilterCondition) -> None:
        """Convert a single FilterCondition into Wazuh XML tag(s)."""
        field   = self._resolve(cond.field)
        op      = cond.op
        value   = cond.value

        if op == ComparisonOperator.EQ:
            if cond.field in ("event_id", "event_type", "category"):
                # <id> is reserved for the rule's own ID / <mitre><id>; use the
                # generic <field name="..."> tag for these.
                tag = ET.SubElement(rule, "field", attrib={"name": field})
                tag.text = str(value)
                if cond.negate:
                    tag.set("negate", "yes")
            elif field in ("srcip", "dstip"):
                # Dedicated tags (CIDR-aware) instead of a text <match>.
                tag = ET.SubElement(rule, field)
                tag.text = str(value)
                if cond.negate:
                    tag.set("negate", "yes")
            elif field == "dstuser":
                # Exact account name, matched against the decoded user field.
                tag = ET.SubElement(rule, "user")
                tag.text = "^" + self._os_regex_escape(value) + "$"
                if cond.negate:
                    tag.set("negate", "yes")
            else:
                self._add_text_condition(rule, [value], cond.negate)

        elif op == ComparisonOperator.CONTAINS:
            self._add_text_condition(rule, [value], cond.negate)

        elif op == ComparisonOperator.REGEX:
            if rule.find("regex") is None:
                tag = ET.SubElement(rule, "regex")
                tag.text = str(value)
                if cond.negate:
                    tag.set("negate", "yes")
            else:
                self._drop_condition(rule, f"regex {value}")

        elif op == ComparisonOperator.GT:
            # Wazuh XML has no numeric-comparison filter tag; surface the loss
            # loudly instead of silently omitting the condition.
            log.warning(
                "GT filter condition has no Wazuh XML equivalent outside "
                "ir.threshold — condition dropped from generated rule",
                extra={"field": field, "value": value},
            )
            rule.append(ET.Comment(
                f" DROPPED CONDITION: {field} > {value} "
                f"(no Wazuh XML equivalent — verify manually) "
            ))

        elif op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            negate = (op == ComparisonOperator.NOT_IN) or cond.negate
            if isinstance(value, (list, tuple, set)) and value:
                if field in ("srcip", "dstip"):
                    tag = ET.SubElement(rule, field)
                    tag.text = "|".join(str(v) for v in value)
                    if negate:
                        tag.set("negate", "yes")
                else:
                    self._add_text_condition(rule, list(value), negate)

        else:
            # Fallback — use field tag with value
            tag = ET.SubElement(rule, "field", attrib={"name": field})
            tag.text = str(value)
            if cond.negate:
                tag.set("negate", "yes")

    # ── text-condition helpers ───────────────────────────────────────────
    @staticmethod
    def _os_match_escape(v: object) -> str:
        """Escape the special characters of Wazuh's <match> syntax."""
        return re.sub(r"([\\^$|!])", r"\\\1", str(v))

    @staticmethod
    def _os_regex_escape(v: object) -> str:
        """Escape the special characters of Wazuh's OS_Regex (<regex>) syntax."""
        return re.sub(r"([\\^$|()+*])", r"\\\1", str(v))

    def _add_text_condition(
        self, rule: ET.Element, values: list, negate: bool = False
    ) -> None:
        """
        Add a text condition. Wazuh allows one <match> and one <regex> per rule,
        so the first condition becomes <match>, the second <regex>, and any
        further one is reported as dropped instead of emitting a duplicate tag.
        Several values are OR-ed with "|".
        """
        if rule.find("match") is None:
            tag = ET.SubElement(rule, "match")
            tag.text = "|".join(self._os_match_escape(v) for v in values)
        elif rule.find("regex") is None:
            tag = ET.SubElement(rule, "regex")
            tag.text = "|".join(self._os_regex_escape(v) for v in values)
        else:
            self._drop_condition(rule, "|".join(str(v) for v in values))
            return
        if negate:
            tag.set("negate", "yes")

    @staticmethod
    def _drop_condition(rule: ET.Element, what: str) -> None:
        log.warning(
            "Wazuh allows one <match> and one <regex> per rule — extra "
            "condition dropped from generated rule",
            extra={"condition": what},
        )
        rule.append(ET.Comment(
            f" DROPPED CONDITION: {what} (only one <match> and one <regex> "
            f"per rule — verify manually) "
        ))

    @staticmethod
    def _derive_rule_id(ir_id: str) -> int:
        """
        Deterministically map an IR record ID to a custom-range Wazuh
        rule ID (100000-109999), so the same detection always regenerates
        the same rule ID instead of depending on call order.
        """
        import hashlib
        digest = hashlib.sha256(ir_id.encode("utf-8")).hexdigest()
        return 100000 + (int(digest[:8], 16) % 9999)

    def _get_same_tag(self, field: str) -> str:
        """Map a field name to a Wazuh same_* grouping tag."""
        mapping = {
            "srcip":    "same_source_ip",
            "dstip":    "same_destination_ip",   # verify tag name against your Wazuh version
            "dstuser":  "same_user",
            "hostname": "same_location",
        }
        return mapping.get(field, "same_source_ip")

    def _build_description(self, ir: IRQuery) -> str:
        """Generate a human-readable rule description."""
        if ir.nl_query:
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

        try:
            root = ET.fromstring(q)
        except ET.ParseError as exc:
            log.warning("Wazuh XML parse error", extra={"error": str(exc)})
            return False

        if root.tag != "rule":
            return False
        if "id" not in root.attrib or "level" not in root.attrib:
            return False
        if root.find("description") is None:
            return False

        # More than one <match> / <regex> is not valid in a single Wazuh rule.
        for tag in ("match", "regex"):
            if len(root.findall(tag)) > 1:
                log.warning("Wazuh rule has more than one <%s>", tag)
                return False

        # Threshold rules must carry both frequency and timeframe.
        # (warning only — failing here would make the refinement loop retry on
        # something the LLM cannot fix when the IR simply has no time window)
        if (root.find("frequency") is None) != (root.find("timeframe") is None):
            log.warning("Wazuh rule has frequency without timeframe (or vice versa)")

        try:
            rule_id = int(root.attrib["id"])
            if rule_id < 100000:
                log.warning("Wazuh rule ID in reserved range", extra={"id": rule_id})
        except ValueError:
            return False

        return True