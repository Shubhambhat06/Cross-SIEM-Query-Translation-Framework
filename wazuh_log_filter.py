#!/usr/bin/env python3
"""
wazuh_log_filter.py  --  run a Wazuh rule (the XML your NL-SIEM pipeline emits)
against a raw syslog / auth.log file and return the log lines it matches.

Standalone (stdlib only).  Drop it in  src/evaluation/  or the repo root.

Typical use
-----------
  # 1) XML you already have (saved from result.wazuh)
  python wazuh_log_filter.py --log auth_source_log.txt --rule rule.xml

  # 2) straight from natural language, through your own pipeline (run from repo root)
  python wazuh_log_filter.py --log auth_source_log.txt \
         --query "10 failed SSH logins from the same IP within 60 seconds"

  # 3) only the raw matching lines (grep-style) written to a file
  python wazuh_log_filter.py --log auth_source_log.txt --rule rule.xml \
         --format raw --out hits.log

  # 4) "why did I get 0 matches?"
  python wazuh_log_filter.py --log auth_source_log.txt --rule rule.xml --explain

From Python / FastAPI
---------------------
  from wazuh_log_filter import filter_log_text
  out = filter_log_text(result.wazuh, open("auth.log").read())

What is emulated
----------------
Pre-decoding (timestamp / host / program[pid]: message), light decoders for
sshd, pam, sudo, useradd/usermod, ufw, cron, and the rule tags
decoded_as, match, regex (osmatch / osregex / pcre2), program_name, hostname,
location, srcip, dstip (CIDR ok), srcport, dstport, user, id, action, status,
url, protocol, extra_data, field, time, weekday, negate, if_sid, if_group,
if_matched_sid / if_matched_group / if_matched_regex, frequency, timeframe,
ignore, same_source_ip / same_user / same_* .

Parent rules (5501, 5503, 5716, 5402 ...) come from a built-in *approximation*
of Wazuh's stock ruleset.  For exact behaviour pass your manager's real rule
files with  --base-rules /var/ossec/ruleset/rules/0095-sshd_rules.xml ...
This is an offline approximation, NOT a replacement for wazuh-logtest.
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

# --------------------------------------------------------------------------- #
# Built-in approximation of the stock Wazuh parent rules                      #
# --------------------------------------------------------------------------- #
BASELINE_RULES_XML = r"""
<group name="syslog,">
  <!-- PAM -->
  <rule id="5500" level="0"><decoded_as>pam</decoded_as>
    <description>Grouping of PAM rules.</description></rule>
  <rule id="5501" level="3"><if_sid>5500</if_sid><match>session opened</match>
    <description>PAM: Login session opened.</description>
    <group>authentication_success,pam,</group></rule>
  <rule id="5502" level="3"><if_sid>5500</if_sid><match>session closed</match>
    <description>PAM: Login session closed.</description><group>pam,</group></rule>
  <rule id="5503" level="5"><if_sid>5500</if_sid>
    <match>authentication failure|bad username|illegal</match>
    <description>PAM: User login failed.</description>
    <group>authentication_failed,pam,</group></rule>

  <!-- sshd -->
  <rule id="5700" level="0"><decoded_as>sshd</decoded_as>
    <description>SSHD messages grouped.</description></rule>
  <rule id="5710" level="5"><if_sid>5700</if_sid><match>illegal user|invalid user</match>
    <description>sshd: Attempt to login using a non-existent user</description>
    <group>invalid_login,authentication_failed,sshd,</group></rule>
  <rule id="5715" level="3"><if_sid>5700</if_sid><match>^Accepted|authenticated.$</match>
    <description>sshd: authentication success.</description>
    <group>authentication_success,sshd,</group></rule>
  <rule id="5716" level="5"><if_sid>5700</if_sid><match>^Failed|^error: PAM: Authentication</match>
    <description>sshd: authentication failed.</description>
    <group>authentication_failed,sshd,</group></rule>
  <rule id="5712" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5710</if_matched_sid><same_source_ip/>
    <description>sshd: brute force trying to get access to the system (non-existent users).</description>
    <group>authentication_failures,sshd,</group></rule>
  <rule id="5763" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5716</if_matched_sid><same_source_ip/>
    <description>sshd: brute force trying to get access to the system (authentication failed).</description>
    <group>authentication_failures,sshd,</group></rule>

  <!-- sudo -->
  <rule id="5400" level="0"><decoded_as>sudo</decoded_as>
    <description>Initial group for sudo messages.</description></rule>
  <rule id="5402" level="3"><if_sid>5400</if_sid><regex>TTY=\S+ ; PWD=\.* ; USER=root ; COMMAND=</regex>
    <description>Successful sudo to ROOT executed.</description><group>sudo,</group></rule>

  <!-- account management -->
  <rule id="5900" level="0"><decoded_as>adduser</decoded_as>
    <description>Grouping of adduser rules.</description></rule>
  <rule id="5902" level="8"><if_sid>5900</if_sid><match>new user:</match>
    <description>New user added to the system.</description><group>adduser,account_changed,</group></rule>
  <rule id="5904" level="8"><if_sid>5900</if_sid><match>^add '</match>
    <description>Information from the user was changed.</description>
    <group>adduser,account_changed,</group></rule>

  <!-- firewall -->
  <rule id="4100" level="0"><decoded_as>ufw</decoded_as>
    <description>Firewall rules grouping.</description></rule>
  <rule id="4101" level="5"><if_sid>4100</if_sid><action>BLOCK</action>
    <description>Firewall drop event.</description><group>firewall_drop,</group></rule>
</group>
"""

# --------------------------------------------------------------------------- #
# Events + decoders                                                           #
# --------------------------------------------------------------------------- #
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$")
PROG_RE = re.compile(r"^(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


@dataclass
class Event:
    idx: int
    lineno: int
    raw: str
    ts: Optional[datetime]
    host: str = ""
    program: str = ""
    pid: str = ""
    msg: str = ""
    decoder: str = ""
    fields: dict = field(default_factory=dict)


def _clean(v):
    return v if v not in (None, "") else None


def decode(program: str, msg: str) -> tuple[str, dict]:
    """Very small stand-in for Wazuh's decoder stage."""
    f: dict = {}
    if msg.startswith("pam_unix("):
        m = re.search(r"session (?:opened|closed) for user (?P<u>[^\s(]+)"
                      r"(?:\(uid=(?P<uid>\d+)\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?", msg)
        if m:
            f["dstuser"] = m["u"]; f["uid"] = m["uid"]; f["srcuser"] = _clean(m["by"])
        m = re.search(r"authentication failure;.*?rhost=(?P<ip>\S*)\s+user=(?P<u>\S+)", msg)
        if m:
            f["srcip"] = _clean(m["ip"]); f["dstuser"] = m["u"]
        f["service"] = (re.match(r"pam_unix\((\w+)", msg) or [None, None])[1]
        return "pam", {k: v for k, v in f.items() if v}
    if program == "sshd":
        m = re.match(r"(?P<st>Accepted|Failed) (?P<meth>\S+) for (?:invalid user )?(?P<u>\S+) "
                     rf"from (?P<ip>{IPV4}) port (?P<p>\d+)", msg)
        if m:
            f.update(status=m["st"], method=m["meth"], dstuser=m["u"], srcip=m["ip"], srcport=m["p"])
        else:
            m = re.match(rf"(?:Invalid|Illegal) user (?P<u>\S+) from (?P<ip>{IPV4})(?: port (?P<p>\d+))?", msg)
            if m:
                f.update(dstuser=m["u"], srcip=m["ip"], srcport=m["p"], status="Invalid")
        return "sshd", {k: v for k, v in f.items() if v}
    if program == "sudo":
        m = re.match(r"(?P<su>\S+)\s*: .*?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<du>\S+) ; "
                     r"COMMAND=(?P<cmd>.*)$", msg)
        if m:
            f.update(srcuser=m["su"], tty=m["tty"], pwd=m["pwd"], dstuser=m["du"], command=m["cmd"])
        return "sudo", f
    if program in ("useradd", "usermod", "groupadd", "userdel", "adduser"):
        m = re.search(r"name=(?P<n>[^,\s]+)", msg) or re.search(r"add '(?P<n>[^']+)'", msg)
        if m:
            f["dstuser"] = m["n"]
        m = re.search(r"to group '(?P<g>[^']+)'", msg)
        if m:
            f["group"] = m["g"]
        return "adduser", f
    if program == "kernel" and "[UFW " in msg:
        m = re.search(r"\[UFW (?P<a>\w+)\]", msg)
        f["action"] = m["a"] if m else None
        for k, name in (("SRC", "srcip"), ("DST", "dstip"), ("PROTO", "protocol"),
                        ("SPT", "srcport"), ("DPT", "dstport")):
            m = re.search(rf"\b{k}=(\S+)", msg)
            if m:
                f[name] = m[1]
        return "ufw", {k: v for k, v in f.items() if v}
    if program == "CRON":
        m = re.match(r"\((?P<u>[^)]+)\) CMD \((?P<c>.*)\)", msg)
        if m:
            f.update(srcuser=m["u"], command=m["c"])
        return "cron", f
    if program == "systemd-logind":
        m = re.match(r"New session (?P<id>\d+) of user (?P<u>\S+)\.", msg)
        if m:
            f.update(id=m["id"], dstuser=m["u"])
        return "systemd-logind", f
    return program.lower(), f


def parse_log(text: str, year: Optional[int] = None) -> list[Event]:
    year = year or datetime.now().year
    events: list[Event] = []
    prev_month, prev_ts = 0, None
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        m = SYSLOG_RE.match(line)
        ts, host, rest = None, "", line
        if m:
            mon = datetime.strptime(m["mon"], "%b").month
            if prev_month and mon < prev_month:      # Dec -> Jan rollover
                year += 1
            prev_month = mon
            try:
                ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = prev_ts
            host, rest = m["host"], m["rest"]
            prev_ts = ts
        p = PROG_RE.match(rest)
        program, pid, msg = (p["prog"], p["pid"] or "", p["msg"]) if p else ("", "", rest)
        decoder, fields = decode(program, msg)
        events.append(Event(len(events), lineno, line, ts, host, program, pid, msg, decoder, fields))
    return events


# --------------------------------------------------------------------------- #
# Condition matchers                                                          #
# --------------------------------------------------------------------------- #
class RuleParseError(ValueError):
    pass


_PUNCT = r"[\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]"


def _osmatch(pattern: str) -> Callable[[str], bool]:
    neg = pattern.startswith("!")
    if neg:
        pattern = pattern[1:]
    alts = []
    for a in re.split(r"(?<!\\)\|", pattern):
        start = a.startswith("^")
        end = a.endswith("$") and not a.endswith("\\$")
        core = re.sub(r"\\(.)", r"\1", a[1 if start else 0: len(a) - 1 if end else len(a)])
        alts.append((start, end, core))

    def fn(s: str) -> bool:
        ok = False
        for start, end, core in alts:
            if start and end:
                ok = s == core
            elif start:
                ok = s.startswith(core)
            elif end:
                ok = s.endswith(core)
            else:
                ok = core in s
            if ok:
                break
        return (not ok) if neg else ok
    return fn


def _osregex_to_py(p: str) -> str:
    """Wazuh OS_Regex -> Python re.  Key differences: '.' is a LITERAL dot and
    '\\.' means ANY character; ? [ ] { } are literals; \\p = punctuation."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            n = p[i + 1]
            i += 2
            if n in "dsSD":
                out.append("\\" + n)
            elif n == "w":
                out.append(r"[\w@-]")
            elif n == "W":
                out.append(r"[^\w@-]")
            elif n == "p":
                out.append(_PUNCT)
            elif n == "t":
                out.append("\t")
            elif n == ".":
                out.append(".")
            elif n in "<>":
                continue
            else:
                out.append(re.escape(n))
            continue
        out.append(r"\." if c == "." else c if c in "^$|()+*" else re.escape(c))
        i += 1
    return "".join(out)


def _osregex(pattern: str, pcre: bool = False) -> Callable[[str], bool]:
    neg = (not pcre) and pattern.startswith("!")
    if neg:
        pattern = pattern[1:]
    py = pattern if pcre else _osregex_to_py(pattern)
    try:
        rx = re.compile(py)
    except re.error as e:
        raise RuleParseError(f"invalid regex {pattern!r}: {e}") from e
    return (lambda s: rx.search(s) is None) if neg else (lambda s: rx.search(s) is not None)


def _ipmatch(pattern: str) -> Callable[[str], bool]:
    neg = pattern.startswith("!")
    nets = []
    for tok in pattern.lstrip("!").split("|"):
        tok = tok.strip()
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            nets.append(tok)

    def fn(s: str) -> bool:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            ip = None
        ok = any((ip in n) if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and ip
                 else (n == s if isinstance(n, str) else False) for n in nets)
        return (not ok) if neg else ok
    return fn


_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


def _clock(s: str) -> int:
    m = re.match(r"\s*(\d{1,2})(?::(\d\d))?\s*(am|pm)?\s*$", s, re.I)
    if not m:
        raise RuleParseError(f"bad <time> value {s!r}")
    h, mi, ap = int(m[1]), int(m[2] or 0), (m[3] or "").lower()
    if ap == "pm" and h < 12:
        h += 12
    if ap == "am" and h == 12:
        h = 0
    return h * 60 + mi


def _time_range(text: str) -> Callable[[datetime], bool]:
    lo_s, hi_s = re.split(r"\s*-\s*", text.strip(), maxsplit=1)
    lo, hi = _clock(lo_s), _clock(hi_s)

    def fn(ts: datetime) -> bool:
        t = ts.hour * 60 + ts.minute
        return lo <= t <= hi if lo <= hi else (t >= lo or t <= hi)
    return fn


def _weekday(text: str) -> Callable[[datetime], bool]:
    days: set[int] = set()
    for tok in re.split(r"\s*,\s*", text.strip().lower()):
        if tok == "weekdays":
            days |= set(range(5))
        elif tok == "weekends":
            days |= {5, 6}
        elif " - " in tok:
            a, b = [t.strip() for t in tok.split(" - ")]
            if a in _DAYS and b in _DAYS:
                i, j = _DAYS.index(a), _DAYS.index(b)
                days |= set(range(i, j + 1)) if i <= j else set(range(i, 7)) | set(range(0, j + 1))
        elif tok in _DAYS:
            days.add(_DAYS.index(tok))
    return lambda ts: ts.weekday() in days


@dataclass
class Cond:
    tag: str
    name: str            # field name for <field>
    text: str
    negate: bool
    fn: Callable
    kind: str = "str"    # str | ts

    def label(self) -> str:
        n = f" name={self.name}" if self.name else ""
        neg = " negate" if self.negate else ""
        return f"<{self.tag}{n}{neg}> {self.text}"


STR_TAGS = {  # tag -> event attribute / field name
    "program_name": "program", "hostname": "host", "srcip": "srcip", "dstip": "dstip",
    "srcport": "srcport", "dstport": "dstport", "user": "dstuser", "id": "id", "action": "action",
    "status": "status", "url": "url", "protocol": "protocol", "extra_data": "extra_data",
    "system_name": "system_name", "location": "@location", "decoded_as": "@decoder",
    "match": "@msg", "regex": "@msg",
}
SAME_TAGS = {"same_source_ip": "srcip", "same_srcip": "srcip", "same_user": "dstuser",
             "same_dstip": "dstip", "same_dst_port": "dstport", "same_dstport": "dstport",
             "same_src_port": "srcport", "same_srcport": "srcport", "same_id": "id",
             "same_location": "@location", "same_field": "field"}
META_TAGS = {"description", "group", "mitre", "options", "info", "noalert", "var", "if_sid",
             "if_group", "if_matched_sid", "if_matched_group", "if_matched_regex", "frequency",
             "timeframe", "ignore", "cve", "check_diff"}


@dataclass
class Rule:
    id: int
    level: int
    description: str = ""
    groups: list = field(default_factory=list)
    if_sid: list = field(default_factory=list)
    if_group: list = field(default_factory=list)
    if_matched_sid: list = field(default_factory=list)
    if_matched_group: list = field(default_factory=list)
    if_matched_regex: Optional[Cond] = None
    frequency: Optional[int] = None
    timeframe: Optional[int] = None
    ignore: Optional[int] = None
    same: list = field(default_factory=list)
    conds: list = field(default_factory=list)
    mitre: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    xml: str = ""

    @property
    def is_correlation(self) -> bool:
        return bool(self.frequency)


def _ints(text: str) -> list[int]:
    return [int(x) for x in re.split(r"[,\s]+", text.strip()) if x]


def _make_cond(el: ET.Element) -> Optional[Cond]:
    tag, text = el.tag, (el.text or "").strip()
    negate = (el.get("negate") or "").lower() == "yes"
    ctype = (el.get("type") or "").lower()
    name = el.get("name", "")
    if tag == "time":
        return Cond(tag, "", text, negate, _time_range(text), "ts")
    if tag == "weekday":
        return Cond(tag, "", text, negate, _weekday(text), "ts")
    if tag == "field":
        if not name:
            raise RuleParseError("<field> needs a name attribute")
        fn = _osmatch(text) if ctype == "osmatch" else _osregex(text, ctype == "pcre2")
        return Cond(tag, name, text, negate, fn)
    if tag in ("srcip", "dstip"):
        return Cond(tag, "", text, negate, _ipmatch(text))
    if tag == "match":
        fn = _osregex(text, True) if ctype == "pcre2" else _osmatch(text)
        return Cond(tag, "", text, negate, fn)
    if tag in STR_TAGS:
        fn = (lambda s, t=text: s == t or s in t.split("|")) if tag == "decoded_as" \
            else _osregex(text, ctype == "pcre2")
        return Cond(tag, "", text, negate, fn)
    return None


def parse_rules(xml_text: str, source: str = "") -> list[Rule]:
    """Accepts <rule>, <group><rule/></group>, several roots, or ```xml fences."""
    t = re.sub(r"^```(?:xml)?\s*|\s*```\s*$", "", xml_text.strip(), flags=re.M)
    t = re.sub(r"<\?xml[^>]*\?>", "", t)
    try:
        root = ET.fromstring(f"<root>{t}</root>")
    except ET.ParseError as e:
        raise RuleParseError(f"rule XML is not well-formed ({source or 'input'}): {e}") from e
    rules: list[Rule] = []

    def walk(node: ET.Element, outer: list[str]):
        for ch in node:
            if ch.tag == "group":
                walk(ch, outer + [g.strip() for g in (ch.get("name") or "").split(",") if g.strip()])
            elif ch.tag == "rule":
                rules.append(_parse_rule(ch, outer))

    walk(root, [])
    if not rules:
        raise RuleParseError("no <rule> element found")
    return rules


def _parse_rule(el: ET.Element, outer: list[str]) -> Rule:
    try:
        rid, lvl = int(el.get("id", "")), int(el.get("level", "0"))
    except ValueError as e:
        raise RuleParseError("<rule> needs integer id and level attributes") from e
    r = Rule(rid, lvl, xml=ET.tostring(el, encoding="unicode").strip())
    r.groups = list(outer)
    if el.get("frequency"):
        r.frequency = int(el.get("frequency"))
    if el.get("timeframe"):
        r.timeframe = int(el.get("timeframe"))
    for ch in el:
        tag, text = ch.tag, (ch.text or "").strip()
        if tag == "description":
            r.description = " ".join(text.split())
        elif tag == "group":
            r.groups += [g.strip() for g in text.split(",") if g.strip()]
        elif tag == "if_sid":
            r.if_sid += _ints(text)
        elif tag == "if_group":
            r.if_group += [g.strip() for g in text.split(",") if g.strip()]
        elif tag == "if_matched_sid":
            r.if_matched_sid += _ints(text)
        elif tag == "if_matched_group":
            r.if_matched_group += [g.strip() for g in text.split(",") if g.strip()]
        elif tag == "if_matched_regex":
            r.if_matched_regex = Cond(tag, "", text, False, _osregex(text))
        elif tag == "frequency":
            r.frequency = int(text)
        elif tag == "timeframe":
            r.timeframe = int(text)
        elif tag == "ignore":
            r.ignore = int(text)
        elif tag == "mitre":
            r.mitre += [i.text.strip() for i in ch.iter("id") if i.text]
        elif tag in SAME_TAGS:
            key = SAME_TAGS[tag]
            r.same.append(ch.get("name") if key == "field" else key)
        else:
            c = _make_cond(ch)
            if c:
                r.conds.append(c)
            elif tag not in META_TAGS:
                r.unsupported.append(tag)
    if r.frequency and not r.timeframe:
        r.warnings.append("frequency without timeframe: Wazuh needs both")
    if r.frequency and r.if_sid and not (r.if_matched_sid or r.if_matched_group or r.if_matched_regex):
        r.warnings.append(
            "uses <if_sid> together with frequency/timeframe. Wazuh's documentation pairs "
            "frequency with <if_matched_sid>/<if_matched_group>/<if_matched_regex>; "
            "this tool counts the <if_sid> parent's events, but verify with wazuh-logtest")
    if r.unsupported:
        r.warnings.append("tags not emulated offline and therefore ignored: " + ", ".join(sorted(set(r.unsupported))))
    return r


# --------------------------------------------------------------------------- #
# Engine                                                                      #
# --------------------------------------------------------------------------- #
@dataclass
class Hit:
    trigger: int                     # event index
    evidence: list = field(default_factory=list)


@dataclass
class RuleResult:
    rule: Rule
    hits: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def event_indices(self, triggers_only: bool = False) -> list[int]:
        s: set[int] = set()
        for h in self.hits:
            s.add(h.trigger)
            if not triggers_only:
                s.update(h.evidence)
        return sorted(s)


class Engine:
    def __init__(self, user_rules: list[Rule], base_rules: Optional[list[Rule]] = None,
                 location: str = "/var/log/auth.log"):
        self.location = location
        self.user_rules = user_rules
        self.rules: dict[int, Rule] = {}
        for r in (base_rules or []) + user_rules:        # user rules override same id
            self.rules[r.id] = r
        self.by_group: dict[str, list[int]] = defaultdict(list)
        for r in self.rules.values():
            for g in r.groups:
                self.by_group[g].append(r.id)
        self._cache: dict[tuple, bool] = {}

    # ---- single-event evaluation ---------------------------------------- #
    def _value(self, c: Cond, ev: Event):
        if c.tag == "field":
            return ev.fields.get(c.name.removeprefix("data."))
        key = STR_TAGS[c.tag]
        if key == "@msg":
            return ev.msg
        if key == "@decoder":
            return ev.decoder
        if key == "@location":
            return self.location
        if key == "program":
            return ev.program
        if key == "host":
            return ev.host
        return ev.fields.get(key)

    def cond_ok(self, c: Cond, ev: Event) -> bool:
        if c.kind == "ts":
            ok = bool(ev.ts and c.fn(ev.ts))
        else:
            v = self._value(c, ev)
            ok = bool(v is not None and c.fn(str(v)))
        return (not ok) if c.negate else ok

    def _parents_ok(self, r: Rule, ev: Event, stack: frozenset) -> bool:
        if r.if_sid and not any(self.matches(self.rules[s], ev, stack) for s in r.if_sid if s in self.rules):
            return False
        if r.if_group and not any(self.matches(self.rules[s], ev, stack)
                                  for g in r.if_group for s in self.by_group.get(g, [])):
            return False
        return True

    def matches(self, r: Rule, ev: Event, stack: frozenset = frozenset()) -> bool:
        """Does this event satisfy rule r (own tags + parent chain)?  Correlation
        (frequency) is handled separately; here it means 'candidate event'."""
        k = (r.id, ev.idx)
        if k in self._cache:
            return self._cache[k]
        if r.id in stack:
            return False
        stack = stack | {r.id}
        ok = all(self.cond_ok(c, ev) for c in r.conds) and self._parents_ok(r, ev, stack)
        if ok and r.is_correlation:
            ok = self.counted(r, ev, stack)
        self._cache[k] = ok
        return ok

    def counted(self, r: Rule, ev: Event, stack: frozenset = frozenset()) -> bool:
        """Would this event be counted towards r's frequency?"""
        if r.if_matched_sid:
            if not any(self.matches(self.rules[s], ev, stack) for s in r.if_matched_sid if s in self.rules):
                return False
        if r.if_matched_group:
            if not any(self.matches(self.rules[s], ev, stack)
                       for g in r.if_matched_group for s in self.by_group.get(g, [])):
                return False
        if r.if_matched_regex and not r.if_matched_regex.fn(ev.msg):
            return False
        return True

    # ---- correlation ------------------------------------------------------ #
    def _key(self, r: Rule, ev: Event):
        out = []
        for f in r.same:
            v = (self.location if f == "@location" else ev.fields.get(f))
            if v is None:
                return None
            out.append(v)
        return tuple(out)

    def run_rule(self, r: Rule, events: list[Event]) -> RuleResult:
        res = RuleResult(r)
        if not r.is_correlation:
            res.hits = [Hit(e.idx) for e in events if self.matches(r, e)]
            res.stats = {"matched": len(res.hits)}
            return res
        window = r.timeframe or 0
        hist: dict[tuple, deque] = defaultdict(deque)
        muted_until: dict[tuple, datetime] = {}
        best = (0, None, None)
        has_parent = bool(r.if_sid or r.if_matched_sid or r.if_matched_group or r.if_matched_regex)
        counted_n = 0
        for ev in events:
            # events counted towards the threshold (self-counting if no parent is named)
            is_cand = all(self.cond_ok(c, ev) for c in r.conds) and self._parents_ok(r, ev, frozenset({r.id}))
            is_cand = is_cand and (self.counted(r, ev) if (r.if_matched_sid or r.if_matched_group
                                                           or r.if_matched_regex) else True)
            if not is_cand or ev.ts is None:
                continue
            key = self._key(r, ev)
            if key is None:
                continue
            counted_n += 1
            dq = hist[key]
            dq.append(ev)
            while dq and (ev.ts - dq[0].ts).total_seconds() > window:
                dq.popleft()
            if len(dq) > best[0]:
                best = (len(dq), key, ev.ts)
            if len(dq) >= (r.frequency or 0):
                if r.ignore and key in muted_until and ev.ts < muted_until[key]:
                    continue
                if r.ignore:
                    muted_until[key] = ev.ts + timedelta(seconds=r.ignore)
                res.hits.append(Hit(ev.idx, [e.idx for e in dq]))
        res.stats = {"counted_events": counted_n, "threshold": r.frequency, "timeframe_s": window,
                     "max_in_window": best[0], "max_key": best[1],
                     "max_at": best[2].isoformat(sep=" ") if best[2] else None,
                     "has_parent": has_parent}
        return res

    def run(self, events: list[Event]) -> list[RuleResult]:
        self._cache.clear()
        return [self.run_rule(r, events) for r in self.user_rules]

    # ---- debugging ---------------------------------------------------------- #
    def baseline_hits(self, events: list[Event]) -> dict[int, int]:
        user_ids = {r.id for r in self.user_rules}
        out = {}
        for r in self.rules.values():
            if r.id in user_ids or r.is_correlation:
                continue
            out[r.id] = sum(1 for e in events if self.matches(r, e))
        return out

    def explain(self, r: Rule, events: list[Event]) -> list[str]:
        lines = [f"Rule {r.id} (level {r.level}): {r.description or '-'}"]
        cur = list(events)
        lines.append(f"  start                                         {len(cur):>6} events")
        for sid in r.if_sid + r.if_matched_sid:
            p = self.rules.get(sid)
            if not p:
                lines.append(f"  parent {sid}: NOT DEFINED (not in built-in or --base-rules)   -> 0 events")
                cur = []
                continue
            cur = [e for e in cur if self.matches(p, e)]
            lines.append(f"  parent {sid} ({p.description[:38]:<38}) {len(cur):>6} events")
        for g in r.if_group + r.if_matched_group:
            ids = self.by_group.get(g, [])
            cur = [e for e in cur if any(self.matches(self.rules[i], e) for i in ids)]
            lines.append(f"  group  {g:<44} {len(cur):>6} events")
        for c in r.conds:
            cur = [e for e in cur if self.cond_ok(c, e)]
            lines.append(f"  {c.label()[:52]:<52} {len(cur):>6} events")
        return lines


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #
def build_engine(rule_xml: str, base_xml_files: Optional[list[str]] = None,
                 rule_ids: Optional[list[int]] = None, location: str = "/var/log/auth.log") -> Engine:
    user = parse_rules(rule_xml, "rule")
    if rule_ids:
        user = [r for r in user if r.id in rule_ids]
        if not user:
            raise RuleParseError(f"rule id(s) {rule_ids} not found in supplied XML")
    base = parse_rules(BASELINE_RULES_XML, "built-in")
    for path in base_xml_files or []:
        with open(path, encoding="utf-8", errors="replace") as fh:
            base += parse_rules(fh.read(), path)
    return Engine(user, base, location)


def _event_dict(e: Event, role: str = "") -> dict:
    return {"line": e.lineno, "time": e.ts.isoformat(sep=" ") if e.ts else None, "role": role,
            "host": e.host, "program": e.program, "decoder": e.decoder, "fields": e.fields, "raw": e.raw}


def filter_log_text(rule_xml: str, log_text: str, *, year: Optional[int] = None,
                    rule_ids: Optional[list[int]] = None, base_files: Optional[list[str]] = None,
                    location: str = "/var/log/auth.log", triggers_only: bool = False) -> dict:
    """JSON-serialisable result, suitable for a FastAPI route."""
    events = parse_log(log_text, year)
    eng = build_engine(rule_xml, base_files, rule_ids, location)
    out = {"total_events": len(events), "rules": []}
    for rr in eng.run(events):
        trig = {h.trigger for h in rr.hits}
        idxs = rr.event_indices(triggers_only)
        out["rules"].append({
            "id": rr.rule.id, "level": rr.rule.level, "description": rr.rule.description,
            "mitre": rr.rule.mitre, "warnings": rr.rule.warnings, "alerts": len(rr.hits),
            "matched_lines": len(idxs), "stats": rr.stats,
            "events": [_event_dict(events[i], "trigger" if i in trig else "evidence") for i in idxs]})
    return out


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #
def _rule_from_query(q: str) -> str:
    try:
        from src.agents.translation_orchestrator import TranslationOrchestrator  # type: ignore
    except ImportError:
        sys.exit("--query needs the NL-SIEM repo on PYTHONPATH (run from the repo root).")
    res = TranslationOrchestrator.from_env().translate(q)
    xml = getattr(res, "wazuh", None)
    if not xml:
        sys.exit("pipeline returned no Wazuh rule for that query.")
    return xml if isinstance(xml, str) else str(xml)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Filter a log file with a Wazuh rule (offline emulation).")
    ap.add_argument("--log", required=True, help="syslog / auth.log style file")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--rule", help="file containing Wazuh rule XML ('-' = stdin)")
    src.add_argument("--rule-text", help="rule XML as a string")
    src.add_argument("--query", help="natural-language query -> NL-SIEM pipeline -> Wazuh XML")
    ap.add_argument("--rule-id", type=int, action="append", help="only evaluate this rule id (repeatable)")
    ap.add_argument("--base-rules", action="append", default=[],
                    help="extra rule XML (e.g. real /var/ossec/ruleset/rules/*.xml) used for if_sid parents")
    ap.add_argument("--year", type=int, help="year for syslog timestamps (default: current year)")
    ap.add_argument("--location", default="/var/log/auth.log", help="value for <location> matching")
    ap.add_argument("--format", choices=["text", "raw", "json", "csv"], default="text")
    ap.add_argument("--triggers-only", action="store_true",
                    help="for frequency rules, show only the alert-firing events, not the whole window")
    ap.add_argument("--max-lines", type=int, default=200, help="text mode: cap lines per rule")
    ap.add_argument("--explain", action="store_true", help="show per-condition counts / why nothing matched")
    ap.add_argument("--save-rule", help="write the XML that was used to this path")
    ap.add_argument("--out", help="write output here instead of stdout")
    a = ap.parse_args(argv)

    if a.query:
        xml = _rule_from_query(a.query)
    elif a.rule_text:
        xml = a.rule_text
    else:
        xml = sys.stdin.read() if a.rule == "-" else open(a.rule, encoding="utf-8").read()
    if a.save_rule:
        open(a.save_rule, "w", encoding="utf-8").write(xml)

    with open(a.log, encoding="utf-8", errors="replace") as fh:
        events = parse_log(fh.read(), a.year)
    try:
        eng = build_engine(xml, a.base_rules, a.rule_id, a.location)
    except RuleParseError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    results = eng.run(events)

    buf = io.StringIO()
    w = buf.write
    if a.format == "json":
        w(json.dumps(filter_log_text(xml, "\n".join(e.raw for e in events), year=a.year,
                                     rule_ids=a.rule_id, base_files=a.base_rules,
                                     location=a.location, triggers_only=a.triggers_only),
                     indent=2, default=str))
    elif a.format == "raw":
        idx = sorted({i for rr in results for i in rr.event_indices(a.triggers_only)})
        w("".join(events[i].raw + "\n" for i in idx))
    elif a.format == "csv":
        cw = csv.writer(buf)
        cw.writerow(["rule_id", "role", "line", "time", "host", "program", "srcip", "dstuser", "raw"])
        for rr in results:
            trig = {h.trigger for h in rr.hits}
            for i in rr.event_indices(a.triggers_only):
                e = events[i]
                cw.writerow([rr.rule.id, "trigger" if i in trig else "evidence", e.lineno,
                             e.ts.isoformat(sep=" ") if e.ts else "", e.host, e.program,
                             e.fields.get("srcip", ""), e.fields.get("dstuser", ""), e.raw])
    else:
        w(f"# {len(events)} log events from {a.log}\n")
        for rr in results:
            r = rr.rule
            idxs = rr.event_indices(a.triggers_only)
            trig = {h.trigger for h in rr.hits}
            mitre = f"  mitre={','.join(r.mitre)}" if r.mitre else ""
            w(f"\n=== Rule {r.id}  level {r.level}{mitre}\n    {r.description}\n")
            for msg in r.warnings:
                w(f"    ! {msg}\n")
            w(f"    alerts: {len(rr.hits)}   log lines in result: {len(idxs)}\n")
            if r.is_correlation:
                s = rr.stats
                w(f"    threshold {s['threshold']} in {s['timeframe_s']}s | highest seen: "
                  f"{s['max_in_window']}" + (f" (key={s['max_key']}, at {s['max_at']})" if s["max_key"] else "") + "\n")
            if idxs:
                w("    T = alert-firing event, . = supporting event\n")
            for n, i in enumerate(idxs):
                if n >= a.max_lines:
                    w(f"    ... {len(idxs) - n} more (use --max-lines or --format raw)\n")
                    break
                w(f"  {'T' if i in trig else '.'} L{events[i].lineno:<6} {events[i].raw}\n")
            if a.explain:
                w("\n  --- explain ---\n")
                for ln in eng.explain(r, events):
                    w(ln + "\n")
                if not idxs:
                    hits = eng.baseline_hits(events)
                    miss = [p for p in r.if_sid + r.if_matched_sid if hits.get(p, 0) == 0 and p in eng.rules]
                    for p in miss:
                        pg = set(eng.rules[p].groups) - {"syslog", "pam", "sshd", "sudo"}   # keep semantic groups only
                        alt = [(hits[i], i) for i, rr_ in eng.rules.items()
                               if i != p and hits.get(i) and pg & set(rr_.groups)]
                        if alt:
                            w(f"  hint: parent {p} ({eng.rules[p].description}) matches nothing in this log. "
                              "Related parents that DO match:\n")
                            for h, i in sorted(alt, reverse=True)[:5]:
                                w(f"        {i}: {eng.rules[i].description}  ({h} events)\n")
    text = buf.getvalue()
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text)
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())