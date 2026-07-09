"""
ATT&CK Classifier Agent — chain-of-thought tactic/technique/sub-technique
inference from natural language input.

Purpose
-------
Replaces any ad-hoc ATT&CK tagging previously done inline inside
ParserAgent (e.g. an LLM guessing a `technique_id` as a side effect of IR
generation, with no taxonomy grounding and no auditable reasoning trail).

This agent performs ATT&CK classification as an explicit, separate,
taxonomy-grounded step:

    1. Candidate narrowing — ATTCKTaxonomyLoader.search_techniques() finds
       the top-K lexically plausible techniques for the NL query, avoiding
       the need to embed the full ~700-technique taxonomy in every prompt.
    2. Chain-of-thought selection — the LLM reasons over the narrowed
       candidate set plus their official descriptions, and selects the
       single best-fit tactic/technique/sub-technique with cited rationale.
    3. Taxonomy verification — the LLM's selection is checked against
       ATTCKTaxonomyLoader.get_technique() before being accepted, so a
       hallucinated technique ID can never reach the IR layer.
    4. AttckIRQuery construction — the verified binding is attached to
       a base IRQuery via AttckIRQuery.from_ir_query().

This separation (structural IR parsing vs. ATT&CK classification) is the
same decoupling principle as the NL→IR vs. IR→SIEM-syntax boundary that is
the framework's core contribution: each agent owns exactly one inference
task and is independently testable, swappable, and auditable.

Multi-technique classification
-------------------------------
A single detection description often genuinely maps to more than one
ATT&CK technique — e.g. repeated failed SSH logins from one IP is password
guessing (T1110.001), but could also be password spraying (T1110.003) if
the target accounts vary. classify() below still collapses to one best
match for callers that only want that. classify_multi() runs the identical
taxonomy-grounded pipeline (same candidate narrowing, same mandatory
taxonomy verification, same hallucination guarantee) but keeps every
technique that clears verification, ranked by confidence, instead of
discarding all but the top one.

Place at: src/agents/attck_classifier_agent.py

Usage:
    from src.agents.attck_classifier_agent import ATTCKClassifierAgent

    classifier = ATTCKClassifierAgent(client=llm_client)
    result     = classifier.classify(
        "Detect more than 50 failed SSH logins from the same source IP in 24h"
    )
    print(result.tactic, result.technique, result.sub_technique)

    # Attach to an already-parsed IR
    attck_ir = classifier.attach(base_ir, result)

    # Multi-technique variant — every plausible technique, ranked
    results = classifier.classify_multi(
        "Detect more than 50 failed SSH logins from the same source IP in 24h"
    )
    for r in results:
        print(r.technique, r.sub_technique, r.confidence, r.rationale)

    # Attach every matched technique to the same base IR
    attck_irs = classifier.attach_multi(base_ir, results)
"""

from __future__ import annotations
import re
import time
from dataclasses import dataclass, field

from src.ir.attck_schema import AttckIRQuery
from src.ir.schema import IRQuery
from src.knowledge_base.mitre.attck_taxonomy_loader import (
    TechniqueEntry,
    get_taxonomy,
)
from src.llm.response_parser import ResponseParser
from src.utils.exceptions import IRValidationError, LLMError, NLSIEMError
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Heuristic rule engine ─────────────────────────────────────────────────
# Fast-path keyword/regex matching, used only to short-circuit the LLM call
# for high-confidence cases. Every heuristic hit is now taxonomy-verified
# before being returned (see _verify_binding() and its use in
# _run_heuristics() / _run_heuristics_multi() below) — a hardcoded rule
# with an incorrect tactic/technique/sub-technique triple can no longer
# silently ship to output. It falls through to the LLM instead, exactly
# like a genuinely unmatched query would.
#
# Confidence-floor design: each _Rule has its own min_score, which governs
# whether the rule fires AT ALL (see _Rule.score()). That is a per-rule
# "is there enough signal to even consider this a candidate" gate — it is
# NOT the same thing as "confident enough to skip the more accurate LLM
# chain-of-thought stage entirely". Those are two different questions.
# _HEURISTIC_BYPASS_FLOOR below answers the second one, and is enforced
# globally in _run_heuristics(), independent of each rule's own min_score.
# A rule that clears its own min_score at, say, 0.5 still routes through
# to full LLM reasoning unless the total also clears the bypass floor.

from dataclasses import dataclass as _dc

# Global safety floor for bypassing the LLM entirely on the classify()
# fast path. Distinct from — and stricter than — any individual rule's
# min_score. A rule can legitimately fire (i.e. be considered a match)
# at a lower score and still be surfaced as a heuristic candidate inside
# classify_multi()'s merge step, but only a match at or above this floor
# is trusted enough to skip taxonomy-grounded LLM reasoning altogether.
_HEURISTIC_BYPASS_FLOOR = 0.85

# Minimum score for a heuristic hit to be considered at all when merging
# into classify_multi()'s ranked result. Prevents weak single-keyword
# matches (e.g. a rule that fires at its own min_score of 0.5) from
# padding the multi-technique output with noise the LLM itself did not
# surface.
_HEURISTIC_MERGE_FLOOR = 0.6

# Hedge / negation phrases that indicate the surrounding trigger words are
# describing normal, authorized, or already-mitigated activity rather than
# an actual detection target (e.g. "alert only on failed logins, not
# successful ones" still contains "failed", but the analyst's intent may
# be more nuanced than the keyword suggests). Presence of any of these
# halves a heuristic rule's score, pushing borderline matches below the
# bypass floor and toward full LLM reasoning rather than a fast, literal,
# keyword-only judgement.
_HEDGE_PATTERNS = [
    r"\bsuccessful\b", r"\bauthorized\b", r"\blegitimate\b",
    r"\bbaseline\b", r"\ballow.?list", r"\bknown\s+good\b",
    r"\bexpected\b", r"\bfalse\s+positive\b", r"\bnot\s+a\b",
    r"\bexclud(e|ing)\b", r"\bwhitelist",
]


@_dc
class _Rule:
    tactic:        str
    technique:     str
    sub_technique: str | None
    rationale:     str
    signal_groups: list[tuple[float, list[str]]]   # (weight, [regex patterns])
    min_score:     float = 0.85
    require_all:   bool  = False

    def score(self, q: str) -> float:
        """
        Evaluate rule against lowercased query.
        Returns 0.0 if rule does not fire, else clamped accumulated score.
        require_all=True: every group must match (strict AND).
        require_all=False: sum weights of matching groups, check vs min_score.

        A non-zero return value means this rule's own min_score bar was
        cleared — it does NOT mean the result is confident enough to skip
        LLM reasoning. That is a separate, stricter check applied by
        callers (see _HEURISTIC_BYPASS_FLOOR).

        Hedge/negation context (see _HEDGE_PATTERNS) halves the score
        before the min_score comparison, so a query like "alert on
        anything except successful, authorized logins" is less likely to
        be treated as a confident brute-force match on "failed" alone.
        """
        total = 0.0
        for weight, patterns in self.signal_groups:
            hit = any(re.search(p, q) for p in patterns)
            if hit:
                total += weight
            elif self.require_all:
                return 0.0          # one miss kills the rule in strict mode

        if total < self.min_score:
            return 0.0

        if any(re.search(p, q) for p in _HEDGE_PATTERNS):
            total *= 0.5
            if total < self.min_score:
                return 0.0

        return min(total, 1.0)


_RULES: list[_Rule] = [

    # ── Credential Access ─────────────────────────────────────────────────

    _Rule("credential-access", "T1110", "T1110.001",
          "SSH/RDP/SMB repeated authentication failures — password guessing.",
          [(0.5, [r"\bssh\b", r"\brdp\b", r"\bsmb\b",
                  r"\bftp\b", r"\bwinrm\b"]),
           # NOTE (fixed): the trailing `*` on the login/logon/auth group
           # made that group optional, so the pattern effectively reduced
           # to `failed.*` — matching "failed" followed by ANYTHING, with
           # no requirement that an authentication-related word appear at
           # all (e.g. "SSH connection failed to establish" would match).
           # Removed the `*` so the group is mandatory, as originally
           # intended.
           (0.5, [r"failed.*(login|logon|auth)", r"brute.?force",
                  r"password.?guess", r"\b4625\b", r"\b4771\b"])],
          require_all=True),

    _Rule("credential-access", "T1110", "T1110.003",
          "Password spray: one source targeting many accounts.",
          [(0.6, [r"password.?spray", r"spraying"]),
           (0.4, [r"multiple\s+accounts?", r"distinct\s+accounts?",
                  r"same\s+(source|ip)"])],
          min_score=0.6),

    _Rule("credential-access", "T1110", "T1110.004",
          "Credential stuffing: breached credential pairs against auth endpoints.",
          [(1.0, [r"credential.?stuffing"])],
          min_score=0.9),

    _Rule("credential-access", "T1558", "T1558.003",
          "Kerberoasting: RC4 TGS-REQ for service accounts.",
          [(0.6, [r"kerberoast"]),
           (0.4, [r"tgs.?req", r"rc4", r"0x17", r"\b4769\b",
                  r"service\s+account", r"\bspn\b"])],
          require_all=True),

    _Rule("credential-access", "T1558", "T1558.004",
          "AS-REP roasting: pre-authentication disabled accounts.",
          [(0.6, [r"as.?rep", r"asrep"]),
           (0.4, [r"pre.?auth", r"roast", r"\b4768\b"])],
          require_all=True),

    _Rule("credential-access", "T1003", "T1003.001",
          "LSASS memory dump for credential extraction.",
          [(0.6, [r"\blsass\b"]),
           (0.4, [r"dump", r"memory\s+read", r"procdump",
                  r"comsvcs", r"minidump", r"vm.?read"])],
          require_all=True),

    _Rule("credential-access", "T1003", "T1003.002",
          "SAM database access for local credential extraction.",
          [(0.6, [r"\bsam\b", r"hklm.{0,5}sam",
                  r"security\s+account\s+manager"]),
           (0.4, [r"dump", r"extract", r"ntlm", r"hash"])],
          require_all=True),

    _Rule("credential-access", "T1555", "T1555.003",
          "Browser credential store access.",
          [(0.5, [r"chrome", r"firefox", r"edge", r"browser"]),
           (0.5, [r"login\s+data", r"logins\.json", r"key4\.db",
                  r"password\s+store", r"credential"])],
          require_all=True),

    _Rule("credential-access", "T1552", "T1552.005",
          "Cloud instance metadata service (IMDS) credential access.",
          [(0.6, [r"169\.254\.169\.254", r"\bimds\b",
                  r"metadata\s+service", r"instance\s+metadata"]),
           (0.4, [r"credential", r"token", r"iam\s+role", r"ssrf"])],
          require_all=True),

    # ── Execution ─────────────────────────────────────────────────────────

    _Rule("execution", "T1059", "T1059.001",
          "PowerShell encoded command or download cradle execution.",
          [(0.5, [r"powershell", r"\bpwsh\b"]),
           (0.5, [r"encoded.?command", r"\-enc\b", r"downloadstring",
                  r"invoke.?expression", r"\biex\b", r"bypass",
                  r"webclient", r"downloadfile"])],
          require_all=True),

    _Rule("execution", "T1059", "T1059.003",
          "Windows Command Shell spawned from suspicious parent.",
          [(0.5, [r"\bcmd\.exe\b", r"command\s+shell"]),
           (0.5, [r"spawned", r"child\s+process",
                  r"parent.{0,20}(svchost|office|winword|excel|outlook)",
                  r"suspicious\s+parent"])],
          require_all=True),

    _Rule("execution", "T1059", "T1059.004",
          "Unix shell reverse shell or suspicious bash execution.",
          [(0.5, [r"\bbash\b", r"\b/bin/sh\b", r"\bzsh\b"]),
           (0.5, [r"reverse\s+shell", r"/dev/tcp", r"\bnc\b.{0,10}\-e",
                  r"mkfifo", r"pty\.spawn", r"bash\s+-i"])],
          require_all=True),

    _Rule("execution", "T1047", None,
          "WMI remote process execution.",
          [(0.6, [r"\bwmic\b", r"\bwmi\b", r"win32_process"]),
           (0.4, [r"process\s+call\s+create", r"remote",
                  r"lateral", r"execut"])],
          require_all=True),

    # NOTE (fixed): T1218 "System Binary Proxy Execution" and all of its
    # sub-techniques (including .010 regsvr32, .011 rundll32, .005 mshta,
    # .004 installutil/msiexec) belong to the Defense Evasion tactic in
    # MITRE ATT&CK, not Execution. Verified against attack.mitre.org.
    # Also switched to require_all=True: a bare mention of "regsvr32" or
    # "rundll32" alone (both extremely common in legitimate admin/software
    # activity) was previously enough to fire these rules on its own,
    # since the first signal group's weight matched min_score exactly.

    _Rule("defense-evasion", "T1218", "T1218.010",
          "Regsvr32 Squiblydoo — remote scriptlet execution.",
          [(0.7, [r"regsvr32"]),
           (0.3, [r"scrobj", r"https?://", r"\.sct\b", r"squiblydoo"])],
          require_all=True),

    _Rule("defense-evasion", "T1218", "T1218.011",
          "Rundll32 LOLBin abuse from writable directory.",
          [(0.7, [r"rundll32"]),
           (0.3, [r"temp", r"appdata", r"http", r"shell32", r"advpack"])],
          require_all=True),

    _Rule("defense-evasion", "T1218", "T1218.005",
          "MSHTA executing remote HTA payload.",
          [(0.8, [r"\bmshta\b"]),
           (0.2, [r"https?://", r"\.hta\b", r"remote"])],
          require_all=True),

    _Rule("defense-evasion", "T1218", "T1218.004",
          "InstallUtil / msiexec LOLBin execution.",
          [(0.7, [r"\bmsiexec\b", r"installutil"]),
           (0.3, [r"/q\b", r"/i\b", r"unc", r"https?://", r"silent"])],
          require_all=True),

    # ── Persistence ───────────────────────────────────────────────────────

    _Rule("persistence", "T1547", "T1547.001",
          "Registry Run key modification for startup persistence.",
          [(0.6, [r"run\s*key", r"runonce", r"hkcu.{0,10}run",
                  r"hklm.{0,10}run", r"currentversion\\run"]),
           (0.4, [r"persist", r"startup", r"autorun", r"boot"])],
          require_all=True),

    _Rule("persistence", "T1053", "T1053.005",
          "Scheduled task creation for persistence.",
          [(0.6, [r"scheduled\s+task", r"\bschtasks\b",
                  r"task\s+schedul", r"\b4698\b"]),
           (0.4, [r"persist", r"creat", r"new\s+task",
                  r"writable", r"appdata", r"temp"])],
          require_all=True),

    _Rule("persistence", "T1543", "T1543.003",
          "New Windows service installed for persistence.",
          [(0.6, [r"new\s+service", r"service\s+install",
                  r"\b7045\b", r"sc\s+create"]),
           (0.4, [r"persist", r"temp", r"appdata", r"unc"])],
          require_all=True),

    _Rule("persistence", "T1546", "T1546.003",
          "WMI event subscription persistence.",
          [(0.7, [r"wmi.{0,10}subscri", r"__eventfilter",
                  r"__eventconsumer", r"filtertoconsumerbinding"]),
           (0.3, [r"persist", r"wmi", r"event"])],
          require_all=True),

    _Rule("persistence", "T1546", "T1546.012",
          "Image File Execution Options (IFEO) debugger hijack.",
          [(0.8, [r"ifeo", r"image\s+file\s+execution",
                  r"globalflag", r"silentprocessexit"]),
           (0.2, [r"debugger", r"hijack", r"persist"])],
          require_all=True),

    # NOTE (fixed): this is specifically Account Manipulation: SSH
    # Authorized Keys, MITRE sub-technique T1098.004, not the bare parent
    # T1098. Left sub_technique as None before, which discarded the exact
    # match the query text was already describing.
    _Rule("persistence", "T1098", "T1098.004",
          "SSH authorized_keys modification.",
          [(0.6, [r"authorized.?keys", r"\.ssh/", r"ssh.{0,10}key"]),
           (0.4, [r"added", r"written", r"modif", r"new\s+entry"])],
          require_all=True),

    _Rule("persistence", "T1136", "T1136.001",
          "Local account created for persistence.",
          [(0.6, [r"new\s+(local\s+)?account", r"user\s+creat",
                  r"\b4720\b", r"net\s+user.{0,20}/add"]),
           (0.4, [r"persist", r"local", r"admin", r"backdoor"])],
          require_all=True),

    # ── Privilege Escalation ──────────────────────────────────────────────

    _Rule("privilege-escalation", "T1548", "T1548.002",
          "UAC bypass via fodhelper, eventvwr, or registry hijack.",
          [(0.7, [r"uac\s+bypass", r"fodhelper", r"eventvwr",
                  r"ms-settings.{0,20}shell.{0,20}open"]),
           (0.3, [r"bypass", r"elevat", r"admin"])],
          require_all=True),

    _Rule("privilege-escalation", "T1134", "T1134.001",
          "Token impersonation / SeImpersonatePrivilege abuse.",
          [(0.6, [r"token\s+impersonat", r"seimpersonateprivilege",
                  r"impersonateloggedonuser", r"duplicatetokenex",
                  r"printspoofer", r"juicypotato", r"rottenpotato"]),
           (0.4, [r"privilege", r"elevat", r"impersonat"])],
          require_all=True),

    _Rule("privilege-escalation", "T1078", None,
          "Domain Admin or local admin group membership change.",
          [(0.5, [r"domain\s+admin", r"added.{0,20}admin",
                  r"\b4728\b", r"\b4732\b"]),
           (0.5, [r"group\s+member", r"privileged\s+group",
                  r"administrator"])],
          require_all=True),

    _Rule("privilege-escalation", "T1484", "T1484.001",
          "GPO modification for privilege escalation.",
          [(0.7, [r"gpo\s+modif", r"group\s+policy.{0,20}modif",
                  r"logon\s+script", r"immediate\s+task"]),
           (0.3, [r"high.?value\s+ou", r"domain", r"privilege"])],
          require_all=True),

    # ── Defense Evasion ───────────────────────────────────────────────────

    _Rule("defense-evasion", "T1070", "T1070.001",
          "Windows event log cleared.",
          [(0.7, [r"event\s+log.{0,10}clear", r"clear.{0,10}event\s+log",
                  r"wevtutil", r"clear-eventlog"]),
           (0.3, [r"\b1102\b", r"\b104\b", r"log.{0,10}delet"])],
          require_all=True),

    _Rule("defense-evasion", "T1562", "T1562.001",
          "Security tooling or audit logging disabled.",
          [(0.6, [r"cloudtrail.{0,10}disabl", r"stoplogging",
                  r"deletetrail", r"guardduty.{0,10}disabl",
                  r"av.{0,10}disabl", r"edr.{0,10}disabl",
                  r"diagnostic.{0,15}delet"]),
           (0.4, [r"disabl", r"stop", r"remov", r"tamper"])],
          require_all=True),

    _Rule("defense-evasion", "T1055", None,
          "Process injection — memory allocation and remote thread creation.",
          [(0.6, [r"process\s+inject", r"virtualallocex",
                  r"writeprocessmemory", r"createremotethread",
                  r"dll\s+inject", r"reflective\s+load"]),
           (0.4, [r"inject", r"shellcode", r"hollow", r"payload"])],
          require_all=True),

    _Rule("defense-evasion", "T1036", "T1036.005",
          "Executable masquerading with lookalike name or double extension.",
          [(0.6, [r"double.?extension", r"masquerad",
                  r"\.(txt|pdf|jpg)\.exe", r"lookalike"]),
           (0.4, [r"execut", r"binary", r"suspicious\s+name"])],
          require_all=True),

    # ── Discovery ─────────────────────────────────────────────────────────

    _Rule("discovery", "T1087", "T1087.002",
          "Domain account and group enumeration.",
          [(0.5, [r"net\s+user", r"net\s+group", r"get-domainuser",
                  r"get-aduser", r"ldap.{0,10}enum",
                  r"\bbloodhound\b", r"\bsharphound\b"]),
           (0.5, [r"enum", r"discover", r"list\s+accounts?",
                  r"domain\s+user"])],
          require_all=True),

    _Rule("discovery", "T1046", None,
          "Network service and port scanning.",
          [(0.6, [r"\bnmap\b", r"\bmasscan\b", r"port\s+scan",
                  r"service\s+scan", r"syn\s+scan", r"arp.?scan"]),
           (0.4, [r"discover", r"enum", r"sweep", r"probe"])],
          require_all=True),

    _Rule("discovery", "T1069", "T1069.002",
          "Domain group and permission enumeration.",
          [(0.6, [r"net\s+localgroup", r"get-domaingroup",
                  r"\bnltest\b", r"domain\s+trust"]),
           (0.4, [r"enum", r"trust", r"permission", r"acl"])],
          require_all=True),

    _Rule("discovery", "T1526", None,
          "Cloud service enumeration.",
          [(0.5, [r"listbuckets", r"describeinstances", r"listroles",
                  r"describesecuritygroups", r"get\s+/subscriptions"]),
           (0.5, [r"enum", r"discover", r"aws", r"azure", r"gcp",
                  r"cloud\s+resource"])],
          require_all=True),

    _Rule("discovery", "T1018", None,
          "Remote system discovery via arp, ping sweep, or net view.",
          [(0.6, [r"\barp\s+-a\b", r"net\s+view", r"ping\s+sweep",
                  r"get-smbshare"]),
           (0.4, [r"discover", r"internal\s+host", r"network\s+topolog",
                  r"subnet"])],
          require_all=True),

    # ── Lateral Movement ──────────────────────────────────────────────────

    _Rule("lateral-movement", "T1021", "T1021.001",
          "RDP-based lateral movement to internal hosts.",
          [(0.6, [r"\brdp\b", r"remote\s+desktop", r"\b3389\b"]),
           (0.4, [r"lateral", r"pivot", r"internal.*host",
                  r"multiple.*host", r"workstation.*server"])],
          require_all=True),

    _Rule("lateral-movement", "T1021", "T1021.002",
          "SMB / Windows Admin Share lateral movement.",
          [(0.5, [r"\bsmb\b", r"admin\$", r"ipc\$",
                  r"\b445\b", r"psexec", r"smbexec"]),
           (0.5, [r"lateral", r"remote\s+exec", r"multiple.*host",
                  r"deploy", r"drop.{0,10}exe"])],
          require_all=True),

    _Rule("lateral-movement", "T1021", "T1021.006",
          "WMI-based remote execution for lateral movement.",
          [(0.5, [r"\bwmi\b", r"\bwmic\b"]),
           (0.5, [r"remote", r"lateral", r"another\s+host",
                  r"target\s+host", r"internal"])],
          require_all=True),

    # NOTE (fixed): T1558 "Steal or Forge Kerberos Tickets" — including
    # .001 Golden Ticket and .002 Silver Ticket — belongs to the
    # Credential Access tactic in MITRE ATT&CK, not Lateral Movement.
    # This is consistent with T1558.003/.004 which are correctly tagged
    # credential-access elsewhere in this same rule set; .001/.002 were
    # simply inconsistent with their own siblings. Verified against
    # attack.mitre.org.

    _Rule("credential-access", "T1558", "T1558.001",
          "Golden Ticket attack via forged TGT.",
          [(0.8, [r"golden\s+ticket", r"krbtgt", r"forged.{0,10}tgt"]),
           (0.2, [r"kerberos", r"ticket", r"\b4769\b"])],
          require_all=True),

    _Rule("credential-access", "T1558", "T1558.002",
          "Silver Ticket attack via forged service ticket.",
          [(0.8, [r"silver\s+ticket", r"forged.{0,10}(service.ticket|tgs)"]),
           (0.2, [r"kerberos", r"service\s+ticket"])],
          require_all=True),

    # NOTE (fixed): T1557 "Adversary-in-the-Middle" (including .001
    # LLMNR/NBT-NS Poisoning and SMB Relay) is tagged Credential Access
    # and Collection in MITRE ATT&CK, not Lateral Movement. Verified
    # against attack.mitre.org.

    _Rule("credential-access", "T1557", "T1557.001",
          "NTLM relay — LLMNR/NBT-NS poisoning.",
          [(0.7, [r"ntlm\s+relay", r"\bresponder\b", r"\binveigh\b",
                  r"llmnr.{0,10}poison", r"nbt.?ns.{0,10}poison"]),
           (0.3, [r"relay", r"poison", r"mitm", r"capture"])],
          require_all=True),

    _Rule("lateral-movement", "T1570", None,
          "Lateral tool transfer — dropping executable on remote share.",
          [(0.6, [r"drop.{0,15}(exe|dll|payload)",
                  r"copy.{0,15}(tool|binary|payload)",
                  r"transfer.{0,15}tool"]),
           (0.4, [r"remote\s+host", r"unc\s+path", r"admin\$",
                  r"lateral"])],
          require_all=True),

    # ── Exfiltration ──────────────────────────────────────────────────────

    _Rule("exfiltration", "T1048", "T1048.003",
          "Exfiltration over unencrypted FTP or SFTP.",
          [(0.5, [r"\bftp\b", r"\bsftp\b"]),
           (0.5, [r"exfil", r"upload", r"transfer.{0,15}external",
                  r"large.{0,10}transfer", r"data.{0,10}out"])],
          require_all=True),

    _Rule("exfiltration", "T1567", "T1567.002",
          "Exfiltration to cloud storage service.",
          [(0.5, [r"\bs3\b", r"dropbox", r"onedrive",
                  r"google\s+drive", r"sharepoint", r"blob\s+storage",
                  r"wetransfer"]),
           (0.5, [r"upload", r"exfil", r"transfer",
                  r"large.{0,10}(amount|file|data)"])],
          require_all=True),

    _Rule("exfiltration", "T1020", None,
          "Automated exfiltration via inbox forwarding rule.",
          [(0.6, [r"forward.{0,10}rule", r"inbox.{0,10}forward",
                  r"mail.{0,10}redirect", r"auto.{0,10}forward",
                  r"new-inboxrule"]),
           (0.4, [r"external\s+address", r"gmail", r"yahoo",
                  r"personal.{0,10}email"])],
          require_all=True),

    # NOTE (fixed): T1071.004 "Application Layer Protocol: DNS" belongs
    # to the Command and Control tactic in MITRE ATT&CK, not Exfiltration
    # — even when the payload being tunnelled is stolen data, the ATT&CK
    # technique classification for the DNS-tunnelling channel itself is
    # C2. Verified against attack.mitre.org.

    _Rule("command-and-control", "T1071", "T1071.004",
          "DNS tunnelling or high-volume TXT/NULL record exfiltration.",
          [(0.6, [r"dns.{0,10}tunnel", r"dns.{0,10}exfil",
                  r"txt\s+record", r"null\s+record", r"\bdga\b"]),
           (0.4, [r"dns", r"exfil", r"covert", r"tunnel"])],
          require_all=True),

    _Rule("exfiltration", "T1030", None,
          "Data transfer size limits — chunked exfiltration.",
          [(0.6, [r"chunk", r"split.{0,10}transfer",
                  r"size.{0,10}limit", r"throttl"]),
           (0.4, [r"exfil", r"transfer", r"upload"])],
          require_all=True),

    # ── Impact ────────────────────────────────────────────────────────────

    _Rule("impact", "T1486", None,
          "Ransomware: mass file encryption or unknown extension rename.",
          [(0.5, [r"ransomware", r"encrypt.{0,10}file",
                  r"file.{0,10}encrypt"]),
           (0.5, [r"mass\s+renam", r"extension\s+change",
                  r"unknown\s+extension", r"ransom"])],
          require_all=True),

    _Rule("impact", "T1490", None,
          "Shadow copy / backup deletion pre-encryption.",
          [(0.7, [r"shadow\s+cop", r"vssadmin.{0,10}delete",
                  r"wmic.{0,20}shadowcopy.{0,10}delete",
                  r"bcdedit.{0,20}recoveryenabled"]),
           (0.3, [r"delet", r"remov", r"disabl"])],
          require_all=True),

    _Rule("impact", "T1485", None,
          "Data destruction: mass deletion or disk wipe.",
          [(0.5, [r"mass\s+delet", r"\bwipe\b", r"destroy",
                  r"format.{0,10}disk", r"mbr.{0,10}overwrite"]),
           (0.5, [r"file", r"disk", r"data", r"volume"])],
          require_all=True),

    _Rule("impact", "T1496", None,
          "Resource hijacking: cryptomining on compromised host.",
          [(0.5, [r"crypto.{0,10}min", r"mining\s+pool",
                  r"\bxmr\b", r"\bmonero\b"]),
           (0.5, [r"pool", r"miner", r"coin",
                  r"port\s+3333", r"port\s+4444", r"high\s+cpu"])],
          require_all=True),

    _Rule("impact", "T1531", None,
          "Account access removal: bulk deletion or lockout.",
          [(0.6, [r"account.{0,10}delet", r"bulk.{0,10}delet",
                  r"mass.{0,10}lockout", r"disable.{0,10}account"]),
           (0.4, [r"user", r"account", r"access"])],
          require_all=True),

    # ── Initial Access ────────────────────────────────────────────────────

    _Rule("initial-access", "T1566", "T1566.001",
          "Spearphishing attachment delivering macro or script payload.",
          [(0.5, [r"phish", r"malicious.{0,10}attach",
                  r"office.{0,10}macro", r"\.docm\b",
                  r"\.xlsm\b", r"\.hta\b", r"\.iso\b"]),
           (0.5, [r"spawn", r"child.{0,10}process",
                  r"macro", r"winword", r"excel"])],
          require_all=True),

    _Rule("initial-access", "T1190", None,
          "Exploitation of public-facing web application.",
          [(0.5, [r"web.{0,10}exploit", r"\bsqli\b",
                  r"sql\s+inject", r"\brce\b",
                  r"remote\s+code\s+exec"]),
           (0.5, [r"public.{0,10}facing", r"web\s+app",
                  r"http", r"request", r"endpoint"])],
          require_all=True),

    _Rule("initial-access", "T1078", None,
          "Valid credentials used for initial access.",
          [(0.5, [r"valid\s+credential", r"stolen\s+credential",
                  r"compromised\s+account", r"account\s+takeover"]),
           (0.5, [r"initial\s+access", r"first\s+(login|logon|access)",
                  r"new\s+device", r"unknown\s+location"])],
          require_all=True),

    # ── Collection ────────────────────────────────────────────────────────

    _Rule("collection", "T1560", "T1560.001",
          "Archive creation for staging data before exfiltration.",
          [(0.5, [r"\b7z\b", r"winrar", r"\.zip\b",
                  r"\barchive\b", r"\bcompress\b"]),
           (0.5, [r"stage", r"collect", r"before.{0,10}exfil",
                  r"usb", r"removable"])],
          require_all=True),

    _Rule("collection", "T1114", "T1114.002",
          "Remote email collection via direct mailbox access.",
          [(0.5, [r"email.{0,10}collect", r"mailbox.{0,10}access",
                  r"exchange.{0,10}read", r"\bowa\b"]),
           (0.5, [r"bulk.{0,10}read", r"inbox",
                  r"forward", r"harvest"])],
          require_all=True),

    _Rule("collection", "T1056", "T1056.001",
          "Keylogger installed via hook or driver.",
          [(0.6, [r"keylog", r"keystroke",
                  r"wh_keyboard", r"setwindowshookex"]),
           (0.4, [r"hook", r"input\s+capture",
                  r"monitor", r"record"])],
          require_all=True),

    # ── Command and Control ───────────────────────────────────────────────

    # NOTE (fixed): the second signal group previously included a bare
    # `https?` pattern at weight 0.5 with min_score=0.5 and require_all=
    # False, meaning ANY mention of "http" or "https" — with none of the
    # actual C2 vocabulary in the first group — was enough to classify a
    # query as C2 beaconing. Switched to require_all=True and dropped the
    # bare protocol pattern from the second group so both a genuine C2
    # term AND a supporting behavioural signal are required.
    _Rule("command-and-control", "T1071", "T1071.001",
          "C2 beaconing over HTTP/HTTPS at regular intervals.",
          [(0.5, [r"\bbeacon", r"\bc2\b", r"command.{0,10}control",
                  r"call.{0,10}home"]),
           (0.5, [r"regular.{0,10}interval", r"periodic",
                  r"same.{0,15}external.{0,10}ip", r"jitter"])],
          require_all=True),

    _Rule("command-and-control", "T1572", None,
          "Protocol tunnelling for covert C2 channel.",
          [(0.6, [r"\btunnel\b", r"encapsulat"]),
           (0.4, [r"dns.{0,10}tunnel", r"icmp.{0,10}tunnel",
                  r"http.{0,10}tunnel", r"ssh.{0,10}tunnel",
                  r"port.{0,10}forward"])],
          require_all=True),

    _Rule("command-and-control", "T1090", "T1090.003",
          "Tor / anonymisation network used for C2.",
          [(0.8, [r"\btor\b", r"onion\s+network",
                  r"exit\s+node", r"\b9001\b", r"\b9030\b"]),
           (0.2, [r"anonymi", r"proxy", r"dark\s+web"])],
          require_all=True),
]


def _run_heuristics(nl_query: str, t0: float, taxonomy) -> "ClassificationResult | None":
    """
    Evaluate all heuristic rules against nl_query.

    Returns the highest-scoring ClassificationResult that (a) clears its
    own rule's min_score, (b) clears the global _HEURISTIC_BYPASS_FLOOR,
    and (c) verifies against the live taxonomy — or None if nothing meets
    all three bars, signalling the caller to fall through to full LLM
    chain-of-thought reasoning.

    Ties broken by preferring sub-technique over parent technique.
    """
    q          = nl_query.lower()
    best_score = 0.0
    best_rule: _Rule | None = None

    for rule in _RULES:
        s = rule.score(q)
        if s > best_score or (
            s == best_score
            and best_rule is not None
            and rule.sub_technique is not None
            and best_rule.sub_technique is None
        ):
            best_score = s
            best_rule  = rule

    if best_rule is None:
        return None

    # Global bypass floor — independent of best_rule's own (possibly much
    # lower) min_score. A rule that merely fired is not automatically
    # trusted to skip LLM reasoning.
    if best_score < _HEURISTIC_BYPASS_FLOOR:
        return None

    # Defense in depth: even a hardcoded rule can have an authoring error
    # (this file previously shipped several — see NOTE (fixed) comments
    # above). Verify the winning rule's tactic/technique/sub_technique
    # triple against the live taxonomy before trusting it; if it doesn't
    # verify, fall through to the LLM rather than emitting a wrong label.
    try:
        technique_entry, tactic_entry = _verify_binding(
            taxonomy, best_rule.technique, best_rule.sub_technique, best_rule.tactic
        )
    except IRValidationError:
        log.error(
            "Heuristic rule failed taxonomy verification — falling through "
            "to LLM. This indicates a bug in the _RULES table.",
            extra={"tactic": best_rule.tactic, "technique": best_rule.technique,
                   "sub_technique": best_rule.sub_technique},
        )
        return None

    return ClassificationResult(
        nl_query               = nl_query,
        tactic                 = tactic_entry.shortname,
        technique              = best_rule.technique,
        sub_technique          = best_rule.sub_technique,
        rationale              = best_rule.rationale,
        confidence             = round(best_score, 4),
        candidates_considered  = [best_rule.technique],
        attempts               = 0,
        elapsed_s              = round(time.monotonic() - t0, 3),
    )


def _run_heuristics_multi(
    nl_query: str,
    t0: float,
    taxonomy,
    max_techniques: int = 5,
) -> list["ClassificationResult"]:
    """
    Multi-match counterpart to _run_heuristics(). Evaluates the same rule
    set but returns every rule that clears both its own min_score AND
    _HEURISTIC_MERGE_FLOOR (a lower bar than the single-best bypass floor,
    since these results are merged with — not substituted for — LLM
    reasoning). Every returned item is taxonomy-verified.

    Returns:
        Ranked list of ClassificationResult, highest confidence first.
        Empty list if nothing clears the merge floor — caller should still
        run the LLM path regardless of what this returns.
    """
    q = nl_query.lower()
    best_by_key: dict[tuple[str, str | None], tuple[float, _Rule]] = {}

    for rule in _RULES:
        s = rule.score(q)
        if s < _HEURISTIC_MERGE_FLOOR:
            continue
        key = (rule.technique, rule.sub_technique)
        if key not in best_by_key or s > best_by_key[key][0]:
            best_by_key[key] = (s, rule)

    if not best_by_key:
        return []

    ranked  = sorted(best_by_key.values(), key=lambda pair: pair[0], reverse=True)
    elapsed = round(time.monotonic() - t0, 3)

    results: list[ClassificationResult] = []
    for s, rule in ranked:
        try:
            technique_entry, tactic_entry = _verify_binding(
                taxonomy, rule.technique, rule.sub_technique, rule.tactic
            )
        except IRValidationError:
            log.error(
                "Heuristic rule failed taxonomy verification — dropping "
                "from multi-technique result. This indicates a bug in the "
                "_RULES table.",
                extra={"tactic": rule.tactic, "technique": rule.technique,
                       "sub_technique": rule.sub_technique},
            )
            continue

        results.append(ClassificationResult(
            nl_query               = nl_query,
            tactic                 = tactic_entry.shortname,
            technique              = rule.technique,
            sub_technique          = rule.sub_technique,
            rationale              = rule.rationale,
            confidence             = round(s, 4),
            candidates_considered  = [rule.technique],
            attempts               = 0,
            elapsed_s              = elapsed,
        ))
        if len(results) >= max_techniques:
            break

    return results


def _verify_binding(taxonomy, technique: str, sub_technique: str | None, tactic: str):
    """
    Verify a single (tactic, technique, sub_technique) triple against the
    live ATT&CK taxonomy. Shared by the LLM path (via
    ATTCKClassifierAgent._verify_binding, which now delegates here) and
    the heuristic path, so a hardcoded rule gets exactly the same
    hallucination/error guarantee as an LLM selection.

    Returns:
        (technique_entry, tactic_entry) on success.

    Raises:
        IRValidationError: On any mismatch — unknown technique, unknown
                           sub-technique, sub-technique/parent mismatch,
                           unknown tactic, or technique/tactic mismatch.
    """
    technique_entry = taxonomy.get_technique(technique)
    if technique_entry is None:
        raise IRValidationError(
            f"technique '{technique}' does not exist in the loaded ATT&CK taxonomy",
            details={"technique": technique},
        )

    if sub_technique is not None:
        sub_entry = taxonomy.get_technique(sub_technique)
        if sub_entry is None:
            raise IRValidationError(
                f"sub_technique '{sub_technique}' does not exist in the "
                f"loaded ATT&CK taxonomy",
                details={"sub_technique": sub_technique},
            )
        if sub_entry.parent_id != technique:
            raise IRValidationError(
                f"sub_technique '{sub_technique}' does not belong to "
                f"technique '{technique}' (actual parent: "
                f"'{sub_entry.parent_id}')",
                details={"technique": technique, "sub_technique": sub_technique},
            )

    tactic_entry = taxonomy.get_tactic(tactic)
    if tactic_entry is None:
        raise IRValidationError(
            f"tactic '{tactic}' does not exist in the loaded ATT&CK taxonomy",
            details={"tactic": tactic},
        )
    if tactic_entry.shortname not in technique_entry.tactic_names:
        raise IRValidationError(
            f"technique '{technique}' is not associated with tactic "
            f"'{tactic}' (technique belongs to: {technique_entry.tactic_names})",
            details={"tactic": tactic, "technique": technique},
        )

    return technique_entry, tactic_entry


# Number of lexically-narrowed candidates shown to the LLM for CoT reasoning.
# Large enough to include the correct technique even when the keyword
# search ranks it imperfectly; small enough to keep prompt cost low.
_DEFAULT_CANDIDATE_K = 12


def _safe_confidence(value, default: float = 0.5) -> float:
    """
    Coerce an LLM-provided confidence value to a float, defensively.

    Handles the common failure modes seen from JSON-mode LLM output:
      - missing key                 -> caller already defaults via .get()
      - explicit JSON null          -> float(None) raises TypeError
      - a numeric-looking string    -> float("0.7") works fine
      - a non-numeric string        -> float("high") raises ValueError
      - out-of-range values         -> clamped by callers after this
    Never raises; always returns a usable float.
    """
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        log.warning(
            "LLM returned a non-numeric confidence value — using default",
            extra={"raw_value": repr(value), "default": default},
        )
        return default


@dataclass
class ClassificationResult:
    """Output of a single ATTCKClassifierAgent.classify() call. Also used,
    unmodified, as the element type of the list returned by
    classify_multi() — each match gets its own ClassificationResult."""

    nl_query:        str
    tactic:          str             # ATT&CK tactic shortname
    technique:       str             # ATT&CK technique ID, e.g. "T1110"
    sub_technique:   str | None      # ATT&CK sub-technique ID, e.g. "T1110.001"
    rationale:       str             # chain-of-thought justification (kept for audit trail)
    confidence:      float           # self-reported [0.0, 1.0]
    candidates_considered: list[str] = field(default_factory=list)
    attempts:        int   = 1
    elapsed_s:        float = 0.0

    def to_dict(self) -> dict:
        return {
            "nl_query":              self.nl_query,
            "tactic":                self.tactic,
            "technique":             self.technique,
            "sub_technique":         self.sub_technique,
            "rationale":             self.rationale,
            "confidence":            self.confidence,
            "candidates_considered": self.candidates_considered,
            "attempts":              self.attempts,
            "elapsed_s":             self.elapsed_s,
        }


# ── Chain-of-thought prompt template ───────────────────────────────────────

_CLASSIFIER_SYSTEM_PROMPT = """You are a MITRE ATT&CK classification expert.

Given a natural language security detection description, identify the
single MOST SPECIFIC MITRE ATT&CK technique (and sub-technique, if
applicable) it corresponds to, choosing ONLY from the candidate list
provided below. Do not invent a technique ID that is not in the list.

Reasoning process (think step by step, then output JSON):
  1. Identify the adversary BEHAVIOUR described (not just keywords).
  2. Compare that behaviour against each candidate's description.
  3. Select the candidate whose description most precisely matches the
     behaviour. Prefer a sub-technique over its parent technique when the
     description's specificity is described in the query (e.g. "password
     guessing" -> T1110.001, not just T1110).
  4. If genuinely no candidate fits, select the closest available option
     and set confidence below 0.5.

Output ONLY a JSON object with this exact shape, no markdown, no preamble:
{{
  "tactic": "<tactic-shortname>",
  "technique": "T####",
  "sub_technique": "T####.###" or null,
  "rationale": "<one to two sentences citing the specific behaviour-to-description match>",
  "confidence": <float 0.0-1.0>
}}

CANDIDATES:
{candidates_block}
""".strip()


# ── Multi-technique prompt template ────────────────────────────────────────
# Same taxonomy grounding and candidate list as the single-technique prompt
# above — only the requested output shape changes, from one object to a
# ranked array.

_MULTI_CLASSIFIER_SYSTEM_PROMPT = """You are a MITRE ATT&CK classification expert.

Given a natural language security detection description, identify EVERY
plausible MITRE ATT&CK technique (and sub-technique, where applicable) it
could correspond to, choosing ONLY from the candidate list below. Do not
invent a technique ID that is not in the list.

A single detection often legitimately maps to more than one technique —
e.g. "repeated failed SSH logins from one IP" is password guessing
(T1110.001), but could also indicate password spraying (T1110.003) if
multiple accounts are targeted. Return every technique a reasonable
analyst would tag, ranked by how precisely the query's described
behaviour matches that technique's official description. Return between
1 and 5 techniques — do not pad the list with weak matches just to reach 5.

Reasoning process (think step by step, then output JSON):
  1. Identify every distinct adversary BEHAVIOUR described in the query.
  2. Compare each behaviour against each candidate's description.
  3. Prefer a sub-technique over its parent technique when the query's
     specificity supports it (e.g. "password guessing" -> T1110.001).
  4. Score each match's confidence by how precisely it fits — not by how
     common the technique is in general.
  5. Sort matches by confidence, descending.

Output ONLY a JSON object with this exact shape, no markdown, no preamble:
{{
  "matches": [
    {{
      "tactic": "<tactic-shortname>",
      "technique": "T####",
      "sub_technique": "T####.###" or null,
      "rationale": "<one sentence citing the specific behaviour-to-description match>",
      "confidence": <float 0.0-1.0>
    }}
  ]
}}

CANDIDATES:
{candidates_block}
""".strip()


class ATTCKClassifierAgent:
    """
    Infers MITRE ATT&CK tactic/technique/sub-technique bindings for natural
    language detection descriptions, using taxonomy-grounded chain-of-thought
    reasoning with mandatory post-hoc verification.

    classify() returns the single best match. classify_multi() runs the
    identical pipeline but returns every technique that clears taxonomy
    verification, ranked by confidence.

    Args:
        client:        LLMClient instance (any supported provider).
        candidate_k:   Number of lexical candidates to surface for CoT
                       reasoning (default 12).
        max_retries:   Retry attempts if the LLM selects an ID not present
                       in the candidate set or taxonomy (default 2).
    """

    def __init__(
        self,
        client,
        candidate_k: int = _DEFAULT_CANDIDATE_K,
        max_retries: int = 2,
    ) -> None:
        self.client      = client
        self.candidate_k = candidate_k
        self.max_retries = max_retries
        self._taxonomy   = get_taxonomy()
        self._parser     = ResponseParser()

        log.info(
            "ATTCKClassifierAgent initialised",
            extra={
                "candidate_k": candidate_k,
                "max_retries": max_retries,
                "taxonomy_summary": self._taxonomy.summary(),
            },
        )

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def classify(self, nl_query: str) -> ClassificationResult:
        """
        Classify a natural language query against the MITRE ATT&CK taxonomy.

        Args:
            nl_query: Free-text detection description.

        Returns:
            ClassificationResult with verified tactic/technique binding.

        Raises:
            NLSIEMError: If no valid classification could be produced after
                         all retry attempts (e.g. candidate search returned
                         nothing and the LLM could not select a fallback).
        """
        t0 = time.monotonic()
        # ── Heuristic fast-path ───────────────────────────────────────────
        # Only bypasses the LLM when the winning rule clears BOTH its own
        # min_score AND the global _HEURISTIC_BYPASS_FLOOR, and only after
        # taxonomy verification succeeds. Anything weaker falls through to
        # full CoT reasoning.
        heuristic_result = _run_heuristics(nl_query, t0, self._taxonomy)
        if heuristic_result is not None:
            log.info(
                "Heuristic fast-path hit — skipping LLM classification",
                extra={"summary": heuristic_result.tactic + "/" + heuristic_result.technique,
                    "confidence": heuristic_result.confidence},
            )
            return heuristic_result
        # ── End heuristic fast-path ───────────────────────────────────────

        candidates = self._taxonomy.search_techniques(nl_query, top_k=self.candidate_k)
        if not candidates:
            # Fall back to a broad sweep across all techniques' names only,
            # rather than failing outright — better to give the LLM *some*
            # grounded options than none.
            candidates = self._taxonomy.all_techniques()[: self.candidate_k]
            log.warning(
                "No lexical candidates found — falling back to a broad slice "
                "of the full technique list",
                extra={"nl_query": nl_query[:80]},
            )

        candidate_ids = [c.technique_id for c in candidates]
        candidates_block = self._format_candidates(candidates)

        last_error = ""
        parsed: dict = {}   # defined up front so an early-failing except
                            # block below never hits a NameError on `parsed`
        for attempt in range(1, self.max_retries + 1):
            try:
                messages = [
                    {
                        "role": "system",
                        "content": _CLASSIFIER_SYSTEM_PROMPT.format(
                            candidates_block=candidates_block
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f'NL Query: "{nl_query}"'
                            + (f"\n\nPrevious attempt was rejected: {last_error}. "
                               f"Choose ONLY from the candidate list above."
                               if attempt > 1 else "")
                        ),
                    },
                ]

                raw = self.client.complete(messages=messages, json_mode=True, temperature=0.0)
                parsed = self._parser.extract_ir_dict(raw)

                result = self._validate_and_build(
                    nl_query   = nl_query,
                    parsed     = parsed,
                    candidate_ids = candidate_ids,
                    attempts   = attempt,
                    elapsed_s  = round(time.monotonic() - t0, 3),
                )

                log.info(
                    "ATT&CK classification succeeded",
                    extra={"label": f"{result.tactic}/{result.technique}", "attempts": attempt},
                )
                return result

            # NOTE (fixed): TypeError added — a JSON-null "confidence" field
            # (`float(None)`) previously escaped this tuple entirely and
            # crashed the whole classify() call instead of triggering a
            # retry like every other malformed-response case does.
            except (IRValidationError, ValueError, TypeError) as exc:
                last_error = str(exc)
                log.warning(
                    "Classification attempt rejected — retrying",
                    extra={"attempt": attempt, "error": last_error, "parsed": parsed},
                )
            except LLMError as exc:
                last_error = f"LLM error: {exc}"
                log.warning("LLM error during classification — retrying", extra={"error": str(exc)})

        elapsed = round(time.monotonic() - t0, 3)
        raise NLSIEMError(
            f"ATTCKClassifierAgent failed after {self.max_retries} attempts "
            f"for query: '{nl_query[:80]}'",
            details={
                "nl_query":     nl_query,
                "last_error":   last_error,
                "candidates":   candidate_ids,
                "elapsed_s":    elapsed,
            },
        )

    def classify_multi(self, nl_query: str, max_techniques: int = 5) -> list[ClassificationResult]:
        """
        Classify a natural language query against the MITRE ATT&CK taxonomy,
        returning EVERY plausible technique ranked by confidence — instead
        of classify()'s single best match.

        The LLM is always called (heuristics never replace it here — see
        classify() for the fast-path-eligible single-best case). Heuristic
        hits above _HEURISTIC_MERGE_FLOOR are folded in as a recall boost
        for techniques the LLM's semantic reasoning might not have
        surfaced, but the LLM result is treated as the primary signal: on
        a key collision, the LLM's entry is kept unless the heuristic
        score exceeds it by a wide margin (>= 0.2), since the two scores
        are on different, not-directly-comparable scales (weighted
        keyword sum vs. self-reported LLM confidence) and blindly taking
        the max let a crude keyword match silently outrank a taxonomy-
        grounded LLM judgement for the same technique.

        Same taxonomy-verification guarantee throughout: a hallucinated
        technique ID can never survive into the returned list — an
        unverifiable item is dropped, not silently kept.

        Args:
            nl_query:       Free-text detection description.
            max_techniques: Upper bound on how many ranked techniques to
                            return after verification (default 5).

        Returns:
            list[ClassificationResult], ordered by confidence descending,
            length >= 1 on success.

        Raises:
            NLSIEMError: If no technique could be verified after all
                         retry attempts (heuristic hits, if any, are still
                         returned in that case rather than raising, since
                         they already passed taxonomy verification when
                         they were computed).
        """
        t0 = time.monotonic()

        heuristic_hits = _run_heuristics_multi(nl_query, t0, self._taxonomy, max_techniques)
        if heuristic_hits:
            log.info(
                "Heuristic hits found — will still run LLM and merge",
                extra={
                    "count": len(heuristic_hits),
                    "top":   f"{heuristic_hits[0].tactic}/{heuristic_hits[0].technique}",
                },
            )

        try:
            llm_hits = self._classify_multi_via_llm(nl_query, t0, max_techniques)
        except NLSIEMError:
            # The LLM path exhausted its retries. Don't lose heuristic
            # signal we already verified — degrade to heuristics-only
            # rather than raising, if we have anything to return at all.
            if heuristic_hits:
                log.warning(
                    "LLM multi-classification failed after retries — "
                    "falling back to heuristic-only results",
                    extra={"count": len(heuristic_hits)},
                )
                return heuristic_hits
            raise

        # Merge policy: LLM entries win ties. A heuristic hit only
        # displaces or adds to the merged result if it's a new key, or if
        # its score beats the LLM's for that same key by a wide margin —
        # the two scores are not on a directly comparable scale, so a
        # small numeric edge shouldn't be enough to override taxonomy-
        # grounded LLM reasoning.
        _OVERRIDE_MARGIN = 0.2
        merged: dict[tuple[str, str | None], ClassificationResult] = {
            (r.technique, r.sub_technique): r for r in llm_hits
        }
        for h in heuristic_hits:
            key = (h.technique, h.sub_technique)
            if key not in merged:
                merged[key] = h
            elif h.confidence > merged[key].confidence + _OVERRIDE_MARGIN:
                merged[key] = h

        ranked = sorted(merged.values(), key=lambda r: r.confidence, reverse=True)
        results = ranked[:max_techniques]

        log.info(
            "Multi-technique ATT&CK classification complete",
            extra={
                "count":           len(results),
                "heuristic_count": len(heuristic_hits),
                "llm_count":       len(llm_hits),
            },
        )
        return results

    def _classify_multi_via_llm(
        self,
        nl_query: str,
        t0: float,
        max_techniques: int,
    ) -> list[ClassificationResult]:
        """
        LLM-only half of classify_multi(), factored out so classify_multi()
        can always invoke it and merge the result with heuristic hits
        instead of treating heuristics and the LLM as mutually exclusive
        paths.

        Raises:
            NLSIEMError: If no technique could be verified after all
                         retry attempts. Caller (classify_multi) decides
                         whether to fall back to heuristic-only results.
        """
        candidates = self._taxonomy.search_techniques(nl_query, top_k=self.candidate_k)
        if not candidates:
            candidates = self._taxonomy.all_techniques()[: self.candidate_k]
            log.warning(
                "No lexical candidates found — falling back to a broad slice "
                "of the full technique list",
                extra={"nl_query": nl_query[:80]},
            )

        candidate_ids = [c.technique_id for c in candidates]
        candidates_block = self._format_candidates(candidates)

        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                messages = [
                    {
                        "role": "system",
                        "content": _MULTI_CLASSIFIER_SYSTEM_PROMPT.format(
                            candidates_block=candidates_block
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f'NL Query: "{nl_query}"'
                            + (f"\n\nPrevious attempt was rejected: {last_error}. "
                               f"Choose ONLY from the candidate list above, and "
                               f"return valid JSON matching the required shape."
                               if attempt > 1 else "")
                        ),
                    },
                ]

                raw = self.client.complete(messages=messages, json_mode=True, temperature=0.0)
                parsed = self._parser.extract_ir_dict(raw)

                results = self._validate_and_build_multi(
                    nl_query       = nl_query,
                    parsed         = parsed,
                    candidate_ids  = candidate_ids,
                    max_techniques = max_techniques,
                    attempts       = attempt,
                    elapsed_s      = round(time.monotonic() - t0, 3),
                )

                log.info(
                    "LLM multi-technique classification succeeded",
                    extra={"count": len(results), "attempts": attempt},
                )
                return results

            except (IRValidationError, ValueError) as exc:
                last_error = str(exc)
                log.warning(
                    "Multi-technique classification attempt rejected — retrying",
                    extra={"attempt": attempt, "error": last_error},
                )
            except LLMError as exc:
                last_error = f"LLM error: {exc}"
                log.warning("LLM error during multi-classification — retrying", extra={"error": str(exc)})

        elapsed = round(time.monotonic() - t0, 3)
        raise NLSIEMError(
            f"ATTCKClassifierAgent.classify_multi failed after {self.max_retries} "
            f"attempts for query: '{nl_query[:80]}'",
            details={
                "nl_query":   nl_query,
                "last_error": last_error,
                "candidates": candidate_ids,
                "elapsed_s":  elapsed,
            },
        )

    def attach(self, base_ir: IRQuery, classification: ClassificationResult) -> AttckIRQuery:
        """
        Combine a structurally-parsed IRQuery with a verified ATT&CK
        classification into a single AttckIRQuery.

        Args:
            base_ir:        IRQuery produced by ParserAgent (Layer 5).
            classification: Output of classify().

        Returns:
            AttckIRQuery ready for translation and coverage accounting.
        """
        return AttckIRQuery.from_ir_query(
            base          = base_ir,
            tactic        = classification.tactic,
            technique     = classification.technique,
            sub_technique = classification.sub_technique,
        )

    def attach_multi(
        self,
        base_ir: IRQuery,
        classifications: list[ClassificationResult],
    ) -> list[AttckIRQuery]:
        """
        Attach every technique in a classify_multi() result to the same
        base IRQuery, producing one AttckIRQuery per technique binding.

        Useful for coverage accounting where a single detection
        legitimately counts toward several ATT&CK techniques — feed the
        resulting list into ATTCKCoverageAuditor as separate rule entries
        that all happen to share one underlying query.

        Args:
            base_ir:         IRQuery produced by ParserAgent (Layer 5).
            classifications: Output of classify_multi().

        Returns:
            list[AttckIRQuery], same order/length as classifications.
        """
        return [
            AttckIRQuery.from_ir_query(
                base          = base_ir,
                tactic        = c.tactic,
                technique     = c.technique,
                sub_technique = c.sub_technique,
            )
            for c in classifications
        ]

    def classify_and_attach(self, nl_query: str, base_ir: IRQuery) -> tuple[AttckIRQuery, ClassificationResult]:
        """Convenience: classify() followed by attach() in one call."""
        result = self.classify(nl_query)
        return self.attach(base_ir, result), result

    def classify_and_attach_multi(
        self,
        nl_query: str,
        base_ir: IRQuery,
        max_techniques: int = 5,
    ) -> tuple[list[AttckIRQuery], list[ClassificationResult]]:
        """Convenience: classify_multi() followed by attach_multi() in one call."""
        results = self.classify_multi(nl_query, max_techniques=max_techniques)
        return self.attach_multi(base_ir, results), results

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _format_candidates(self, candidates: list[TechniqueEntry]) -> str:
        """Render candidate techniques (and their sub-techniques) for the prompt."""
        lines = []
        for c in candidates:
            kind = "sub-technique" if c.is_subtechnique else "technique"
            lines.append(
                f'- {c.technique_id} ({kind}) "{c.name}" '
                f"[tactics: {', '.join(c.tactic_names)}]: "
                f"{c.description[:220]}"
            )
            if not c.is_subtechnique:
                subs = self._taxonomy.get_sub_techniques(c.technique_id)
                for s in subs[:4]:   # cap sub-technique listing per parent
                    lines.append(
                        f'    - {s.technique_id} (sub-technique) "{s.name}": '
                        f"{s.description[:160]}"
                    )
        return "\n".join(lines)

    def _validate_and_build(
        self,
        nl_query:      str,
        parsed:        dict,
        candidate_ids: list[str],
        attempts:      int,
        elapsed_s:     float,
    ) -> ClassificationResult:
        """
        Validate the LLM's classification JSON against both the candidate
        set and the live taxonomy before constructing a ClassificationResult.

        Raises:
            ValueError: If required fields are missing or malformed.
            IRValidationError: If the selected technique cannot be verified
                               against the loaded MITRE ATT&CK taxonomy.
        """
        technique     = str(parsed.get("technique", "")).strip().upper()
        sub_technique = parsed.get("sub_technique")
        # Fix common LLM behavior:
        # if technique itself is a sub-technique, split it into parent+child.
        if "." in technique:
            if sub_technique in (None, "", technique):
                sub_technique = technique
            technique = technique.split(".")[0]
        tactic        = str(parsed.get("tactic", "")).strip().lower()
        rationale     = str(parsed.get("rationale", "")).strip()
        # (fixed) was: float(parsed.get("confidence", 0.5)) — raised
        # uncaught TypeError on an explicit JSON null. _safe_confidence()
        # never raises and logs the anomaly instead.
        confidence    = _safe_confidence(parsed.get("confidence", 0.5))

        if sub_technique is not None:
            sub_technique = str(sub_technique).strip().upper()
            if sub_technique.lower() in ("null", "none", ""):
                sub_technique = None

        if not technique:
            raise ValueError("LLM response missing required 'technique' field")
        if not tactic:
            raise ValueError("LLM response missing required 'tactic' field")

        # The technique selected must actually verify against the taxonomy —
        # this is the hard guarantee that prevents a hallucinated ID from
        # silently reaching the IR layer, regardless of whether it happened
        # to also appear in the candidate list (defence in depth).
        technique_entry, tactic_entry = _verify_binding(
            self._taxonomy, technique, sub_technique, tactic
        )

        return ClassificationResult(
            nl_query               = nl_query,
            tactic                 = tactic_entry.shortname,
            technique              = technique,
            sub_technique          = sub_technique,
            rationale              = rationale,
            confidence             = max(0.0, min(1.0, confidence)),
            candidates_considered  = candidate_ids,
            attempts               = attempts,
            elapsed_s              = elapsed_s,
        )

    def _verify_binding(
        self,
        technique:     str,
        sub_technique: str | None,
        tactic:        str,
    ):
        """
        Instance-method wrapper kept for backward compatibility with any
        existing callers — delegates to the shared module-level
        _verify_binding() used by both the LLM and heuristic paths, so
        there is exactly one implementation of the verification logic.

        Raises:
            IRValidationError: On any mismatch — unknown technique, unknown
                               sub-technique, sub-technique/parent mismatch,
                               unknown tactic, or technique/tactic mismatch.
        """
        return _verify_binding(self._taxonomy, technique, sub_technique, tactic)

    def _validate_and_build_multi(
        self,
        nl_query:       str,
        parsed:         dict,
        candidate_ids:  list[str],
        max_techniques: int,
        attempts:       int,
        elapsed_s:      float,
    ) -> list[ClassificationResult]:
        """
        Validate every item in the LLM's ranked "matches" array against the
        taxonomy via _verify_binding(). An individual bad item is dropped,
        not fatal — the call only raises if NOTHING survives verification,
        matching the "one bad entry shouldn't discard the good ones"
        design used throughout classify_multi().

        Raises:
            ValueError: If 'matches' is missing, empty, or not a list.
            IRValidationError: If every item fails taxonomy verification.
        """
        raw_matches = parsed.get("matches")
        if not isinstance(raw_matches, list) or not raw_matches:
            raise ValueError("LLM response missing required non-empty 'matches' array")

        results: list[ClassificationResult] = []
        seen: set[tuple[str, str | None]] = set()

        for item in raw_matches:
            # Guard against a non-dict item in the matches array (e.g. the
            # LLM emits a bare string or null in the list) — item.get(...)
            # below would otherwise raise AttributeError, which is NOT in
            # the except tuple and would crash the whole multi-
            # classification instead of just dropping that one item.
            if not isinstance(item, dict):
                log.debug("Dropping non-dict entry from matches array", extra={"item": repr(item)})
                continue

            try:
                technique     = str(item.get("technique", "")).strip().upper()
                sub_technique = item.get("sub_technique")
                if "." in technique:
                    if sub_technique in (None, "", technique):
                        sub_technique = technique
                    technique = technique.split(".")[0]
                tactic     = str(item.get("tactic", "")).strip().lower()
                rationale  = str(item.get("rationale", "")).strip()
                confidence = _safe_confidence(item.get("confidence", 0.5))

                if sub_technique is not None:
                    sub_technique = str(sub_technique).strip().upper()
                    if sub_technique.lower() in ("null", "none", ""):
                        sub_technique = None

                if not technique or not tactic:
                    continue

                technique_entry, tactic_entry = self._verify_binding(technique, sub_technique, tactic)

                key = (technique, sub_technique)
                if key in seen:
                    continue
                seen.add(key)

                results.append(ClassificationResult(
                    nl_query               = nl_query,
                    tactic                 = tactic_entry.shortname,
                    technique              = technique,
                    sub_technique          = sub_technique,
                    rationale              = rationale,
                    confidence             = max(0.0, min(1.0, confidence)),
                    candidates_considered  = candidate_ids,
                    attempts               = attempts,
                    elapsed_s              = elapsed_s,
                ))

            except IRValidationError as exc:
                log.debug("Dropping unverifiable match from multi-result", extra={"error": str(exc)})
                continue
            except (TypeError, ValueError):
                continue

        if not results:
            raise IRValidationError(
                "No technique in the LLM's match list survived taxonomy verification",
                details={"candidates": candidate_ids},
            )

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results[:max_techniques]

    def __repr__(self) -> str:
        return (
            f"ATTCKClassifierAgent(candidate_k={self.candidate_k}, "
            f"max_retries={self.max_retries})"
        )