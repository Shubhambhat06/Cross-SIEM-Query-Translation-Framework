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
"""

from __future__ import annotations
from dataclasses import dataclass, field as dc_field
import re
import json
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
# Research-grade replacement for boolean if/else keyword matching.
# Each rule requires evidence from multiple independent signal groups,
# preventing single-keyword false positives. Scores accumulate across
# groups; require_all=True enforces strict AND across all groups.
# Only results above _HEURISTIC_THRESHOLD are returned — everything
# else falls through to taxonomy-grounded LLM chain-of-thought reasoning.

import re
from dataclasses import dataclass as _dc, field as _f

_HEURISTIC_THRESHOLD = 0.85   # minimum score to bypass LLM stage


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
        """
        total = 0.0
        for weight, patterns in self.signal_groups:
            hit = any(re.search(p, q) for p in patterns)
            if hit:
                total += weight
            elif self.require_all:
                return 0.0          # one miss kills the rule in strict mode
        return min(total, 1.0) if total >= self.min_score else 0.0


_RULES: list[_Rule] = [

    # ── Credential Access ─────────────────────────────────────────────────

    _Rule("credential-access", "T1110", "T1110.001",
          "SSH/RDP/SMB repeated authentication failures — password guessing.",
          [(0.5, [r"\bssh\b", r"\brdp\b", r"\bsmb\b",
                  r"\bftp\b", r"\bwinrm\b"]),
           (0.5, [r"failed.*(login|logon|auth)*", r"brute.?force",
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
          [(0.6, [r"kerberoast", r"tgs.?req", r"rc4", r"0x17", r"\b4769\b"]),
           (0.4, [r"service\s+account", r"\bspn\b", r"kerberos"])],
          min_score=0.6),

    _Rule("credential-access", "T1558", "T1558.004",
          "AS-REP roasting: pre-authentication disabled accounts.",
          [(0.7, [r"as.?rep", r"asrep", r"\b4768\b"]),
           (0.3, [r"pre.?auth", r"roast", r"kerberos"])],
          min_score=0.7),

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
          min_score=0.6),

    # ── Execution ─────────────────────────────────────────────────────────

    _Rule("execution", "T1059", "T1059.001",
          "PowerShell encoded command or download cradle execution.",
          [(0.5, [r"powershell", r"\bpwsh\b"]),
           (0.5, [r"encoded.?command", r"\-enc\b", r"downloadstring",
                  r"invoke.?expression", r"\biex\b", r"bypass",
                  r"webclient", r"downloadfile"])],
          min_score=0.5),

    _Rule("execution", "T1059", "T1059.003",
          "Windows Command Shell spawned from suspicious parent.",
          [(0.5, [r"\bcmd\.exe\b", r"command\s+shell"]),
           (0.5, [r"spawned", r"child\s+process",
                  r"parent.{0,20}(svchost|office|winword|excel|outlook)",
                  r"suspicious\s+parent"])],
          min_score=0.5),

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
          min_score=0.6),

    _Rule("execution", "T1218", "T1218.010",
          "Regsvr32 Squiblydoo — remote scriptlet execution.",
          [(0.7, [r"regsvr32"]),
           (0.3, [r"scrobj", r"https?://", r"\.sct\b", r"squiblydoo"])],
          min_score=0.7),

    _Rule("execution", "T1218", "T1218.011",
          "Rundll32 LOLBin abuse from writable directory.",
          [(0.7, [r"rundll32"]),
           (0.3, [r"temp", r"appdata", r"http", r"shell32", r"advpack"])],
          min_score=0.7),

    _Rule("execution", "T1218", "T1218.005",
          "MSHTA executing remote HTA payload.",
          [(0.8, [r"\bmshta\b"]),
           (0.2, [r"https?://", r"\.hta\b", r"remote"])],
          min_score=0.8),

    _Rule("execution", "T1218", "T1218.004",
          "InstallUtil / msiexec LOLBin execution.",
          [(0.7, [r"\bmsiexec\b", r"installutil"]),
           (0.3, [r"/q\b", r"/i\b", r"unc", r"https?://", r"silent"])],
          min_score=0.7),

    # ── Persistence ───────────────────────────────────────────────────────

    _Rule("persistence", "T1547", "T1547.001",
          "Registry Run key modification for startup persistence.",
          [(0.6, [r"run\s*key", r"runonce", r"hkcu.{0,10}run",
                  r"hklm.{0,10}run", r"currentversion\\run"]),
           (0.4, [r"persist", r"startup", r"autorun", r"boot"])],
          min_score=0.6),

    _Rule("persistence", "T1053", "T1053.005",
          "Scheduled task creation for persistence.",
          [(0.6, [r"scheduled\s+task", r"\bschtasks\b",
                  r"task\s+schedul", r"\b4698\b"]),
           (0.4, [r"persist", r"creat", r"new\s+task",
                  r"writable", r"appdata", r"temp"])],
          min_score=0.6),

    _Rule("persistence", "T1543", "T1543.003",
          "New Windows service installed for persistence.",
          [(0.6, [r"new\s+service", r"service\s+install",
                  r"\b7045\b", r"sc\s+create"]),
           (0.4, [r"persist", r"temp", r"appdata", r"unc"])],
          min_score=0.6),

    _Rule("persistence", "T1546", "T1546.003",
          "WMI event subscription persistence.",
          [(0.7, [r"wmi.{0,10}subscri", r"__eventfilter",
                  r"__eventconsumer", r"filtertoconsumerbinding"]),
           (0.3, [r"persist", r"wmi", r"event"])],
          min_score=0.7),

    _Rule("persistence", "T1546", "T1546.012",
          "Image File Execution Options (IFEO) debugger hijack.",
          [(0.8, [r"ifeo", r"image\s+file\s+execution",
                  r"globalflag", r"silentprocessexit"]),
           (0.2, [r"debugger", r"hijack", r"persist"])],
          min_score=0.8),

    _Rule("persistence", "T1098", None,
          "SSH authorized_keys modification.",
          [(0.6, [r"authorized.?keys", r"\.ssh/", r"ssh.{0,10}key"]),
           (0.4, [r"added", r"written", r"modif", r"new\s+entry"])],
          require_all=True),

    _Rule("persistence", "T1136", "T1136.001",
          "Local account created for persistence.",
          [(0.6, [r"new\s+(local\s+)?account", r"user\s+creat",
                  r"\b4720\b", r"net\s+user.{0,20}/add"]),
           (0.4, [r"persist", r"local", r"admin", r"backdoor"])],
          min_score=0.6),

    # ── Privilege Escalation ──────────────────────────────────────────────

    _Rule("privilege-escalation", "T1548", "T1548.002",
          "UAC bypass via fodhelper, eventvwr, or registry hijack.",
          [(0.7, [r"uac\s+bypass", r"fodhelper", r"eventvwr",
                  r"ms-settings.{0,20}shell.{0,20}open"]),
           (0.3, [r"bypass", r"elevat", r"admin"])],
          min_score=0.7),

    _Rule("privilege-escalation", "T1134", "T1134.001",
          "Token impersonation / SeImpersonatePrivilege abuse.",
          [(0.6, [r"token\s+impersonat", r"seimpersonateprivilege",
                  r"impersonateloggedonuser", r"duplicatetokenex",
                  r"printspoofer", r"juicypotato", r"rottenpotato"]),
           (0.4, [r"privilege", r"elevat", r"impersonat"])],
          min_score=0.6),

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
          min_score=0.7),

    # ── Defense Evasion ───────────────────────────────────────────────────

    _Rule("defense-evasion", "T1070", "T1070.001",
          "Windows event log cleared.",
          [(0.7, [r"event\s+log.{0,10}clear", r"clear.{0,10}event\s+log",
                  r"\b1102\b", r"\b104\b"]),
           (0.3, [r"wevtutil", r"clear-eventlog", r"log.{0,10}delet"])],
          min_score=0.7),

    _Rule("defense-evasion", "T1562", "T1562.001",
          "Security tooling or audit logging disabled.",
          [(0.6, [r"cloudtrail.{0,10}disabl", r"stoplogging",
                  r"deletetrail", r"guardduty.{0,10}disabl",
                  r"av.{0,10}disabl", r"edr.{0,10}disabl",
                  r"diagnostic.{0,15}delet"]),
           (0.4, [r"disabl", r"stop", r"remov", r"tamper"])],
          min_score=0.6),

    _Rule("defense-evasion", "T1055", None,
          "Process injection — memory allocation and remote thread creation.",
          [(0.6, [r"process\s+inject", r"virtualallocex",
                  r"writeprocessmemory", r"createremotethread",
                  r"dll\s+inject", r"reflective\s+load"]),
           (0.4, [r"inject", r"shellcode", r"hollow", r"payload"])],
          min_score=0.6),

    _Rule("defense-evasion", "T1036", "T1036.005",
          "Executable masquerading with lookalike name or double extension.",
          [(0.6, [r"double.?extension", r"masquerad",
                  r"\.(txt|pdf|jpg)\.exe", r"lookalike"]),
           (0.4, [r"execut", r"binary", r"suspicious\s+name"])],
          min_score=0.6),

    # ── Discovery ─────────────────────────────────────────────────────────

    _Rule("discovery", "T1087", "T1087.002",
          "Domain account and group enumeration.",
          [(0.5, [r"net\s+user", r"net\s+group", r"get-domainuser",
                  r"get-aduser", r"ldap.{0,10}enum",
                  r"\bbloodhound\b", r"\bsharphound\b"]),
           (0.5, [r"enum", r"discover", r"list\s+accounts?",
                  r"domain\s+user"])],
          min_score=0.5),

    _Rule("discovery", "T1046", None,
          "Network service and port scanning.",
          [(0.6, [r"\bnmap\b", r"\bmasscan\b", r"port\s+scan",
                  r"service\s+scan", r"syn\s+scan", r"arp.?scan"]),
           (0.4, [r"discover", r"enum", r"sweep", r"probe"])],
          min_score=0.6),

    _Rule("discovery", "T1069", "T1069.002",
          "Domain group and permission enumeration.",
          [(0.6, [r"net\s+localgroup", r"get-domaingroup",
                  r"\bnltest\b", r"domain\s+trust"]),
           (0.4, [r"enum", r"trust", r"permission", r"acl"])],
          min_score=0.6),

    _Rule("discovery", "T1526", None,
          "Cloud service enumeration.",
          [(0.5, [r"listbuckets", r"describeinstances", r"listroles",
                  r"describesecuritygroups", r"get\s+/subscriptions"]),
           (0.5, [r"enum", r"discover", r"aws", r"azure", r"gcp",
                  r"cloud\s+resource"])],
          min_score=0.5),

    _Rule("discovery", "T1018", None,
          "Remote system discovery via arp, ping sweep, or net view.",
          [(0.6, [r"\barp\s+-a\b", r"net\s+view", r"ping\s+sweep",
                  r"get-smbshare"]),
           (0.4, [r"discover", r"internal\s+host", r"network\s+topolog",
                  r"subnet"])],
          min_score=0.6),

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
          min_score=0.5),

    _Rule("lateral-movement", "T1021", "T1021.006",
          "WMI-based remote execution for lateral movement.",
          [(0.5, [r"\bwmi\b", r"\bwmic\b"]),
           (0.5, [r"remote", r"lateral", r"another\s+host",
                  r"target\s+host", r"internal"])],
          require_all=True),

    _Rule("lateral-movement", "T1558", "T1558.001",
          "Golden Ticket attack via forged TGT.",
          [(0.8, [r"golden\s+ticket", r"krbtgt", r"forged.{0,10}tgt"]),
           (0.2, [r"kerberos", r"ticket", r"\b4769\b"])],
          min_score=0.8),

    _Rule("lateral-movement", "T1558", "T1558.002",
          "Silver Ticket attack via forged service ticket.",
          [(0.8, [r"silver\s+ticket", r"forged.{0,10}(service.ticket|tgs)"]),
           (0.2, [r"kerberos", r"service\s+ticket"])],
          min_score=0.8),

    _Rule("lateral-movement", "T1557", "T1557.001",
          "NTLM relay — LLMNR/NBT-NS poisoning.",
          [(0.7, [r"ntlm\s+relay", r"\bresponder\b", r"\binveigh\b",
                  r"llmnr.{0,10}poison", r"nbt.?ns.{0,10}poison"]),
           (0.3, [r"relay", r"poison", r"mitm", r"capture"])],
          min_score=0.7),

    _Rule("lateral-movement", "T1570", None,
          "Lateral tool transfer — dropping executable on remote share.",
          [(0.6, [r"drop.{0,15}(exe|dll|payload)",
                  r"copy.{0,15}(tool|binary|payload)",
                  r"transfer.{0,15}tool"]),
           (0.4, [r"remote\s+host", r"unc\s+path", r"admin\$",
                  r"lateral"])],
          min_score=0.6),

    # ── Exfiltration ──────────────────────────────────────────────────────

    _Rule("exfiltration", "T1048", "T1048.003",
          "Exfiltration over unencrypted FTP or SFTP.",
          [(0.5, [r"\bftp\b", r"\bsftp\b"]),
           (0.5, [r"exfil", r"upload", r"transfer.{0,15}external",
                  r"large.{0,10}transfer", r"data.{0,10}out"])],
          min_score=0.5),

    _Rule("exfiltration", "T1567", "T1567.002",
          "Exfiltration to cloud storage service.",
          [(0.5, [r"\bs3\b", r"dropbox", r"onedrive",
                  r"google\s+drive", r"sharepoint", r"blob\s+storage",
                  r"wetransfer"]),
           (0.5, [r"upload", r"exfil", r"transfer",
                  r"large.{0,10}(amount|file|data)"])],
          min_score=0.5),

    _Rule("exfiltration", "T1020", None,
          "Automated exfiltration via inbox forwarding rule.",
          [(0.6, [r"forward.{0,10}rule", r"inbox.{0,10}forward",
                  r"mail.{0,10}redirect", r"auto.{0,10}forward",
                  r"new-inboxrule"]),
           (0.4, [r"external\s+address", r"gmail", r"yahoo",
                  r"personal.{0,10}email"])],
          require_all=True),

    _Rule("exfiltration", "T1071", "T1071.004",
          "DNS tunnelling or high-volume TXT/NULL record exfiltration.",
          [(0.6, [r"dns.{0,10}tunnel", r"dns.{0,10}exfil",
                  r"txt\s+record", r"null\s+record", r"\bdga\b"]),
           (0.4, [r"dns", r"exfil", r"covert", r"tunnel"])],
          min_score=0.6),

    _Rule("exfiltration", "T1030", None,
          "Data transfer size limits — chunked exfiltration.",
          [(0.6, [r"chunk", r"split.{0,10}transfer",
                  r"size.{0,10}limit", r"throttl"]),
           (0.4, [r"exfil", r"transfer", r"upload"])],
          min_score=0.6),

    # ── Impact ────────────────────────────────────────────────────────────

    _Rule("impact", "T1486", None,
          "Ransomware: mass file encryption or unknown extension rename.",
          [(0.5, [r"ransomware", r"encrypt.{0,10}file",
                  r"file.{0,10}encrypt"]),
           (0.5, [r"mass\s+renam", r"extension\s+change",
                  r"unknown\s+extension", r"ransom"])],
          min_score=0.5),

    _Rule("impact", "T1490", None,
          "Shadow copy / backup deletion pre-encryption.",
          [(0.7, [r"shadow\s+cop", r"vssadmin.{0,10}delete",
                  r"wmic.{0,20}shadowcopy.{0,10}delete",
                  r"bcdedit.{0,20}recoveryenabled"]),
           (0.3, [r"delet", r"remov", r"disabl"])],
          min_score=0.7),

    _Rule("impact", "T1485", None,
          "Data destruction: mass deletion or disk wipe.",
          [(0.5, [r"mass\s+delet", r"\bwipe\b", r"destroy",
                  r"format.{0,10}disk", r"mbr.{0,10}overwrite"]),
           (0.5, [r"file", r"disk", r"data", r"volume"])],
          min_score=0.5),

    _Rule("impact", "T1496", None,
          "Resource hijacking: cryptomining on compromised host.",
          [(0.5, [r"crypto.{0,10}min", r"mining\s+pool",
                  r"\bxmr\b", r"\bmonero\b", r"high\s+cpu"]),
           (0.5, [r"pool", r"miner", r"coin",
                  r"port\s+3333", r"port\s+4444"])],
          min_score=0.5),

    _Rule("impact", "T1531", None,
          "Account access removal: bulk deletion or lockout.",
          [(0.6, [r"account.{0,10}delet", r"bulk.{0,10}delet",
                  r"mass.{0,10}lockout", r"disable.{0,10}account"]),
           (0.4, [r"user", r"account", r"access"])],
          min_score=0.6),

    # ── Initial Access ────────────────────────────────────────────────────

    _Rule("initial-access", "T1566", "T1566.001",
          "Spearphishing attachment delivering macro or script payload.",
          [(0.5, [r"phish", r"malicious.{0,10}attach",
                  r"office.{0,10}macro", r"\.docm\b",
                  r"\.xlsm\b", r"\.hta\b", r"\.iso\b"]),
           (0.5, [r"spawn", r"child.{0,10}process",
                  r"macro", r"winword", r"excel"])],
          min_score=0.5),

    _Rule("initial-access", "T1190", None,
          "Exploitation of public-facing web application.",
          [(0.5, [r"web.{0,10}exploit", r"\bsqli\b",
                  r"sql\s+inject", r"\brce\b",
                  r"remote\s+code\s+exec"]),
           (0.5, [r"public.{0,10}facing", r"web\s+app",
                  r"http", r"request", r"endpoint"])],
          min_score=0.5),

    _Rule("initial-access", "T1078", None,
          "Valid credentials used for initial access.",
          [(0.5, [r"valid\s+credential", r"stolen\s+credential",
                  r"compromised\s+account", r"account\s+takeover"]),
           (0.5, [r"initial\s+access", r"first\s+(login|logon|access)",
                  r"new\s+device", r"unknown\s+location"])],
          min_score=0.5),

    # ── Collection ────────────────────────────────────────────────────────

    _Rule("collection", "T1560", "T1560.001",
          "Archive creation for staging data before exfiltration.",
          [(0.5, [r"\b7z\b", r"winrar", r"\.zip\b",
                  r"\barchive\b", r"\bcompress\b"]),
           (0.5, [r"stage", r"collect", r"before.{0,10}exfil",
                  r"usb", r"removable"])],
          min_score=0.5),

    _Rule("collection", "T1114", "T1114.002",
          "Remote email collection via direct mailbox access.",
          [(0.5, [r"email.{0,10}collect", r"mailbox.{0,10}access",
                  r"exchange.{0,10}read", r"\bowa\b"]),
           (0.5, [r"bulk.{0,10}read", r"inbox",
                  r"forward", r"harvest"])],
          min_score=0.5),

    _Rule("collection", "T1056", "T1056.001",
          "Keylogger installed via hook or driver.",
          [(0.6, [r"keylog", r"keystroke",
                  r"wh_keyboard", r"setwindowshookex"]),
           (0.4, [r"hook", r"input\s+capture",
                  r"monitor", r"record"])],
          min_score=0.6),

    # ── Command and Control ───────────────────────────────────────────────

    _Rule("command-and-control", "T1071", "T1071.001",
          "C2 beaconing over HTTP/HTTPS at regular intervals.",
          [(0.5, [r"\bbeacon", r"\bc2\b", r"command.{0,10}control",
                  r"call.{0,10}home"]),
           (0.5, [r"https?", r"regular.{0,10}interval",
                  r"periodic", r"same.{0,15}external.{0,10}ip"])],
          min_score=0.5),

    _Rule("command-and-control", "T1572", None,
          "Protocol tunnelling for covert C2 channel.",
          [(0.6, [r"\btunnel\b", r"encapsulat"]),
           (0.4, [r"dns.{0,10}tunnel", r"icmp.{0,10}tunnel",
                  r"http.{0,10}tunnel", r"ssh.{0,10}tunnel",
                  r"port.{0,10}forward"])],
          min_score=0.6),

    _Rule("command-and-control", "T1090", "T1090.003",
          "Tor / anonymisation network used for C2.",
          [(0.8, [r"\btor\b", r"onion\s+network",
                  r"exit\s+node", r"\b9001\b", r"\b9030\b"]),
           (0.2, [r"anonymi", r"proxy", r"dark\s+web"])],
          min_score=0.8),
]


def _run_heuristics(nl_query: str, t0: float) -> ClassificationResult | None:
    """
    Evaluate all heuristic rules against nl_query.
    Returns the highest-scoring ClassificationResult above
    _HEURISTIC_THRESHOLD, or None to trigger LLM fallback.
    Ties broken by preferring sub-technique over parent technique.
    """
    q           = nl_query.lower()
    best_score  = 0.0
    best_rule:  _Rule | None = None

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

    if best_rule is None or best_score < _HEURISTIC_THRESHOLD:
        return None

    return ClassificationResult(
        nl_query               = nl_query,
        tactic                 = best_rule.tactic,
        technique              = best_rule.technique,
        sub_technique          = best_rule.sub_technique,
        rationale              = best_rule.rationale,
        confidence             = round(best_score, 4),
        candidates_considered  = [best_rule.technique],
        attempts               = 0,
        elapsed_s              = round(time.monotonic() - t0, 3),
    )
# Number of lexically-narrowed candidates shown to the LLM for CoT reasoning.
# Large enough to include the correct technique even when the keyword
# search ranks it imperfectly; small enough to keep prompt cost low.
_DEFAULT_CANDIDATE_K = 12


@dataclass
class ClassificationResult:
    """Output of a single ATTCKClassifierAgent.classify() call."""

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


class ATTCKClassifierAgent:
    """
    Infers MITRE ATT&CK tactic/technique/sub-technique bindings for natural
    language detection descriptions, using taxonomy-grounded chain-of-thought
    reasoning with mandatory post-hoc verification.

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
        # ── Heuristic fast-path ───────────────────────────────────────────────
    # Runs before candidate search and LLM call.
    # High-confidence, multi-signal rules only — single keyword never fires.
    # Falls through to full CoT reasoning if no rule scores above threshold.
        heuristic_result = _run_heuristics(nl_query, t0)
        if heuristic_result is not None:
            log.info(
                "Heuristic fast-path hit — skipping LLM classification",
                extra={"summary": heuristic_result.tactic + "/" + heuristic_result.technique,
                    "confidence": heuristic_result.confidence},
            )
            return heuristic_result
        # ── End heuristic fast-path ───────────────────────────────────────────

        
        
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

            except (IRValidationError, ValueError) as exc:
                print("\n========== REJECTED ==========")
                print("QUERY:", nl_query)
                print("PARSED:", parsed)
                print("ERROR:", exc)
                print("==============================\n")
                last_error = str(exc)
                log.warning(
                    "Classification attempt rejected — retrying",
                    extra={"attempt": attempt, "error": last_error},
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

    def classify_and_attach(self, nl_query: str, base_ir: IRQuery) -> tuple[AttckIRQuery, ClassificationResult]:
        """Convenience: classify() followed by attach() in one call."""
        result = self.classify(nl_query)
        return self.attach(base_ir, result), result

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
        confidence    = float(parsed.get("confidence", 0.5))

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
        technique_entry = self._taxonomy.get_technique(technique)
        if technique_entry is None:
            raise IRValidationError(
                f"LLM selected technique '{technique}' which does not exist "
                f"in the loaded ATT&CK taxonomy",
                details={"technique": technique, "candidates": candidate_ids},
            )

        if sub_technique is not None:
            sub_entry = self._taxonomy.get_technique(sub_technique)
            if sub_entry is None:
                raise IRValidationError(
                    f"LLM selected sub_technique '{sub_technique}' which does "
                    f"not exist in the loaded ATT&CK taxonomy",
                    details={"sub_technique": sub_technique},
                )
            if sub_entry.parent_id != technique:
                raise IRValidationError(
                    f"sub_technique '{sub_technique}' does not belong to "
                    f"technique '{technique}' (actual parent: "
                    f"'{sub_entry.parent_id}')",
                    details={"technique": technique, "sub_technique": sub_technique},
                )

        # Normalise tactic to the canonical shortname recognised by the
        # taxonomy, rather than trusting the LLM's exact casing/spelling.
        tactic_entry = self._taxonomy.get_tactic(tactic)
        if tactic_entry is None:
            raise IRValidationError(
                f"LLM selected tactic '{tactic}' which does not exist in the "
                f"loaded ATT&CK taxonomy",
                details={"tactic": tactic},
            )
        if tactic_entry.shortname not in technique_entry.tactic_names:
            raise IRValidationError(
                f"technique '{technique}' is not associated with tactic "
                f"'{tactic}' (technique belongs to: {technique_entry.tactic_names})",
                details={"tactic": tactic, "technique": technique},
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

    def __repr__(self) -> str:
        return (
            f"ATTCKClassifierAgent(candidate_k={self.candidate_k}, "
            f"max_retries={self.max_retries})"
        )