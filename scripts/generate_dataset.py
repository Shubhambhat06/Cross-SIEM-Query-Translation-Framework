#!/usr/bin/env python3
"""
scripts/generate_dataset.py
============================
Builds the SIEMBench evaluation dataset by translating a seed set of
natural-language SIEM queries into ground-truth translations across all five
platforms.

Pipeline
--------
    seed_queries.jsonl
         |  dedupe + schema-check
         v
    ParserAgent      -- NL -> IR
         v
    Translators       -- IR -> per-platform queries (rule-based, no LLM)
         v
    SyntaxValidator   -- per-platform pass/fail + diagnostics
         v
    integrity check + stratified, leakage-safe train/dev/test split
         v
    data/siembench.jsonl (+ data/siembench.{train,dev,test}.jsonl,
                            data/stats.json, data/DATASET_CARD.md,
                            data/manifest.json)

What changed vs. v1 (why this is "the best" version of this script)
---------------------------------------------------------------------
1. **No data leakage across splits.** Paraphrases generated from the same
   seed are kept together in one split via a `source_seed_id` group key.
   Splitting *after* augmentation without this is the single most common
   correctness bug in NL benchmark construction -- it silently inflates
   eval scores because the model has "seen" a near-duplicate of every
   test example during training/dev tuning.
2. **Deduplication** of seeds and of LLM paraphrases (normalized-text
   match), so near-identical rows don't dominate the dataset.
3. **Deterministic, resumable, atomic writes.** Output is built in a
   temp file and only swapped into place once generation completes
   successfully (`--resume` additionally lets you continue an
   interrupted/expanded run without regenerating already-validated rows).
4. **Concurrent generation** (`--workers N`) for when ParserAgent /
   LLMClient hit a network API -- off by default so single-threaded
   behavior is unchanged unless explicitly requested.
5. **Retry with backoff** around LLM augmentation calls, plus robust
   JSON extraction (LLMs love wrapping arrays in ```json fences).
6. **Rich validation diagnostics** per platform (not just pass/fail) are
   kept in `metadata.validation`, so a translator regression is
   debuggable straight from the dataset file instead of needing a rerun.
7. **A real dataset deliverable**, not just a JSONL blob: per-run
   `stats.json`, a human-readable `DATASET_CARD.md`, and a `manifest.json`
   with sha256 checksums of every output file for provenance/reproducibility.
8. **A quality gate.** If per-platform validity or seed-acceptance rate
   drops below a configurable threshold, the script exits 1 (partial)
   instead of silently shipping a degraded dataset.

Usage
-----
    # Generate from built-in seeds
    python scripts/generate_dataset.py

    # Custom seed file
    python scripts/generate_dataset.py --seeds data/my_seeds.jsonl

    # LLM-augmented (expand each seed with paraphrases), 4 workers
    python scripts/generate_dataset.py --augment --augment-factor 5 --workers 4

    # Resume an interrupted/expanded run without redoing finished rows
    python scripts/generate_dataset.py --augment --resume

    # Sanity-check seeds without calling the parser/translators
    python scripts/generate_dataset.py --dry-run

    # Limit for quick testing
    python scripts/generate_dataset.py --limit 20

Exit codes: 0 success | 1 partial / quality gate failed | 2 fatal
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.utils.logger import get_logger

log = get_logger("generate_dataset")

SCHEMA_VERSION = "2.0"
GENERATOR_VERSION = "2.0.0"
PLATFORMS = ("splunk", "qradar", "elastic", "sentinel", "wazuh")

DEFAULT_OUTPUT = _ROOT / "data" / "siembench.jsonl"
DEFAULT_SEEDS = _ROOT / "data" / "seed_queries.jsonl"

# ── Built-in seed queries (used when no --seeds file is provided) ─────────────
# Kept as plain {nl_query, category, complexity} dicts -- exactly the shape
# ParserAgent.parse() already consumes, so this expansion needs zero changes
# anywhere else in the pipeline. Categories broadened beyond the original
# six to widen ATT&CK coverage (cloud/IAM, web, malware/C2, email, insider).
# ── Built-in seed queries (used when no --seeds file is provided) ─────────────
#
# v2.0 — 250 research-grade seeds across 14 categories mapping to all 11
# ATT&CK tactics (Initial Access, Execution, Persistence, Privilege Escalation,
# Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection,
# Exfiltration, Impact) and seven modern environments (Windows, Linux, Active
# Directory, AWS, Azure, Containers/Kubernetes, Email, Web Applications).
#
# Target category counts:
#   authentication: 25  |  network: 25      |  process: 25
#   persistence: 20     |  privilege: 20    |  discovery: 20
#   credential_access: 20  |  lateral_movement: 20
#   exfiltration: 15    |  impact: 15       |  cloud: 20
#   container: 15       |  web: 15          |  email: 15
#
# Schema: {nl_query, category, complexity}  — unchanged from v1 so ParserAgent
# and all downstream pipeline components require zero modification.
#
# Every seed is written to be translatable into:
#   Splunk SPL  ·  Elastic EQL/KQL  ·  Microsoft Sentinel KQL
#   IBM QRadar AQL  ·  Wazuh rules (XML/syscheck/decoder)
#
# Detection-engineering principles applied per seed:
#   • Concrete thresholds (counts, time windows, byte sizes) so translators can
#     emit deterministic WHERE / stats clauses rather than free-text stubs.
#   • Named log sources / event IDs / field names where ATT&CK or vendor docs
#     ground them (Windows Security, Sysmon, CloudTrail, AuditD, CEF/LEEF).
#   • No paraphrases of existing seeds — every entry represents a distinct
#     detection scenario grounded in public threat intelligence or ATT&CK T-IDs.
_BUILTIN_SEEDS = [

    # ══════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION  (25)  — ATT&CK: Initial Access · Credential Access
    # Covers: Windows, Linux, Active Directory, AWS, Azure, MFA, Kerberos
    # ══════════════════════════════════════════════════════════════════════════

    # --- Brute-force / spray ---
    {"nl_query": "Detect failed SSH login attempts from a single IP exceeding 10 failures within 5 minutes (Linux brute-force)", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Alert on a password spray attack: one source IP failing authentication against more than 20 distinct accounts within 10 minutes", "category": "authentication", "complexity": "high"},
    {"nl_query": "Find Windows event ID 4625 (logon failure) with logon type 3 (network) exceeding 15 failures per source IP in 5 minutes", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Detect RDP brute-force: more than 20 failed Windows event 4625 logon type 10 events from one external IP in 10 minutes", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Alert on Kerberos pre-authentication failure (event ID 4771) for more than 10 accounts from the same source within 5 minutes (AS-REP or password spray)", "category": "authentication", "complexity": "high"},

    # --- Brute-force success / credential stuffing ---
    {"nl_query": "Alert on successful login (event ID 4624) within 60 seconds after five or more failed logons (event ID 4625) for the same account", "category": "authentication", "complexity": "high"},
    {"nl_query": "Detect credential-stuffing success: account login with a source IP that produced more than 50 failed attempts across different accounts in the preceding hour", "category": "authentication", "complexity": "high"},

    # --- Geo / impossible travel ---
    {"nl_query": "Detect impossible travel: same user account authenticating from two different countries less than 90 minutes apart", "category": "authentication", "complexity": "high"},
    {"nl_query": "Find logins from countries outside the organisation's baseline operating regions for any privileged account", "category": "authentication", "complexity": "high"},
    {"nl_query": "Alert when a user authenticates from a new ASN that has never been observed in the last 30 days", "category": "authentication", "complexity": "high"},

    # --- Privileged / off-hours ---
    {"nl_query": "Alert when a Domain Admin account (member of group SID S-1-5-21-*-512) logs in interactively between 20:00 and 06:00 local time", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Detect service accounts (accounts with a $ suffix in sAMAccountName) performing interactive logons (event ID 4624 logon type 2 or 10)", "category": "authentication", "complexity": "low"},

    # --- MFA / token abuse ---
    {"nl_query": "Alert when MFA is disabled for a user account (Azure AD audit log operation DisableStrongAuthentication) followed by a successful login within 15 minutes", "category": "authentication", "complexity": "high"},
    {"nl_query": "Detect an OAuth refresh token used from a different IP address or user-agent than the one that issued the original access token", "category": "authentication", "complexity": "high"},
    {"nl_query": "Alert on more than 5 MFA push-notification denials for the same account within 10 minutes (MFA fatigue attack)", "category": "authentication", "complexity": "medium"},

    # --- AWS / Azure cloud authentication ---
    {"nl_query": "Detect AWS console sign-in failures exceeding 5 attempts in 10 minutes for the same IAM user from the same source IP", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Alert on AWS root account console login at any time (root usage should be zero in a well-governed account)", "category": "authentication", "complexity": "low"},
    {"nl_query": "Detect Azure AD sign-in risk level 'high' events that result in a successful authentication (risky sign-in bypassed conditional access)", "category": "authentication", "complexity": "high"},
    {"nl_query": "Find Azure AD guest account logins originating from IP addresses flagged by Microsoft Threat Intelligence as malicious", "category": "authentication", "complexity": "medium"},

    # --- Kerberos / Active Directory protocol attacks ---
    {"nl_query": "Detect Kerberoasting: Windows event ID 4769 requesting a service ticket with encryption type 0x17 (RC4-HMAC) for a service account", "category": "authentication", "complexity": "high"},
    {"nl_query": "Alert on AS-REP roasting: Windows event ID 4768 for accounts with Kerberos pre-authentication disabled (UserAccountControl bit 0x400000)", "category": "authentication", "complexity": "high"},
    {"nl_query": "Detect a Pass-the-Ticket attack: event ID 4768 or 4769 with a ticket-granting ticket requested from a host that did not previously authenticate via normal logon event 4624", "category": "authentication", "complexity": "high"},

    # --- Account lockout / enumeration ---
    {"nl_query": "Alert when more than 10 accounts reach lockout status (event ID 4740) within a 5-minute window on the same domain controller", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Detect LDAP enumeration of user accounts: more than 200 LDAP queries from a single workstation to a domain controller within 1 minute", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Alert on a new device (first-seen device ID) logging in to a privileged account, where the account has not authenticated from that device in the last 60 days", "category": "authentication", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # NETWORK  (25)  — ATT&CK: Command and Control · Exfiltration · Discovery
    # Covers: DNS, SMB, beaconing, TOR, protocol anomalies, tunnelling
    # ══════════════════════════════════════════════════════════════════════════

    # --- Scanning / reconnaissance ---
    {"nl_query": "Detect horizontal port scan: single source IP contacting more than 50 unique destination IPs on the same port within 60 seconds", "category": "network", "complexity": "medium"},
    {"nl_query": "Detect vertical port scan: single source IP hitting more than 100 unique destination ports on one target host within 60 seconds", "category": "network", "complexity": "medium"},
    {"nl_query": "Alert on ICMP sweep: more than 254 ICMP echo requests from one source to a /24 subnet within 30 seconds", "category": "network", "complexity": "low"},
    {"nl_query": "Detect SYN scan activity: more than 1000 TCP SYN packets without completing the three-way handshake from one source in 60 seconds", "category": "network", "complexity": "medium"},

    # --- C2 / beaconing ---
    {"nl_query": "Detect beaconing behaviour: a host making outbound HTTP or HTTPS connections to the same external IP at intervals of less than 60 seconds variance over a 6-hour window", "category": "network", "complexity": "high"},
    {"nl_query": "Alert on long-duration low-bandwidth sessions: TCP session lasting more than 4 hours transferring less than 1 KB per minute (possible C2 keep-alive)", "category": "network", "complexity": "high"},
    {"nl_query": "Detect DNS-over-HTTPS (DoH) connections from internal hosts to non-approved resolvers such as 8.8.8.8:443 or 1.1.1.1:443", "category": "network", "complexity": "medium"},

    # --- DNS anomalies ---
    {"nl_query": "Alert on DNS queries to known malicious domains based on a threat-intelligence feed match in the last 24 hours", "category": "network", "complexity": "medium"},
    {"nl_query": "Detect DNS tunnelling: a single host making more than 500 DNS TXT or NULL record queries per minute", "category": "network", "complexity": "high"},
    {"nl_query": "Alert on newly observed domains (registered within 7 days) receiving DNS queries from internal hosts for the first time", "category": "network", "complexity": "medium"},
    {"nl_query": "Detect fast-flux DNS: same hostname resolving to more than 10 different IP addresses within 60 minutes", "category": "network", "complexity": "high"},
    {"nl_query": "Alert when an internal host queries a domain with a DGA-like pattern: entropy score above 3.5 and no prior resolution history", "category": "network", "complexity": "high"},

    # --- Tor / anonymiser ---
    {"nl_query": "Detect outbound connections to known Tor exit node IP addresses from any internal host", "category": "network", "complexity": "low"},
    {"nl_query": "Alert on connections to Tor guard relays on ports 9001 or 9030 from internal hosts", "category": "network", "complexity": "low"},

    # --- Data volume / exfil indicators ---
    {"nl_query": "Alert on outbound network sessions transferring more than 500 MB to a single external IP in under 10 minutes from a workstation", "category": "network", "complexity": "medium"},
    {"nl_query": "Detect SMTP traffic from an internal workstation directly to an external mail server (bypassing the corporate mail relay)", "category": "network", "complexity": "low"},
    {"nl_query": "Alert on FTP or SFTP sessions initiated from a server to an external IP not on the approved transfer list", "category": "network", "complexity": "low"},

    # --- Protocol / port anomalies ---
    {"nl_query": "Detect non-HTTP traffic on TCP port 80 or 443 (protocol mismatch indicating tunnelling or C2 over common ports)", "category": "network", "complexity": "high"},
    {"nl_query": "Alert on ICMP packets with payload sizes greater than 1000 bytes from internal hosts (possible ICMP tunnelling)", "category": "network", "complexity": "medium"},
    {"nl_query": "Detect internal hosts communicating over uncommon egress ports (not 80, 443, 22, 53, 25, 8080) to the internet", "category": "network", "complexity": "low"},
    {"nl_query": "Alert on SMB connections (TCP 445) from workstations to external internet IP addresses (lateral movement staging or data exfiltration via SMB)", "category": "network", "complexity": "medium"},

    # --- Lateral movement network indicators ---
    {"nl_query": "Detect SMB lateral movement: a single internal host connecting to more than 5 other internal hosts via TCP 445 within 10 minutes", "category": "network", "complexity": "high"},
    {"nl_query": "Detect internal RDP pivoting: workstation establishing RDP connections (TCP 3389) to more than 3 other internal hosts within 10 minutes", "category": "network", "complexity": "high"},

    # --- Threat-intel / blocklist ---
    {"nl_query": "Alert on any network connection to IP addresses present in the current threat-intelligence IOC feed with severity high or critical", "category": "network", "complexity": "low"},
    {"nl_query": "Detect SSL/TLS certificate subject CN mismatches against known malware C2 certificate fingerprints in threat-intel feeds", "category": "network", "complexity": "high"},

    # ══════════════════════════════════════════════════════════════════════════
    # PROCESS  (25)  — ATT&CK: Execution · Defense Evasion · Credential Access
    # Covers: Windows, Linux, LOLBins, macOS, script interpreters, injection
    # ══════════════════════════════════════════════════════════════════════════

    # --- PowerShell abuse ---
    {"nl_query": "Detect PowerShell launched with -EncodedCommand or -enc argument (Base64-encoded payload delivery)", "category": "process", "complexity": "medium"},
    {"nl_query": "Alert on PowerShell downloading content: process command line contains DownloadString, DownloadFile, WebClient, or Invoke-WebRequest", "category": "process", "complexity": "medium"},
    {"nl_query": "Detect PowerShell executing from a non-standard parent process (not explorer.exe, services.exe, or scheduled task host)", "category": "process", "complexity": "high"},
    {"nl_query": "Alert on PowerShell with execution policy Bypass and a script block loading a reflective assembly from memory (AMSI bypass pattern)", "category": "process", "complexity": "high"},
    {"nl_query": "Detect PowerShell Remoting sessions (WinRM, port 5985/5986) initiated from a workstation to more than 2 other internal hosts within 10 minutes", "category": "process", "complexity": "high"},

    # --- Office macro / phishing execution ---
    {"nl_query": "Alert on child processes spawned by WINWORD.EXE, EXCEL.EXE, or POWERPNT.EXE that are cmd.exe, powershell.exe, wscript.exe, or mshta.exe (T1566.001)", "category": "process", "complexity": "high"},
    {"nl_query": "Detect MSHTA.EXE executing a remote HTA file from an external URL (mshta http:// or mshta https:// command line)", "category": "process", "complexity": "high"},

    # --- LOLBin abuse ---
    {"nl_query": "Detect certutil.exe invoked with -decode or -urlcache arguments (payload download or Base64 decode via LOLBin)", "category": "process", "complexity": "medium"},
    {"nl_query": "Alert on regsvr32.exe loading a remote scriptlet (command line contains http:// or https:// - Squiblydoo technique)", "category": "process", "complexity": "high"},
    {"nl_query": "Detect rundll32.exe executing a DLL from the TEMP or APPDATA directory with a suspicious export name (shell32 or advpack ordinal abuse)", "category": "process", "complexity": "high"},
    {"nl_query": "Alert on wmic.exe process call create invoking a command string that contains powershell or cmd (WMI execution for lateral movement staging)", "category": "process", "complexity": "high"},
    {"nl_query": "Detect msiexec.exe running with /q /i flags from a network UNC path or external URL", "category": "process", "complexity": "medium"},
    {"nl_query": "Alert on bitsadmin.exe or bitsadmin transfer command downloading a file to a user-writable directory", "category": "process", "complexity": "medium"},

    # --- Credential dumping process indicators ---
    {"nl_query": "Detect LSASS memory access: non-system processes (not werfault.exe or windows error reporting) opening a handle to lsass.exe with PROCESS_VM_READ permissions (Sysmon event ID 10)", "category": "process", "complexity": "high"},
    {"nl_query": "Alert on procdump.exe or task manager being used to create a memory dump of lsass.exe", "category": "process", "complexity": "high"},

    # --- Process injection ---
    {"nl_query": "Detect process injection: a process calling VirtualAllocEx followed by WriteProcessMemory and CreateRemoteThread into a different process (Sysmon events 8 and 10)", "category": "process", "complexity": "high"},
    {"nl_query": "Alert on DLL injection via SetWindowsHookEx targeting a process in a different session from the injecting process", "category": "process", "complexity": "high"},

    # --- Unsigned / suspicious binary execution ---
    {"nl_query": "Detect execution of unsigned PE files from user-writable directories (TEMP, AppData, Downloads) on Windows endpoints", "category": "process", "complexity": "medium"},
    {"nl_query": "Alert on executable files with a .txt, .pdf, or .jpg extension being launched as a process (double-extension masquerading)", "category": "process", "complexity": "medium"},
    {"nl_query": "Detect scripts (VBScript, JScript, Python) executed from a browser download directory within 5 minutes of the file being created", "category": "process", "complexity": "high"},

    # --- Linux process anomalies ---
    {"nl_query": "Detect reverse shell spawned via bash: process executing bash -i with output redirection to /dev/tcp or nc -e /bin/bash pattern", "category": "process", "complexity": "high"},
    {"nl_query": "Alert on crontab modifications made by a non-root user followed by execution of a new process not previously seen on that host", "category": "process", "complexity": "medium"},
    {"nl_query": "Detect LD_PRELOAD hijacking: a process launched with LD_PRELOAD environment variable pointing to a non-system library path", "category": "process", "complexity": "high"},

    # --- Suspicious interpreter chains ---
    {"nl_query": "Alert on cmd.exe spawned as a child of svchost.exe with a command line not matching known Windows service invocation patterns", "category": "process", "complexity": "high"},
    {"nl_query": "Detect python.exe or python3 executing a base64-encoded payload inline via the -c flag", "category": "process", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # PERSISTENCE  (20)  — ATT&CK: Persistence
    # Covers: registry, scheduled tasks, services, boot, startup, WMI subs
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect modifications to Windows registry Run or RunOnce keys (HKLM or HKCU) by a non-system process (T1547.001)", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Alert on creation of a new Windows scheduled task with an action pointing to a file in a user-writable directory (Sysmon event 1 / Security event 4698)", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Detect a new Windows service being installed (event ID 7045) with a binary path in TEMP, AppData, or a UNC share", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Alert on modifications to the Windows BITS job queue that add a new transfer job pointing to an external URL (T1197)", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Detect WMI event subscription persistence: creation of a __EventFilter, __EventConsumer, or __FilterToConsumerBinding object in the WMI repository (T1546.003)", "category": "persistence", "complexity": "high"},
    {"nl_query": "Alert on modifications to the Startup folder for any user profile by a non-administrative process", "category": "persistence", "complexity": "low"},
    {"nl_query": "Detect DLL search-order hijacking: a non-system DLL placed in the same directory as a legitimate signed executable that does not have an absolute DLL load path", "category": "persistence", "complexity": "high"},
    {"nl_query": "Alert on Image File Execution Options (IFEO) registry key modification to add a Debugger value pointing to a non-debugger binary (T1546.012)", "category": "persistence", "complexity": "high"},
    {"nl_query": "Detect a new SSH authorized_keys entry written to a user's home directory on a Linux server outside of a scheduled provisioning window", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Alert on cron job files created or modified under /etc/cron.d/, /etc/cron.daily/, or /var/spool/cron/ by a non-root process", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Detect modifications to /etc/passwd or /etc/shadow files by any process other than useradd, usermod, or passwd", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Alert on a new systemd service unit file created in /etc/systemd/system/ or /usr/lib/systemd/system/ by a non-package-manager process", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Detect kernel module loaded via insmod or modprobe that is not signed or not present in the approved module list (Linux rootkit staging)", "category": "persistence", "complexity": "high"},
    {"nl_query": "Alert on a browser extension installed outside of enterprise push policy (new extension directory created in Chrome or Firefox profile under AppData)", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Detect PowerShell profile modification: writes to the PowerShell profile path by a non-administrative user", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Alert on modifications to the LSA Security Packages or Authentication Packages registry values (T1547.002 custom SSP/AP for credential harvesting)", "category": "persistence", "complexity": "high"},
    {"nl_query": "Detect new print monitor DLL registered in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors (T1547.010)", "category": "persistence", "complexity": "high"},
    {"nl_query": "Alert on a COM object hijack: HKCU\\Software\\Classes\\CLSID entry created that shadows a HKLM CLSID used by a privileged process (T1546.015)", "category": "persistence", "complexity": "high"},
    {"nl_query": "Detect Active Directory GPO modification that adds a new logon script or immediate task to a GPO linked to a high-value OU", "category": "persistence", "complexity": "high"},
    {"nl_query": "Alert on new accounts created in Active Directory outside of the approved identity-provisioning service account (event ID 4720 not originating from the provisioning server)", "category": "persistence", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION  (20)  — ATT&CK: Privilege Escalation
    # Covers: Windows UAC bypass, token impersonation, sudo abuse, AD delegation
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Alert when a user account is added to the Domain Admins group (event ID 4728, group SID ending -512)", "category": "privilege", "complexity": "low"},
    {"nl_query": "Detect a standard user account being added to the local Administrators group on a workstation (event ID 4732)", "category": "privilege", "complexity": "low"},
    {"nl_query": "Alert on token impersonation: a process calling ImpersonateLoggedOnUser or DuplicateTokenEx for a token belonging to a higher-privileged account (Sysmon event 8 access rights 0x0200)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect UAC bypass via fodhelper.exe: process creating HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command registry key followed by fodhelper.exe launching a child process", "category": "privilege", "complexity": "high"},
    {"nl_query": "Alert on named-pipe impersonation: a service process creating a named pipe that is subsequently connected to by a high-privileged client (T1134.001)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect PrintSpoofer or similar SeImpersonatePrivilege abuse: spoolsv.exe spawning an unexpected child process not in baseline (T1134)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Alert on Kerberos delegation abuse: account with unconstrained delegation (TrustedForDelegation = True) receiving a TGT for a Domain Admin (T1558)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect sudo privilege escalation on Linux: audit log showing a non-standard user running sudo to execute /bin/bash or /bin/sh (sudoers abuse)", "category": "privilege", "complexity": "medium"},
    {"nl_query": "Alert on SUID binary abuse: execution of a file with the SUID bit set from a non-standard path (not /usr/bin or /bin) by a non-root user", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect container escape via privileged pod: a process inside a container reading /proc/1/cgroup where the cgroup is not a container namespace (host PID namespace escape)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Alert on AWS IAM privilege escalation: AttachUserPolicy or AttachRolePolicy call adding AdministratorAccess or PowerUserAccess managed policy to an existing principal", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect Azure role assignment: new Owner or User Access Administrator role granted at subscription scope outside of Privileged Identity Management workflow (Azure Activity Log)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Alert on SID history injection: an account's SIDHistory attribute modified to include a Domain Admins SID (event ID 4765 or 4766)", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect DCSync attack: a non-domain-controller account performing DS-Replication-Get-Changes-All (event ID 4662 with access mask 0x100) to replicate AD secrets", "category": "privilege", "complexity": "high"},
    {"nl_query": "Alert on Windows access token manipulation: a process calling AdjustTokenPrivileges to enable SeDebugPrivilege outside of known administrative tools", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect pass-the-hash: event ID 4624 logon type 3 with NTLM authentication and NTLMv1 or NTLMv2 from a source that has not previously used NTLM for network logon", "category": "privilege", "complexity": "high"},
    {"nl_query": "Alert on new AdminSDHolder modifications: ACE added to the AdminSDHolder container in Active Directory granting a non-privileged account WriteDACL or GenericAll", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect group policy preference files containing cpassword (MS14-025 lingering GPP password): GPO XML files with a cpassword attribute in SYSVOL", "category": "privilege", "complexity": "medium"},
    {"nl_query": "Alert on a user adding themselves to a privileged group via LDAP modify operation on their own account object without going through approved IAM workflow", "category": "privilege", "complexity": "high"},
    {"nl_query": "Detect exploit of vulnerable kernel module: unexpected privilege change (UID transition to 0) recorded in Linux auditd after execution of an unrecognised binary", "category": "privilege", "complexity": "high"},

    # ══════════════════════════════════════════════════════════════════════════
    # DISCOVERY  (20)  — ATT&CK: Discovery
    # Covers: AD enumeration, network discovery, cloud resource enumeration
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect Active Directory enumeration via net group, net user, or net localgroup commands executed by a non-administrative user on a domain-joined host", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Alert on BloodHound or SharpHound collection: LDAP queries requesting all user, computer, and group objects with SPN attributes from a single workstation in under 60 seconds", "category": "discovery", "complexity": "high"},
    {"nl_query": "Detect nltest.exe /dclist or nltest.exe /domain_trusts executed by a non-privileged user (domain trust enumeration)", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Alert on PowerView or similar recon: PowerShell commands containing Get-DomainUser, Get-DomainComputer, or Get-DomainTrust within a single session", "category": "discovery", "complexity": "high"},
    {"nl_query": "Detect host and service discovery on Linux: rapid execution of nmap, masscan, or arp-scan by a non-root user account", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Alert on whoami, hostname, ipconfig, or systeminfo commands executed in sequence within 60 seconds by the same process tree (post-exploitation system survey)", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Detect AWS resource enumeration: IAM principal calling DescribeInstances, ListBuckets, ListRoles, and DescribeSecurityGroups in sequence within 5 minutes (CloudTrail)", "category": "discovery", "complexity": "high"},
    {"nl_query": "Alert on AWS GetCallerIdentity called from an access key that has never previously used the AWS CLI (possible stolen key first use)", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Detect Azure subscription enumeration: service principal calling GET on subscriptions, resourceGroups, and resources in sequence within 2 minutes (Azure Activity Log)", "category": "discovery", "complexity": "high"},
    {"nl_query": "Alert on Kubernetes API server audit log showing LIST or GET on secrets, configmaps, or serviceaccounts by a user outside the kube-system namespace", "category": "discovery", "complexity": "high"},
    {"nl_query": "Detect registry enumeration: reg.exe query or regedit.exe accessing HKLM\\SAM or HKLM\\SECURITY hives by a non-SYSTEM process", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Alert on file system discovery: process enumerating more than 500 files under C:\\Users or /home within 30 seconds (automated credential or document harvesting)", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Detect network share enumeration: net view or Get-SmbShare executed from a workstation connecting to more than 5 different hosts within 5 minutes", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Alert on security tool discovery: process executing tasklist, sc query, or Get-Service filtering for known AV or EDR product names (T1518.001)", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Detect cloud storage enumeration: S3 ListObjects or ListObjectsV2 API calls across more than 10 different buckets within 5 minutes from a single IAM identity", "category": "discovery", "complexity": "high"},
    {"nl_query": "Alert on a workstation running arp -a, route print, and netstat -an in sequence within 120 seconds (network topology discovery)", "category": "discovery", "complexity": "low"},
    {"nl_query": "Detect Local Security Authority secrets query: reg save HKLM\\SECURITY or reg save HKLM\\SAM commands executed by a non-SYSTEM process", "category": "discovery", "complexity": "high"},
    {"nl_query": "Alert on DNS zone transfer (AXFR) request from a non-authoritative server or non-approved monitoring host to an internal DNS server", "category": "discovery", "complexity": "medium"},
    {"nl_query": "Detect Active Directory Certificate Services enumeration: certutil -CA or certutil -config executed by a non-administrator, or LDAP queries for pKIEnrollmentService objects", "category": "discovery", "complexity": "high"},
    {"nl_query": "Alert on process executing Get-GPO, Get-GPOReport, or gpresult /R targeting another user or computer (GPO enumeration for lateral movement planning)", "category": "discovery", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS  (20)  — ATT&CK: Credential Access
    # Covers: dumping, keylogging, password files, cloud secrets
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect Mimikatz execution: process command line containing sekurlsa::logonpasswords, lsadump::sam, or lsadump::dcsync", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on LSASS dump via comsvcs.dll: rundll32.exe executing MiniDump with lsass as the target process (T1003.001)", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect SAM database access: attempts to read HKLM\\SAM\\SAM\\Domains\\Account\\Users by a non-SYSTEM, non-approved backup process", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on ntds.dit file access outside of backup windows: file open handle on ntds.dit or a VSS shadow copy of NTDS on a domain controller", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect DPAPI secret decryption: CryptUnprotectData called with the CRYPTPROTECT_LOCAL_MACHINE flag by a process in a non-administrative session (browser credential theft)", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on keylogger indicators: process installing a SetWindowsHookEx WH_KEYBOARD_LL hook pointing to a DLL not present in baseline (T1056.001)", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect credential file access: reads to Chrome, Firefox, or Edge login data files (Login Data, logins.json, key4.db) by a process other than the browser itself", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on AWS Secrets Manager secret values retrieved by an IAM principal that has never previously accessed secrets, especially GetSecretValue on production secrets", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect Azure Key Vault secret retrieval: service principal calling SecretGet on more than 10 distinct secrets within 5 minutes outside of normal deployment windows", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on HashiCorp Vault secrets engine bulk read: more than 50 kv/data reads by a single token within 2 minutes (possible automated credential harvesting)", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect password manager process memory scraping: uncommon process opening a handle to 1Password, Bitwarden, or KeePass processes with VM_READ access", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on Kerberoasting: more than 10 TGS-REQ requests for service accounts with RC4 encryption type from the same host within 5 minutes (event ID 4769)", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect /etc/shadow file read on Linux by a process other than passwd, chage, or login (shadow file credential access)", "category": "credential_access", "complexity": "medium"},
    {"nl_query": "Alert on cloud metadata service access from inside an EC2 instance or Azure VM by a process that is not the hypervisor agent or cloud-init (SSRF to IMDS T1552.005)", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Detect LaZagne or credential scanning tool execution: process name or command line matching laZagne, credentialfileview, or netpass", "category": "credential_access", "complexity": "medium"},
    {"nl_query": "Alert on SSH private key file reads from the user ssh directory or /etc/ssh by a process other than sshd or ssh", "category": "credential_access", "complexity": "medium"},
    {"nl_query": "Detect GCP service account key file exfiltration: serviceaccounts.keys.list or serviceaccounts.keys.get called from outside approved CI/CD service accounts", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on Windows Credential Manager enumeration: vaultcmd /list or cmdkey /list executed by a standard user, or direct access to the Vault directory", "category": "credential_access", "complexity": "medium"},
    {"nl_query": "Detect pass-the-hash preparation: process reading the NTDS.dit file via volume shadow copy followed by ntdsutil or esentutl snapshot copy", "category": "credential_access", "complexity": "high"},
    {"nl_query": "Alert on plaintext credentials in environment variables: process with environment variables matching SECRET, PASSWORD, TOKEN, or API_KEY written to a log file or child process", "category": "credential_access", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT  (20)  — ATT&CK: Lateral Movement
    # Covers: PsExec, RDP, WMI, SSH tunnelling, AD abuse, token relay
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect PsExec-style lateral movement: ADMIN$ share mount followed by creation of a PSEXESVC service (event ID 7045) on the target host within 60 seconds", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on WMI remote process creation: WMI consumer spawning cmd.exe or powershell.exe with an encoded payload on a target host (T1021.006)", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect RDP session initiated by a user from a workstation to a server the user has never accessed in the last 30 days (anomalous lateral RDP)", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on remote service creation via SC: sc.exe targeting a remote host executed from a workstation", "category": "lateral_movement", "complexity": "medium"},
    {"nl_query": "Detect scheduled task created on a remote host via schtasks /create /s targeting an internal host from an anomalous source workstation", "category": "lateral_movement", "complexity": "medium"},
    {"nl_query": "Alert on Impacket or similar Python framework usage: SMB session with no prior net use establishing a share and dropping an executable within 5 minutes (SMBEXEC pattern)", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect SSH tunnelling or port forwarding: ssh process launched with -L, -R, or -D flags forwarding a local or dynamic port to an internal target from a bastion host", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on RPC-based lateral movement: process opening MS-SCMR Service Control Manager Remote Protocol pipe on more than 3 internal hosts within 10 minutes", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect Golden Ticket attack: event ID 4769 for a service ticket where the ticket encryption type is RC4 and the account is a krbtgt-derived SPN", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on Silver Ticket attack: Kerberos service ticket presented for a service on a host where no corresponding TGT exchange was observed in the preceding 10 hours (T1558.002)", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect NTLM relay attack setup: LLMNR or NBT-NS poisoning indicators with UDP port 5355 or 137 traffic from an internal workstation that is not a DNS server", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on credential relay via PrinterBug SpoolSample: RPC call to MS-RPRN spoolss pipe triggering authentication from a domain controller to an attacker host", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect overpass-the-hash: NTLM authentication on network logon (event 4624 type 3) immediately followed by a Kerberos TGT request from the same source (ticket minting from NTLM hash)", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on excessive IPC$ connections: single source host mounting IPC$ on more than 10 different internal targets within 5 minutes", "category": "lateral_movement", "complexity": "medium"},
    {"nl_query": "Detect DCOM lateral movement: mmc.exe or ShellBrowserWindow COM object invocation from a remote IP in event ID 4624 logon type 3 (T1021.003)", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on Azure VM RunCommand or Invoke-AzVMRunCommand called against a production VM by a principal outside the approved automation account", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect AWS Systems Manager Run Document execution targeting EC2 instances by an IAM principal that has not previously used SSM Run Command", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on container-to-container lateral movement: a pod communicating with another pod in a different namespace on a port not declared in NetworkPolicy", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Detect Active Directory Certificate Services ESC1 abuse: certificate enrollment request where the SAN includes a Domain Admin UPN submitted by a non-administrative account", "category": "lateral_movement", "complexity": "high"},
    {"nl_query": "Alert on Mimikatz sekurlsa::pth generating a new logon session (event ID 4624 logon type 9 NewCredentials) without a corresponding interactive logon", "category": "lateral_movement", "complexity": "high"},

    # ══════════════════════════════════════════════════════════════════════════
    # EXFILTRATION  (15)  — ATT&CK: Exfiltration
    # Covers: email, cloud upload, FTP, DNS, USB, staging
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Alert on a user sending more than 50 external emails within one hour when their 30-day baseline is fewer than 10 per hour", "category": "exfiltration", "complexity": "medium"},
    {"nl_query": "Detect email attachment exfiltration: a user forwarding emails with attachments larger than 5 MB to a personal Gmail, Yahoo, or Hotmail address", "category": "exfiltration", "complexity": "medium"},
    {"nl_query": "Alert on an inbox forwarding rule created to an external address via Exchange admin audit log or Microsoft 365 Unified Audit Log", "category": "exfiltration", "complexity": "medium"},
    {"nl_query": "Detect large uploads to personal cloud storage: DNS resolution of dropbox.com, drive.google.com, or wetransfer.com followed by more than 50 MB of HTTPS upload traffic", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Alert on FTP or SFTP session from a workstation to an external IP transferring more than 20 MB within one session", "category": "exfiltration", "complexity": "low"},
    {"nl_query": "Detect data staged in an unusual location: more than 500 files copied to a user's TEMP directory within 10 minutes before a large archive being created", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Alert on DNS exfiltration: more than 200 DNS queries per minute with subdomains longer than 40 characters from a single internal host to an external resolver", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Detect exfiltration via ICMP: outbound ICMP packets with a payload larger than 1400 bytes at a rate exceeding 10 per second from a workstation", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Alert on S3 data exfiltration: GetObject calls on a bucket not accessed in the last 90 days followed by more than 1 GB of data transferred out within an hour", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Detect Azure Blob Storage bulk download: more than 100 GetBlob operations on a container within 10 minutes from an IP outside corporate IP ranges", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Alert on archive creation immediately preceding USB insertion: 7z.exe, winrar.exe, or zip spawned within 5 minutes of a new removable storage device appearing in Windows event 6416", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Detect sensitive file exfiltration via Teams or Slack: DLP alert for files tagged as Confidential shared externally via collaboration platform webhook", "category": "exfiltration", "complexity": "medium"},
    {"nl_query": "Alert on print spooler job sent for a document tagged as sensitive exceeding 50 pages outside business hours", "category": "exfiltration", "complexity": "medium"},
    {"nl_query": "Detect a user accessing and downloading more than 1000 files from SharePoint Online within a single 30-minute session (Microsoft 365 audit log FileDownloaded event)", "category": "exfiltration", "complexity": "high"},
    {"nl_query": "Alert on data transferred to a SaaS application not on the corporate approved application list exceeding 10 MB (Shadow IT upload)", "category": "exfiltration", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # IMPACT  (15)  — ATT&CK: Impact
    # Covers: ransomware, wiper, DoS, resource hijacking, data destruction
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect ransomware activity: more than 100 file rename operations to an unknown extension by the same process within 60 seconds", "category": "impact", "complexity": "high"},
    {"nl_query": "Alert on mass file deletion: more than 200 files deleted by a single process within 30 seconds, not matching known backup or cleanup software", "category": "impact", "complexity": "high"},
    {"nl_query": "Detect shadow copy deletion: vssadmin delete shadows, wmic shadowcopy delete, or bcdedit /set recoveryenabled no executed by any process (ransomware pre-encryption step)", "category": "impact", "complexity": "medium"},
    {"nl_query": "Alert on MBR overwrite attempt: process with low-level disk write access to PhysicalDrive0 with GENERIC_WRITE outside of known disk management tools", "category": "impact", "complexity": "high"},
    {"nl_query": "Detect resource hijacking: sudden CPU spike above 90% on an EC2 or Azure VM combined with new outbound connections to mining pool domains on ports 3333, 4444, or 14444", "category": "impact", "complexity": "high"},
    {"nl_query": "Alert on Windows event log clearing: event ID 1102 (Security log cleared) or 104 (System log cleared) on any host, especially a domain controller", "category": "impact", "complexity": "low"},
    {"nl_query": "Detect denial of service staging: a single internal host sending more than 100000 UDP packets per minute to a single external target (UDP flood preparation)", "category": "impact", "complexity": "medium"},
    {"nl_query": "Alert on logical disk format command: format.exe executed on a volume containing live data outside of a known provisioning or decommission job", "category": "impact", "complexity": "high"},
    {"nl_query": "Detect bcdedit changes disabling safe-mode recovery or changing boot policy to ignore integrity checks outside of approved patch windows", "category": "impact", "complexity": "medium"},
    {"nl_query": "Alert on an EC2 instance termination API call (TerminateInstances) targeting more than 5 production instances within 5 minutes by a single IAM principal", "category": "impact", "complexity": "high"},
    {"nl_query": "Detect database wiper activity: DROP TABLE or TRUNCATE statements issued to more than 5 tables within 60 seconds by an application account outside a deployment window", "category": "impact", "complexity": "high"},
    {"nl_query": "Alert on Kubernetes namespace deletion or large-scale pod termination (more than 10 pods deleted) by a service account outside the cluster lifecycle management workflow", "category": "impact", "complexity": "high"},
    {"nl_query": "Detect email bombing: a mailbox receiving more than 500 emails within 10 minutes (email flood used to bury notification emails during account takeover)", "category": "impact", "complexity": "medium"},
    {"nl_query": "Alert on Azure resource group deletion by a principal whose previous activity in the same session shows reconnaissance and lateral movement", "category": "impact", "complexity": "high"},
    {"nl_query": "Detect firmware update command issued to a network device from an IP not belonging to the network management system (SNMP set or out-of-band management)", "category": "impact", "complexity": "high"},

    # ══════════════════════════════════════════════════════════════════════════
    # CLOUD  (20)  — ATT&CK: Initial Access · Persistence · Privilege Escalation
    # Covers: AWS, Azure, GCP — IAM, storage, logging, compute, networking
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect AWS IAM access key created for a root account (CloudTrail CreateAccessKey where userIdentity.type is Root)", "category": "cloud", "complexity": "low"},
    {"nl_query": "Alert on an S3 bucket ACL change that grants public READ or READ_ACP permission to AllUsers or AuthenticatedUsers (CloudTrail PutBucketAcl)", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect CloudTrail logging disabled: StopLogging, DeleteTrail, or UpdateTrail with IncludeGlobalServiceEvents set to false by any principal", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on IAM policy attached to an IAM user directly (not via group or role) granting actions containing wildcard on resource wildcard (overly permissive inline policy)", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect a new EC2 security group rule opening port 22 or 3389 to 0.0.0.0/0 (unrestricted SSH or RDP inbound)", "category": "cloud", "complexity": "low"},
    {"nl_query": "Alert on AWS Lambda function code updated to include a new IAM role assumption or exfiltration-capable SDK call outside of approved CI/CD pipeline events", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect AWS GuardDuty finding severity HIGH or CRITICAL that has not been remediated or acknowledged within 4 hours of creation", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on an IAM role trust policy modification that adds a new external AWS account ID as a trusted principal (cross-account trust abuse)", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect Azure diagnostic settings deleted or modified to exclude a category of resource log from the Log Analytics workspace", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on Azure Entra ID application granted application permissions to Microsoft Graph mail.readwrite or files.readwrite.all outside of approved service principal lifecycle", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect GCP service account key created with a validity longer than 90 days outside of the approved rotation process (IAM CreateServiceAccountKey)", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on AWS Systems Manager Parameter Store GetParameters call retrieving SecureString parameters by an IAM entity not in the approved decryption list", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect mass deletion of AWS CloudWatch alarms: DeleteAlarms API call removing more than 5 alarms within 5 minutes (defense evasion)", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on a new VPC peering connection accepted between the production VPC and an unrecognised AWS account VPC", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect AWS ECS task definition update injecting a new container image from an unapproved registry (not the corporate ECR private registry)", "category": "cloud", "complexity": "high"},
    {"nl_query": "Alert on GCP organisation policy constraint updated to allow a previously restricted service or resource type without change-management approval", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect Azure Automation runbook created or modified by a user who does not hold the Automation Contributor role (possible role creep or account compromise)", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on AWS IAM AssumeRole cross-account call from an account ID not in the approved-vendor list, especially for roles with Administrator-level permissions", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect Azure Policy assignment removed for a compliance policy such as a CIS benchmark or NIST 800-53 initiative in a production subscription", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on a new public IP address or NAT Gateway created in a production VPC or VNet without a corresponding approved change-management reference tag", "category": "cloud", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # CONTAINER / KUBERNETES  (15)  — ATT&CK: Execution · Privilege Escalation
    # Covers: Kubernetes API, Docker daemon, runtime escapes, supply chain
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Alert on a container running in privileged mode (securityContext.privileged: true) in a production Kubernetes namespace", "category": "container", "complexity": "medium"},
    {"nl_query": "Detect kubectl exec or kubectl cp into a production pod from a source IP not in the approved operations CIDR range (Kubernetes API audit log)", "category": "container", "complexity": "high"},
    {"nl_query": "Alert on a new ClusterRoleBinding granting cluster-admin to a ServiceAccount or user outside the kube-system or approved IAM namespace", "category": "container", "complexity": "high"},
    {"nl_query": "Detect container image pulled from an unapproved registry (not the corporate ECR or internal Harbor) in any production or staging namespace", "category": "container", "complexity": "medium"},
    {"nl_query": "Alert on a pod spec mounting the Docker socket (/var/run/docker.sock) as a volume, enabling container escape to the host", "category": "container", "complexity": "high"},
    {"nl_query": "Detect a process inside a container reading /proc/1/environ or /proc/1/cmdline on the host (host PID namespace escape indicator)", "category": "container", "complexity": "high"},
    {"nl_query": "Alert on Kubernetes secret accessed directly via API by a ServiceAccount that has not previously read secrets in that namespace (K8s audit log get or list on secrets)", "category": "container", "complexity": "high"},
    {"nl_query": "Detect a new pod created in the kube-system namespace by a non-administrative service account or human user (privileged namespace tampering)", "category": "container", "complexity": "high"},
    {"nl_query": "Alert on a Kubernetes CronJob or Job spawning a process that makes outbound network connections to a domain not in the egress NetworkPolicy allowlist", "category": "container", "complexity": "high"},
    {"nl_query": "Detect Docker daemon API exposed on TCP: any remote call to containers list or containers create from an IP outside the management network", "category": "container", "complexity": "high"},
    {"nl_query": "Alert on a container process writing to /etc/cron.d/, /etc/cron.daily/, or /etc/profile.d/ (persistence mechanisms not valid inside a stateless container)", "category": "container", "complexity": "high"},
    {"nl_query": "Detect high-privilege Linux capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN) granted to a container not on the approved security-policy exception list", "category": "container", "complexity": "medium"},
    {"nl_query": "Alert on a Kubernetes admission controller policy override annotation added to a workload manifest to bypass PodSecurityAdmission or OPA Gatekeeper", "category": "container", "complexity": "high"},
    {"nl_query": "Detect lateral movement between pods: a process inside a pod making direct TCP connections to another pod's internal ClusterIP on a port not declared in any Service definition", "category": "container", "complexity": "high"},
    {"nl_query": "Alert on a runtime security tool such as Falco or Sysdig generating a CRITICAL severity event for any container in the production cluster that has not been acknowledged within 30 minutes", "category": "container", "complexity": "medium"},

    # ══════════════════════════════════════════════════════════════════════════
    # WEB  (15)  — ATT&CK: Initial Access · Collection · Exploitation
    # Covers: injection, auth bypass, API abuse, WAF evasion, SSRF, XXE
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Detect SQL injection attempts: HTTP requests containing UNION SELECT, OR 1=1, or SQL comment sequences in query parameters or POST body", "category": "web", "complexity": "medium"},
    {"nl_query": "Alert on cross-site scripting (XSS) probe: HTTP request containing script tags, javascript:, or onerror= in any parameter, header, or body field", "category": "web", "complexity": "medium"},
    {"nl_query": "Detect path traversal: HTTP request URL containing ../ or URL-encoded equivalents attempting to access files outside the web root", "category": "web", "complexity": "medium"},
    {"nl_query": "Alert on Server-Side Request Forgery (SSRF) probe: web application making an outbound HTTP request to the cloud metadata service at 169.254.169.254 triggered by user-supplied URL input", "category": "web", "complexity": "high"},
    {"nl_query": "Detect XXE injection: HTTP POST body containing a DOCTYPE declaration with an ENTITY reference to a file:// or http:// URI in XML input to an API endpoint", "category": "web", "complexity": "high"},
    {"nl_query": "Alert on authentication endpoint brute-force: more than 100 POST requests to /login, /signin, or /auth within 5 minutes from a single IP with different credential pairs", "category": "web", "complexity": "medium"},
    {"nl_query": "Detect web application credential stuffing: login endpoint returning HTTP 200 after receiving credentials matching a known breach data set", "category": "web", "complexity": "high"},
    {"nl_query": "Alert on API key abuse: same API key generating more than 5000 requests per hour, exceeding the normal per-key rate limit by 10x", "category": "web", "complexity": "low"},
    {"nl_query": "Detect insecure direct object reference (IDOR) exploitation: a user receiving more than 20 HTTP 200 responses on sequential object IDs not owned by the requesting user", "category": "web", "complexity": "high"},
    {"nl_query": "Alert on command injection in web parameters: HTTP request containing shell metacharacters such as semicolons, pipes, or subshell expansion in fields processed by OS command execution functions", "category": "web", "complexity": "high"},
    {"nl_query": "Detect WAF bypass attempts: HTTP requests with unusual encoding (double URL encoding, UTF-8 overlong encoding, null-byte injection) triggering WAF bypass signatures", "category": "web", "complexity": "high"},
    {"nl_query": "Alert on web scanner activity: HTTP requests from a single IP containing more than 50 distinct URL paths with 404 responses within 5 minutes (vulnerability scanner or fuzzer)", "category": "web", "complexity": "medium"},
    {"nl_query": "Detect JWT token forgery: web application receiving a JWT with algorithm set to none or HS256 when RS256 is the configured standard (algorithm confusion attack)", "category": "web", "complexity": "high"},
    {"nl_query": "Alert on admin panel access from an IP outside the corporate IP range: HTTP 200 response to /admin, /wp-admin, or /phpmyadmin from an unapproved source IP", "category": "web", "complexity": "medium"},
    {"nl_query": "Detect GraphQL introspection query sent to a production API from an IP not in the developer allow-list (information disclosure risk)", "category": "web", "complexity": "low"},

    # ══════════════════════════════════════════════════════════════════════════
    # EMAIL  (15)  — ATT&CK: Initial Access · Collection · Exfiltration
    # Covers: phishing, BEC, mail rules, spoofing, OAuth consent, DLP
    # ══════════════════════════════════════════════════════════════════════════

    {"nl_query": "Alert on creation of an Exchange or Microsoft 365 inbox forwarding rule redirecting all incoming mail to an external address (Unified Audit Log New-InboxRule with ForwardTo external)", "category": "email", "complexity": "medium"},
    {"nl_query": "Detect email spoofing: inbound email where the From header domain matches the organisation's domain but SPF, DKIM, and DMARC all fail", "category": "email", "complexity": "medium"},
    {"nl_query": "Alert on Business Email Compromise indicator: an email thread with an executive's display name but a From address in a lookalike domain (homoglyph or hyphenated variant)", "category": "email", "complexity": "high"},
    {"nl_query": "Detect mass phishing campaign: a single sender or IP delivering more than 200 emails containing the same URL or attachment hash to internal recipients within 15 minutes", "category": "email", "complexity": "high"},
    {"nl_query": "Alert when a user clicks a URL in an email that resolves to a domain categorised as phishing, malware, or newly registered in the last 7 days (email click-tracking or proxy log)", "category": "email", "complexity": "medium"},
    {"nl_query": "Detect malicious attachment detonation: email attachment with a .docm, .xlsm, .js, .vbs, .hta, or .iso extension delivered to more than 5 internal recipients in a 10-minute window", "category": "email", "complexity": "high"},
    {"nl_query": "Alert on email account compromise: user account sending more than 500 outbound emails within one hour when the 30-day baseline is below 100 per hour", "category": "email", "complexity": "high"},
    {"nl_query": "Detect OAuth application consent granted by a user to a third-party app requesting mail.readwrite, calendars.readwrite, or contacts.read permissions in Microsoft 365", "category": "email", "complexity": "high"},
    {"nl_query": "Alert on a Microsoft 365 transport rule created that forwards a copy of all mail matching a keyword to an external address (BEC persistence via mail flow rule)", "category": "email", "complexity": "high"},
    {"nl_query": "Detect a dormant email account (no activity in 60 days) suddenly sending emails with external attachments (possible compromised account re-activation)", "category": "email", "complexity": "medium"},
    {"nl_query": "Alert on email impersonation of an executive: inbound email with ReplyTo address different from the From address and subject containing urgency keywords such as Wire Transfer, Urgent, or Payment", "category": "email", "complexity": "medium"},
    {"nl_query": "Detect email data loss: outbound email to a personal email domain with an attachment matching the DLP sensitive-data policy for PII or financial data", "category": "email", "complexity": "high"},
    {"nl_query": "Alert on email account sign-in from a location inconsistent with the user's recent activity, followed by creation of an inbox rule within 5 minutes (account takeover pattern)", "category": "email", "complexity": "high"},
    {"nl_query": "Detect QR code phishing (quishing): inbound email with no body text but an embedded image and no text links, bypassing URL filters", "category": "email", "complexity": "medium"},
    {"nl_query": "Alert on a shared mailbox accessed by a user who is not a member of the approved shared-mailbox access group and who reads more than 50 messages in one session", "category": "email", "complexity": "medium"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ParseError(RuntimeError):
    """Raised when ParserAgent fails to produce an IR for a seed query."""


class AugmentationError(RuntimeError):
    """Raised when LLM paraphrase augmentation exhausts its retries."""


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GenerationConfig:
    seeds_path: Optional[Path] = None
    output: Path = DEFAULT_OUTPUT
    limit: Optional[int] = None
    augment: bool = False
    augment_factor: int = 3
    augment_retries: int = 3
    min_valid: int = 3
    min_platform_coverage: float = 0.7   # quality gate: per-platform validity rate
    min_acceptance_rate: float = 0.5     # quality gate: records_written / total_seeds
    workers: int = 1
    resume: bool = False
    make_splits: bool = True
    split_ratios: tuple[float, float, float] = (0.8, 0.1, 0.1)
    rng_seed: int = 42
    dry_run: bool = False
    quiet: bool = False
    no_progress: bool = False

    def as_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["seeds_path"] = str(self.seeds_path) if self.seeds_path else None
        d["output"] = str(self.output)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Text normalization / hashing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace, for dedupe comparisons only."""
    return re.sub(r"\s+", " ", text.strip().lower())


def _content_hash(text: str, *extra: str) -> str:
    h = hashlib.sha256("|".join((text, *extra)).encode("utf-8")).hexdigest()
    return h[:12]


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(pct / 100 * (len(s) - 1)))))
    return round(s[idx], 2)


# ─────────────────────────────────────────────────────────────────────────────
# Seed loading + dedupe
# ─────────────────────────────────────────────────────────────────────────────

def _load_seeds(path: Optional[Path], limit: Optional[int]) -> list[dict]:
    if path and path.exists():
        log.info("Loading seeds from file", extra={"path": str(path)})
        raw = []
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    log.warning("Skipping malformed seed line", extra={"line": lineno, "error": str(exc)})
    else:
        log.info("Using built-in seed queries", extra={"n": len(_BUILTIN_SEEDS)})
        raw = list(_BUILTIN_SEEDS)

    # Schema check + dedupe by normalized nl_query.
    seen: dict[str, dict] = {}
    dupes = 0
    invalid = 0
    for s in raw:
        nl = (s.get("nl_query") or "").strip()
        if not nl:
            invalid += 1
            continue
        key = _normalize(nl)
        if key in seen:
            dupes += 1
            continue
        seen[key] = {
            "nl_query": nl,
            "category": s.get("category", "unknown"),
            "complexity": s.get("complexity", "medium"),
        }

    seeds = list(seen.values())
    if limit:
        seeds = seeds[:limit]

    log.info("Seeds loaded", extra={"n": len(seeds), "duplicates_dropped": dupes, "invalid_dropped": invalid})
    return seeds


# ─────────────────────────────────────────────────────────────────────────────
# Translation (rule-based via translators, no LLM cost)
# ─────────────────────────────────────────────────────────────────────────────

def _translate_rule_based(ir) -> dict[str, str]:
    """Generate ground-truth queries using deterministic translator chain."""
    from src.translators.splunk import SplunkTranslator
    from src.translators.qradar import QRadarTranslator
    from src.translators.elastic import ElasticTranslator
    from src.translators.sentinel import SentinelTranslator
    from src.translators.wazuh import WazuhTranslator

    results: dict[str, str] = {}
    for name, cls in [
        ("splunk", SplunkTranslator),
        ("qradar", QRadarTranslator),
        ("elastic", ElasticTranslator),
        ("sentinel", SentinelTranslator),
        ("wazuh", WazuhTranslator),
    ]:
        try:
            results[name] = cls().translate(ir)
        except Exception as exc:
            log.warning("Translator failed", extra={"platform": name, "error": str(exc)})
            results[name] = ""
    return results


def _validate_translations(translations: dict[str, str]) -> dict[str, dict[str, Any]]:
    """
    Validate each platform's translation. Returns per-platform diagnostics
    (not just a pass/fail list) so a translator regression is debuggable
    directly from the dataset file: metadata.validation.<platform>.error.
    """
    from src.evaluation.syntax_validator import SyntaxValidator
    v = SyntaxValidator()
    out: dict[str, dict[str, Any]] = {}
    for platform, query in translations.items():
        if not query:
            out[platform] = {"is_valid": False, "error": "empty_translation"}
            continue
        try:
            result = v.validate(platform, query)
            is_valid = bool(getattr(result, "is_valid", False))
            err = None
            if not is_valid:
                err = getattr(result, "errors", None) or getattr(result, "error", None) or "invalid_syntax"
            out[platform] = {"is_valid": is_valid, "error": err}
        except Exception as exc:
            out[platform] = {"is_valid": False, "error": f"validator_exception: {exc}"}
    return out


# ─────────────────────────────────────────────────────────────────────────────
# LLM augmentation (optional) -- with retries, backoff, robust JSON parsing
# ─────────────────────────────────────────────────────────────────────────────

def _extract_json_array(raw: str) -> list[str]:
    """Pull a JSON array of strings out of a raw LLM response, tolerating
    ```json fences or stray prose around the array."""
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.MULTILINE).strip()
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return [str(p).strip() for p in parsed if str(p).strip()]
    except json.JSONDecodeError:
        pass
    # Fallback: grab the first [...] block.
    match = re.search(r"\[.*\]", cleaned, flags=re.DOTALL)
    if match:
        parsed = json.loads(match.group(0))
        return [str(p).strip() for p in parsed if str(p).strip()]
    raise AugmentationError("Could not locate a JSON array in LLM response")


def _augment_with_llm(seed: str, n_paraphrases: int, retries: int = 3) -> list[str]:
    """
    Use the LLM client to generate N paraphrases of a seed query, retrying
    transient failures with exponential backoff. Returns [seed] + unique,
    non-empty paraphrases (deduped against each other and the original).
    """
    from src.llm.client import LLMClient

    prompt = (
        f"Generate {n_paraphrases} distinct paraphrases of this security detection query. "
        f"Each must describe the same detection goal but use different wording, "
        f"realistic of how a SOC analyst would phrase a request.\n\n"
        f"Original: {seed}\n\n"
        f"Return a JSON array of strings only, no markdown, no commentary."
    )

    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            client = LLMClient()
            raw = client.complete(prompt, max_tokens=512)
            paraphrases = _extract_json_array(raw)
            seen = {_normalize(seed)}
            unique: list[str] = []
            for p in paraphrases:
                key = _normalize(p)
                if key and key not in seen:
                    seen.add(key)
                    unique.append(p)
                if len(unique) >= n_paraphrases:
                    break
            return [seed] + unique
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                sleep_s = (0.5 * 2 ** (attempt - 1)) + random.uniform(0, 0.25)
                log.warning("Augmentation attempt failed, retrying",
                            extra={"attempt": attempt, "error": str(exc), "sleep_s": round(sleep_s, 2)})
                time.sleep(sleep_s)

    log.warning("Augmentation failed after retries, falling back to original seed only",
                extra={"error": str(last_exc)})
    return [seed]


# ─────────────────────────────────────────────────────────────────────────────
# Per-seed processing (parse -> translate -> validate)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProcessResult:
    record: Optional[dict]
    skip_reason: Optional[str]
    parse_ms: float
    pipeline_ms: float


def _process_one(seed: dict, min_valid: int) -> ProcessResult:
    from src.llm.client import LLMClient
    from src.agents.parser_agent import ParserAgent

    nl_query = seed["nl_query"]
    t0 = time.monotonic()

    try:
        client = LLMClient()

        parser = ParserAgent(
            client=client
        )

        ir_result = parser.parse(nl_query)

        ir = (
            ir_result.ir
            if hasattr(ir_result, "ir")
            else ir_result
        )

    except Exception as exc:
        log.warning("Parser failed", extra={"query": nl_query[:60], "error": str(exc)})
        return ProcessResult(None, "parse_failed", round((time.monotonic() - t0) * 1000, 2), 0.0)

    t1 = time.monotonic()
    translations = _translate_rule_based(ir)
    validation = _validate_translations(translations)
    valid_plats = [p for p, r in validation.items() if r["is_valid"]]

    pipeline_ms = round((time.monotonic() - t0) * 1000, 2)
    parse_ms = round((t1 - t0) * 1000, 2)

    if len(valid_plats) < min_valid:
        log.debug("Skipping: too few valid translations",
                  extra={"query": nl_query[:40], "valid": valid_plats})
        return ProcessResult(None, "too_few_valid_platforms", parse_ms, pipeline_ms)

    ir_dict = ir.to_dict() if hasattr(ir, "to_dict") else (vars(ir) if ir else {})
    record = {
        "nl_query": nl_query,
        "complexity": seed.get("complexity", "medium"),
        "category": seed.get("category", "unknown"),
        "ir": ir_dict,
        "ground_truth": translations,
        "_internal": {
            "source_seed_id": seed["_source_seed_id"],
            "is_paraphrase": seed.get("_is_paraphrase", False),
            "valid_platforms": valid_plats,
            "n_valid": len(valid_plats),
            "validation": validation,
            "content_hash": _content_hash(_normalize(nl_query), seed.get("category", "")),
        },
    }
    return ProcessResult(record, None, parse_ms, pipeline_ms)


# ─────────────────────────────────────────────────────────────────────────────
# Progress printing
# ─────────────────────────────────────────────────────────────────────────────

def _print_progress(idx: int, total: int, t0: float, n_ok: int) -> None:
    bar_len = 30
    filled = int(bar_len * idx / max(total, 1))
    bar = "#" * filled + "." * (bar_len - filled)
    pct = 100 * idx / max(total, 1)
    elapsed = time.monotonic() - t0
    rate = idx / elapsed if elapsed > 0 else 0
    eta = (total - idx) / rate if rate > 0 else 0
    print(f"\r  [{bar}] {pct:5.1f}%  [{idx:>4}/{total}]  kept={n_ok:<4}  eta={eta:5.1f}s", end="", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Leakage-safe stratified splitting
# ─────────────────────────────────────────────────────────────────────────────

def _make_splits(
    records: list[dict], ratios: tuple[float, float, float], rng_seed: int,
    group_key=lambda r: r["metadata"]["source_seed_id"],
    category_key=lambda r: r["category"],
) -> dict[str, list[dict]]:
    """
    Stratified train/dev/test split that keeps every paraphrase of a given
    seed entirely within one split (grouped by `group_key`, default
    `metadata.source_seed_id`). Splitting at the record level instead would
    leak near-duplicate phrasings of the same underlying query across
    splits and inflate eval metrics.
    """
    by_category: dict[str, list[str]] = defaultdict(list)
    seen_groups: set[str] = set()

    for r in records:
        gid = group_key(r)
        if gid not in seen_groups:
            seen_groups.add(gid)
            by_category[category_key(r)].append(gid)

    rng = random.Random(rng_seed)
    split_of_group: dict[str, str] = {}
    train_r, dev_r, _ = ratios

    for category, gids in by_category.items():
        gids = list(gids)
        rng.shuffle(gids)
        n = len(gids)
        n_train = max(1, round(n * train_r)) if n >= 3 else n
        n_dev = max(1 if n >= 2 else 0, round(n * dev_r)) if n >= 3 else 0
        n_train = min(n_train, n)
        n_dev = min(n_dev, n - n_train)
        for gid in gids[:n_train]:
            split_of_group[gid] = "train"
        for gid in gids[n_train:n_train + n_dev]:
            split_of_group[gid] = "dev"
        for gid in gids[n_train + n_dev:]:
            split_of_group[gid] = "test"

    splits: dict[str, list[dict]] = {"train": [], "dev": [], "test": []}
    for r in records:
        gid = group_key(r)
        splits[split_of_group[gid]].append(r)
    return splits


# ─────────────────────────────────────────────────────────────────────────────
# Reporting: stats.json + DATASET_CARD.md + manifest.json
# ─────────────────────────────────────────────────────────────────────────────

def _compute_stats(records: list[dict], gen_stats: dict) -> dict:
    cat_counts = Counter(r["category"] for r in records)
    cx_counts = Counter(r["complexity"] for r in records)
    plat_valid = Counter()
    for r in records:
        for p in r["metadata"]["valid_platforms"]:
            plat_valid[p] += 1
    n = max(len(records), 1)
    return {
        **gen_stats,
        "category_distribution": dict(sorted(cat_counts.items())),
        "complexity_distribution": dict(sorted(cx_counts.items())),
        "platform_validity_rate": {p: round(plat_valid.get(p, 0) / n, 3) for p in PLATFORMS},
        "mean_valid_platforms_per_record": round(
            sum(r["metadata"]["n_valid"] for r in records) / n, 2
        ),
    }


def _write_dataset_card(path: Path, stats: dict, splits: dict[str, list[dict]]) -> None:
    lines = [
        "# SIEMBench Dataset Card",
        "",
        f"Generated: {stats['generated_at']}  ·  Schema v{SCHEMA_VERSION}  ·  Generator v{GENERATOR_VERSION}  ·  run `{stats['run_id']}`",
        "",
        "## Summary",
        "",
        f"- Total seeds considered: **{stats['total_seeds']}**",
        f"- Records kept (>= min_valid platforms): **{stats['records_written']}**",
        f"- Skipped: **{stats['skipped']}** ({stats.get('skip_reasons', {})})",
        f"- Acceptance rate: **{stats['acceptance_rate']:.1%}**",
        "",
        "## Category distribution",
        "",
        "| Category | Records |",
        "|---|---|",
    ]
    for cat, n in stats["category_distribution"].items():
        lines.append(f"| {cat} | {n} |")

    lines += ["", "## Complexity distribution", "", "| Complexity | Records |", "|---|---|"]
    for cx, n in stats["complexity_distribution"].items():
        lines.append(f"| {cx} | {n} |")

    lines += ["", "## Per-platform ground-truth validity rate", "", "| Platform | Valid rate |", "|---|---|"]
    for p, rate in stats["platform_validity_rate"].items():
        lines.append(f"| {p} | {rate:.1%} |")

    lines += [
        "",
        "## Splits",
        "",
        "| Split | Records | Unique seeds |",
        "|---|---|---|",
    ]
    for name, recs in splits.items():
        n_groups = len({r["metadata"]["source_seed_id"] for r in recs})
        lines.append(f"| {name} | {len(recs)} | {n_groups} |")

    lines += [
        "",
        "## Methodology notes",
        "",
        "- Seeds are deduplicated on normalized text before generation.",
        "- Splits are grouped by `source_seed_id`: every paraphrase of a given "
        "seed query stays in a single split, preventing train/test leakage "
        "from near-duplicate phrasings.",
        "- Ground truth is produced by deterministic, rule-based translators "
        "(no LLM in the translation path) and filtered through "
        "`SyntaxValidator`; per-platform validation diagnostics are kept "
        "in each record's `_internal.validation` field.",
        "- LLM paraphrase augmentation (if used) retries transient failures "
        "with exponential backoff and deduplicates paraphrases against the "
        "original seed.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest(path: Path, files: dict[str, Path], config: GenerationConfig, run_id: str) -> None:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "run_id": run_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "config": config.as_jsonable(),
        "files": {
            name: {
                "path": str(p),
                "sha256": _sha256_file(p),
                "bytes": p.stat().st_size,
            }
            for name, p in files.items() if p.exists()
        },
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Main generation loop
# ─────────────────────────────────────────────────────────────────────────────

def generate(config: GenerationConfig) -> dict:
    run_id = uuid.uuid4().hex[:8]
    generator = "rule_based_v1" + ("_augmented" if config.augment else "")

    seeds = _load_seeds(config.seeds_path, config.limit)
    if not seeds:
        raise RuntimeError("No seeds available after loading/dedup.")

    # Tag every seed with a stable source_seed_id BEFORE augmentation, so
    # paraphrases inherit their parent's group key for leakage-safe splits.
    for s in seeds:
        s["_source_seed_id"] = _content_hash(_normalize(s["nl_query"]), s["category"])

    if config.dry_run:
        cats = Counter(s["category"] for s in seeds)
        cxs = Counter(s["complexity"] for s in seeds)
        return {
            "dry_run": True, "total_seeds": len(seeds),
            "category_distribution": dict(sorted(cats.items())),
            "complexity_distribution": dict(sorted(cxs.items())),
        }

    # ── Expand via augmentation ────────────────────────────────────────────
    all_seeds: list[dict] = []
    for seed in seeds:
        if config.augment:
            paraphrases = _augment_with_llm(seed["nl_query"], config.augment_factor, config.augment_retries)
            for i, p in enumerate(paraphrases):
                all_seeds.append({**seed, "nl_query": p, "_is_paraphrase": i > 0})
        else:
            all_seeds.append({**seed, "_is_paraphrase": False})

    # Dedupe again post-augmentation (paraphrases can collide across seeds).
    dedup: dict[str, dict] = {}
    for s in all_seeds:
        key = _normalize(s["nl_query"])
        dedup.setdefault(key, s)
    all_seeds = list(dedup.values())
    total = len(all_seeds)

    # ── Resume support ─────────────────────────────────────────────────────
    existing_records: list[dict] = []
    already_done: set[str] = set()
    if config.resume and config.output.exists():
        with open(config.output, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    existing_records.append(rec)
                    already_done.add(_normalize(rec["nl_query"]))
                except json.JSONDecodeError:
                    continue
        log.info("Resuming previous run", extra={"existing_records": len(existing_records)})

    pending = [s for s in all_seeds if _normalize(s["nl_query"]) not in already_done]

    # ── Process (optionally concurrent) ────────────────────────────────────
    records: list[dict] = list(existing_records)
    skip_reasons: Counter = Counter()
    parse_latencies: list[float] = []
    pipeline_latencies: list[float] = []
    t0 = time.monotonic()

    def _run(seed: dict) -> ProcessResult:
        return _process_one(seed, config.min_valid)

    if config.workers > 1:
        with ThreadPoolExecutor(max_workers=config.workers) as pool:
            futures = [pool.submit(_run, s) for s in pending]
            results = [f.result() for f in futures]
    else:
        results = [_run(s) for s in pending]

    for i, result in enumerate(results, start=1):
        if result.parse_ms:
            parse_latencies.append(result.parse_ms)
        if result.pipeline_ms:
            pipeline_latencies.append(result.pipeline_ms)
        if result.record is None:
            skip_reasons[result.skip_reason or "unknown"] += 1
        else:
            records.append(result.record)
        if not config.quiet and not config.no_progress:
            _print_progress(i, len(pending), t0, len(records) - len(existing_records))

    if not config.quiet and not config.no_progress and pending:
        print()

    # ── Assign final sequential ids (stable, content-addressed sort) ──────
    records.sort(key=lambda r: r["_internal"]["content_hash"])
    for idx, r in enumerate(records):
        r["id"] = f"sb_{idx:04d}"

    # ── Finalize record shape (move validation/internal bookkeeping into
    #    a public `metadata` block; nl ground truth stays top-level) ──────
    finalized: list[dict] = []
    for r in records:
        internal = r.pop("_internal")
        r["metadata"] = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "generator": generator,
            "run_id": run_id,
            "source_seed_id": internal["source_seed_id"],
            "is_paraphrase": internal["is_paraphrase"],
            "valid_platforms": internal["valid_platforms"],
            "n_valid": internal["n_valid"],
            "validation": internal["validation"],
            "content_hash": internal["content_hash"],
        }
        finalized.append(r)
    records = finalized

    # ── Build splits (leakage-safe: grouped by source_seed_id) ────────────
    splits = _make_splits(records, config.split_ratios, config.rng_seed) if config.make_splits else {}

    # ── Atomic write of the main dataset file ──────────────────────────────
    config.output.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config.output.with_suffix(config.output.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp_path.replace(config.output)

    split_paths: dict[str, Path] = {}
    if config.make_splits:
        for name, recs in splits.items():
            p = config.output.with_name(f"{config.output.stem}.{name}{config.output.suffix}")
            with open(p, "w", encoding="utf-8") as f:
                for r in recs:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            split_paths[name] = p

    # ── Integrity check (catches truncated writes / id collisions) ────────
    issues: list[str] = []
    ids_seen: set[str] = set()
    with open(config.output, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                issues.append(f"line {lineno}: invalid JSON")
                continue
            if rec.get("id") in ids_seen:
                issues.append(f"line {lineno}: duplicate id {rec.get('id')}")
            ids_seen.add(rec.get("id"))
            if not rec.get("ground_truth"):
                issues.append(f"line {lineno}: empty ground_truth")
    if issues:
        log.warning("Integrity check found issues", extra={"n_issues": len(issues), "sample": issues[:5]})

    elapsed = round(time.monotonic() - t0, 2)
    gen_stats = {
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_seeds": total,
        "records_written": len(records),
        "skipped": sum(skip_reasons.values()),
        "skip_reasons": dict(skip_reasons),
        "acceptance_rate": round(len(records) / total, 3) if total else 0.0,
        "output": str(config.output),
        "elapsed_s": elapsed,
        "generator": generator,
        "parse_latency_ms_p50": _percentile(parse_latencies, 50),
        "parse_latency_ms_p95": _percentile(parse_latencies, 95),
        "pipeline_latency_ms_p50": _percentile(pipeline_latencies, 50),
        "pipeline_latency_ms_p95": _percentile(pipeline_latencies, 95),
        "integrity_issues": len(issues),
    }
    stats = _compute_stats(records, gen_stats)

    stats_path = config.output.with_name("stats.json")
    stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    card_path = config.output.with_name("DATASET_CARD.md")
    _write_dataset_card(card_path, stats, splits)

    manifest_path = config.output.with_name("manifest.json")
    files = {"dataset": config.output, "stats": stats_path, "dataset_card": card_path, **{f"split_{k}": v for k, v in split_paths.items()}}
    _write_manifest(manifest_path, files, config, run_id)

    stats["quality_gate_passed"] = (
        stats["acceptance_rate"] >= config.min_acceptance_rate
        and all(rate >= config.min_platform_coverage for rate in stats["platform_validity_rate"].values())
    )
    stats["artifacts"] = {k: str(v) for k, v in files.items()}
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Build the SIEMBench evaluation dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--seeds", type=Path, default=None,
                    help="Seed queries JSONL file (uses built-in seeds if omitted)")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output JSONL path")
    p.add_argument("--limit", type=int, default=None, help="Limit number of seeds (for quick testing)")
    p.add_argument("--augment", action="store_true", help="Expand seeds via LLM paraphrasing")
    p.add_argument("--augment-factor", type=int, default=3, help="Paraphrases per seed (only with --augment)")
    p.add_argument("--augment-retries", type=int, default=3, help="Retries per seed for LLM augmentation")
    p.add_argument("--min-valid", type=int, default=3, help="Minimum valid platforms to include a record")
    p.add_argument("--min-platform-coverage", type=float, default=0.7,
                    help="Quality gate: minimum per-platform validity rate")
    p.add_argument("--min-acceptance-rate", type=float, default=0.5,
                    help="Quality gate: minimum fraction of seeds kept")
    p.add_argument("--workers", type=int, default=1,
                    help="Concurrent workers (helps when ParserAgent/LLMClient hit a network API)")
    p.add_argument("--resume", action="store_true", help="Resume from an existing --output file")
    p.add_argument("--no-splits", action="store_true", help="Skip writing train/dev/test split files")
    p.add_argument("--rng-seed", type=int, default=42, help="Seed for deterministic split assignment")
    p.add_argument("--dry-run", action="store_true",
                    help="Validate/dedupe seeds and print a summary without running the pipeline")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--no-progress", action="store_true", help="Suppress the progress bar (kept on for --quiet)")
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()

    if not args.quiet:
        print("\n" + "=" * 60)
        print("  NL-SIEM  |  SIEMBench Dataset Generator  v" + GENERATOR_VERSION)
        print("=" * 60)

    config = GenerationConfig(
        seeds_path=args.seeds,
        output=args.output,
        limit=args.limit,
        augment=args.augment,
        augment_factor=args.augment_factor,
        augment_retries=args.augment_retries,
        min_valid=args.min_valid,
        min_platform_coverage=args.min_platform_coverage,
        min_acceptance_rate=args.min_acceptance_rate,
        workers=max(1, args.workers),
        resume=args.resume,
        make_splits=not args.no_splits,
        rng_seed=args.rng_seed,
        dry_run=args.dry_run,
        quiet=args.quiet,
        no_progress=args.no_progress,
    )

    try:
        stats = generate(config)
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]", file=sys.stderr)
        return 2
    except Exception as exc:
        log.exception("Dataset generation failed")
        print(f"[ERROR]  {exc}", file=sys.stderr)
        return 2

    if config.dry_run:
        print(json.dumps(stats, indent=2))
        return 0

    if not args.quiet:
        print("\n-- Dataset generation stats " + "-" * 33)
        for k, v in stats.items():
            if k in ("category_distribution", "complexity_distribution", "platform_validity_rate",
                      "skip_reasons", "artifacts"):
                print(f"  {k}:")
                for kk, vv in v.items():
                    print(f"      {kk:<20}: {vv}")
            else:
                print(f"  {k:<26}: {v}")
        print("-" * 60)
        gate = "PASSED" if stats["quality_gate_passed"] else "FAILED"
        print(f"\n[{'OK' if stats['quality_gate_passed'] else 'WARN'}]  Quality gate: {gate}")
        print(f"[OK]  Dataset written to: {args.output}")

    if stats["records_written"] == 0:
        return 1
    return 0 if stats["quality_gate_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())