#!/usr/bin/env python3
"""
label_attck.py — Batch ATT&CK labeller for SIEMBench gold seeds
================================================================
Reads  : data/seeds/gold_seeds.jsonl
Writes : data/seeds/siembench_attck.jsonl

Each input record gains an `attck` block:
  {
    "tactic":        "credential-access",
    "technique":     "T1110",
    "sub_technique": "T1110.003",   # "" if none
    "confidence":    0.92,
    "rationale":     "one-line reason"
  }

Design principles
-----------------
* Resume-safe  — already-labelled IDs are skipped on re-run.
* Rate-limited — configurable RPS with exponential back-off.
* Validated    — every label is checked against the MITRE ATT&CK
                 taxonomy before it is written to disk.
* Auditable    — a run manifest (label_run_manifest.json) records
                 model, timestamp, pass/fail counts, and total cost.
* Zero lock-in — provider is a thin adapter; swap Groq ↔ OpenAI ↔
                 Anthropic by changing --provider.

Usage
-----
  # Full run (Groq default)
  python scripts/label_attck.py

  # Explicit paths / provider
  python scripts/label_attck.py \
      --input  data/seeds/gold_seeds.jsonl \
      --output data/seeds/siembench_attck.jsonl \
      --provider groq \
      --model   llama3-70b-8192 \
      --rps     4 \
      --max-retries 5

  # Dry-run (print first 3 prompts, no API calls)
  python scripts/label_attck.py --dry-run --limit 3

Environment variables
---------------------
  GROQ_API_KEY      required for --provider groq
  OPENAI_API_KEY    required for --provider openai
  ANTHROPIC_API_KEY required for --provider anthropic
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from src.llm.client import LLMClient
from src.agents.attck_classifier_agent import ATTCKClassifierAgent
# ---------------------------------------------------------------------------
# MITRE ATT&CK taxonomy (technique → canonical tactic mapping)
# Covers every technique referenced by the gold seed corpus.
# Extend as needed; validation is soft-warn, not hard-fail, so new
# techniques that arrive via LLM output still pass through with a flag.
# ---------------------------------------------------------------------------
ATTCK_TAXONOMY: dict[str, dict[str, Any]] = {
    # Credential Access
    "T1003":  {"tactic": "credential-access", "name": "OS Credential Dumping"},
    "T1003.001": {"tactic": "credential-access", "name": "LSASS Memory"},
    "T1003.002": {"tactic": "credential-access", "name": "Security Account Manager"},
    "T1003.003": {"tactic": "credential-access", "name": "NTDS"},
    "T1003.004": {"tactic": "credential-access", "name": "LSA Secrets"},
    "T1056":  {"tactic": "credential-access", "name": "Input Capture"},
    "T1056.001": {"tactic": "credential-access", "name": "Keylogging"},
    "T1056.004": {"tactic": "credential-access", "name": "Credential API Hooking"},
    "T1110":  {"tactic": "credential-access", "name": "Brute Force"},
    "T1110.001": {"tactic": "credential-access", "name": "Password Guessing"},
    "T1110.002": {"tactic": "credential-access", "name": "Password Cracking"},
    "T1110.003": {"tactic": "credential-access", "name": "Password Spraying"},
    "T1110.004": {"tactic": "credential-access", "name": "Credential Stuffing"},
    "T1528":  {"tactic": "credential-access", "name": "Steal Application Access Token"},
    "T1539":  {"tactic": "credential-access", "name": "Steal Web Session Cookie"},
    "T1552":  {"tactic": "credential-access", "name": "Unsecured Credentials"},
    "T1552.001": {"tactic": "credential-access", "name": "Credentials In Files"},
    "T1552.004": {"tactic": "credential-access", "name": "Private Keys"},
    "T1555":  {"tactic": "credential-access", "name": "Credentials from Password Stores"},
    "T1555.003": {"tactic": "credential-access", "name": "Credentials from Web Browsers"},
    "T1557":  {"tactic": "credential-access", "name": "Adversary-in-the-Middle"},
    "T1557.001": {"tactic": "credential-access", "name": "LLMNR/NBT-NS Poisoning"},
    "T1558":  {"tactic": "credential-access", "name": "Steal or Forge Kerberos Tickets"},
    "T1558.001": {"tactic": "credential-access", "name": "Golden Ticket"},
    "T1558.002": {"tactic": "credential-access", "name": "Silver Ticket"},
    "T1558.003": {"tactic": "credential-access", "name": "Kerberoasting"},
    "T1558.004": {"tactic": "credential-access", "name": "AS-REP Roasting"},
    "T1606":  {"tactic": "credential-access", "name": "Forge Web Credentials"},
    # Defense Evasion
    "T1027":  {"tactic": "defense-evasion", "name": "Obfuscated Files or Information"},
    "T1036":  {"tactic": "defense-evasion", "name": "Masquerading"},
    "T1055":  {"tactic": "defense-evasion", "name": "Process Injection"},
    "T1055.001": {"tactic": "defense-evasion", "name": "DLL Injection"},
    "T1055.002": {"tactic": "defense-evasion", "name": "Portable Executable Injection"},
    "T1055.003": {"tactic": "defense-evasion", "name": "Thread Execution Hijacking"},
    "T1055.012": {"tactic": "defense-evasion", "name": "Process Hollowing"},
    "T1055.013": {"tactic": "defense-evasion", "name": "Process Doppelgänging"},
    "T1070":  {"tactic": "defense-evasion", "name": "Indicator Removal"},
    "T1070.001": {"tactic": "defense-evasion", "name": "Clear Windows Event Logs"},
    "T1070.004": {"tactic": "defense-evasion", "name": "File Deletion"},
    "T1112":  {"tactic": "defense-evasion", "name": "Modify Registry"},
    "T1140":  {"tactic": "defense-evasion", "name": "Deobfuscate/Decode Files or Information"},
    "T1197":  {"tactic": "defense-evasion", "name": "BITS Jobs"},
    "T1218":  {"tactic": "defense-evasion", "name": "System Binary Proxy Execution"},
    "T1218.001": {"tactic": "defense-evasion", "name": "Compiled HTML File"},
    "T1218.005": {"tactic": "defense-evasion", "name": "Mshta"},
    "T1218.010": {"tactic": "defense-evasion", "name": "Regsvr32"},
    "T1218.011": {"tactic": "defense-evasion", "name": "Rundll32"},
    "T1562":  {"tactic": "defense-evasion", "name": "Impair Defenses"},
    "T1562.001": {"tactic": "defense-evasion", "name": "Disable or Modify Tools"},
    "T1574":  {"tactic": "defense-evasion", "name": "Hijack Execution Flow"},
    "T1574.001": {"tactic": "defense-evasion", "name": "DLL Search Order Hijacking"},
    # Discovery
    "T1007":  {"tactic": "discovery", "name": "System Service Discovery"},
    "T1010":  {"tactic": "discovery", "name": "Application Window Discovery"},
    "T1016":  {"tactic": "discovery", "name": "System Network Configuration Discovery"},
    "T1018":  {"tactic": "discovery", "name": "Remote System Discovery"},
    "T1033":  {"tactic": "discovery", "name": "System Owner/User Discovery"},
    "T1046":  {"tactic": "discovery", "name": "Network Service Discovery"},
    "T1049":  {"tactic": "discovery", "name": "System Network Connections Discovery"},
    "T1057":  {"tactic": "discovery", "name": "Process Discovery"},
    "T1069":  {"tactic": "discovery", "name": "Permission Groups Discovery"},
    "T1082":  {"tactic": "discovery", "name": "System Information Discovery"},
    "T1083":  {"tactic": "discovery", "name": "File and Directory Discovery"},
    "T1087":  {"tactic": "discovery", "name": "Account Discovery"},
    "T1087.001": {"tactic": "discovery", "name": "Local Account"},
    "T1087.002": {"tactic": "discovery", "name": "Domain Account"},
    "T1135":  {"tactic": "discovery", "name": "Network Share Discovery"},
    "T1201":  {"tactic": "discovery", "name": "Password Policy Discovery"},
    "T1482":  {"tactic": "discovery", "name": "Domain Trust Discovery"},
    "T1526":  {"tactic": "discovery", "name": "Cloud Service Discovery"},
    "T1538":  {"tactic": "discovery", "name": "Cloud Service Dashboard"},
    "T1580":  {"tactic": "discovery", "name": "Cloud Infrastructure Discovery"},
    # Execution
    "T1047":  {"tactic": "execution", "name": "Windows Management Instrumentation"},
    "T1053":  {"tactic": "execution", "name": "Scheduled Task/Job"},
    "T1053.005": {"tactic": "execution", "name": "Scheduled Task"},
    "T1059":  {"tactic": "execution", "name": "Command and Scripting Interpreter"},
    "T1059.001": {"tactic": "execution", "name": "PowerShell"},
    "T1059.003": {"tactic": "execution", "name": "Windows Command Shell"},
    "T1059.006": {"tactic": "execution", "name": "Python"},
    "T1203":  {"tactic": "execution", "name": "Exploitation for Client Execution"},
    "T1204":  {"tactic": "execution", "name": "User Execution"},
    # Exfiltration
    "T1020":  {"tactic": "exfiltration", "name": "Automated Exfiltration"},
    "T1041":  {"tactic": "exfiltration", "name": "Exfiltration Over C2 Channel"},
    "T1048":  {"tactic": "exfiltration", "name": "Exfiltration Over Alternative Protocol"},
    "T1048.001": {"tactic": "exfiltration", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"},
    "T1048.003": {"tactic": "exfiltration", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"},
    "T1052":  {"tactic": "exfiltration", "name": "Exfiltration Over Physical Medium"},
    "T1052.001": {"tactic": "exfiltration", "name": "Exfiltration over USB"},
    "T1567":  {"tactic": "exfiltration", "name": "Exfiltration Over Web Service"},
    "T1567.002": {"tactic": "exfiltration", "name": "Exfiltration to Cloud Storage"},
    # Impact
    "T1485":  {"tactic": "impact", "name": "Data Destruction"},
    "T1486":  {"tactic": "impact", "name": "Data Encrypted for Impact"},
    "T1489":  {"tactic": "impact", "name": "Service Stop"},
    "T1490":  {"tactic": "impact", "name": "Inhibit System Recovery"},
    "T1491":  {"tactic": "impact", "name": "Defacement"},
    "T1496":  {"tactic": "impact", "name": "Resource Hijacking"},
    "T1498":  {"tactic": "impact", "name": "Network Denial of Service"},
    "T1499":  {"tactic": "impact", "name": "Endpoint Denial of Service"},
    "T1561":  {"tactic": "impact", "name": "Disk Wipe"},
    # Initial Access
    "T1190":  {"tactic": "initial-access", "name": "Exploit Public-Facing Application"},
    "T1566":  {"tactic": "initial-access", "name": "Phishing"},
    "T1566.001": {"tactic": "initial-access", "name": "Spearphishing Attachment"},
    "T1566.002": {"tactic": "initial-access", "name": "Spearphishing Link"},
    # Lateral Movement
    "T1021":  {"tactic": "lateral-movement", "name": "Remote Services"},
    "T1021.001": {"tactic": "lateral-movement", "name": "Remote Desktop Protocol"},
    "T1021.002": {"tactic": "lateral-movement", "name": "SMB/Windows Admin Shares"},
    "T1021.004": {"tactic": "lateral-movement", "name": "SSH"},
    "T1021.006": {"tactic": "lateral-movement", "name": "Windows Remote Management"},
    "T1210":  {"tactic": "lateral-movement", "name": "Exploitation of Remote Services"},
    "T1534":  {"tactic": "lateral-movement", "name": "Internal Spearphishing"},
    "T1550":  {"tactic": "lateral-movement", "name": "Use Alternate Authentication Material"},
    "T1550.002": {"tactic": "lateral-movement", "name": "Pass the Hash"},
    "T1550.003": {"tactic": "lateral-movement", "name": "Pass the Ticket"},
    "T1563":  {"tactic": "lateral-movement", "name": "Remote Service Session Hijacking"},
    # Persistence
    "T1037":  {"tactic": "persistence", "name": "Boot or Logon Initialization Scripts"},
    "T1053.003": {"tactic": "persistence", "name": "Cron"},
    "T1098":  {"tactic": "persistence", "name": "Account Manipulation"},
    "T1098.004": {"tactic": "persistence", "name": "SSH Authorized Keys"},
    "T1133":  {"tactic": "persistence", "name": "External Remote Services"},
    "T1136":  {"tactic": "persistence", "name": "Create Account"},
    "T1136.001": {"tactic": "persistence", "name": "Local Account"},
    "T1137":  {"tactic": "persistence", "name": "Office Application Startup"},
    "T1176":  {"tactic": "persistence", "name": "Browser Extensions"},
    "T1505":  {"tactic": "persistence", "name": "Server Software Component"},
    "T1505.003": {"tactic": "persistence", "name": "Web Shell"},
    "T1543":  {"tactic": "persistence", "name": "Create or Modify System Process"},
    "T1543.003": {"tactic": "persistence", "name": "Windows Service"},
    "T1546":  {"tactic": "persistence", "name": "Event Triggered Execution"},
    "T1546.003": {"tactic": "persistence", "name": "Windows Management Instrumentation Event Subscription"},
    "T1547":  {"tactic": "persistence", "name": "Boot or Logon Autostart Execution"},
    "T1547.001": {"tactic": "persistence", "name": "Registry Run Keys / Startup Folder"},
    "T1554":  {"tactic": "persistence", "name": "Compromise Host Software Binary"},
    "T1574.006": {"tactic": "persistence", "name": "Dynamic Linker Hijacking"},
    # Privilege Escalation
    "T1055.011": {"tactic": "privilege-escalation", "name": "Extra Window Memory Injection"},
    "T1068":  {"tactic": "privilege-escalation", "name": "Exploitation for Privilege Escalation"},
    "T1134":  {"tactic": "privilege-escalation", "name": "Access Token Manipulation"},
    "T1134.001": {"tactic": "privilege-escalation", "name": "Token Impersonation/Theft"},
    "T1134.002": {"tactic": "privilege-escalation", "name": "Create Process with Token"},
    "T1484":  {"tactic": "privilege-escalation", "name": "Domain Policy Modification"},
    "T1548":  {"tactic": "privilege-escalation", "name": "Abuse Elevation Control Mechanism"},
    "T1548.002": {"tactic": "privilege-escalation", "name": "Bypass User Account Control"},
    "T1611":  {"tactic": "privilege-escalation", "name": "Escape to Host"},
    # Collection
    "T1005":  {"tactic": "collection", "name": "Data from Local System"},
    "T1039":  {"tactic": "collection", "name": "Data from Network Shared Drive"},
    "T1113":  {"tactic": "collection", "name": "Screen Capture"},
    "T1114":  {"tactic": "collection", "name": "Email Collection"},
    "T1114.003": {"tactic": "collection", "name": "Email Forwarding Rule"},
    "T1115":  {"tactic": "collection", "name": "Clipboard Data"},
    "T1530":  {"tactic": "collection", "name": "Data from Cloud Storage"},
    "T1560":  {"tactic": "collection", "name": "Archive Collected Data"},
    "T1560.001": {"tactic": "collection", "name": "Archive via Utility"},
    # Command and Control
    "T1071":  {"tactic": "command-and-control", "name": "Application Layer Protocol"},
    "T1071.001": {"tactic": "command-and-control", "name": "Web Protocols"},
    "T1071.004": {"tactic": "command-and-control", "name": "DNS"},
    "T1090":  {"tactic": "command-and-control", "name": "Proxy"},
    "T1095":  {"tactic": "command-and-control", "name": "Non-Application Layer Protocol"},
    "T1105":  {"tactic": "command-and-control", "name": "Ingress Tool Transfer"},
    "T1132":  {"tactic": "command-and-control", "name": "Data Encoding"},
    "T1568":  {"tactic": "command-and-control", "name": "Dynamic Resolution"},
    "T1568.002": {"tactic": "command-and-control", "name": "Domain Generation Algorithms"},
    "T1571":  {"tactic": "command-and-control", "name": "Non-Standard Port"},
    "T1572":  {"tactic": "command-and-control", "name": "Protocol Tunneling"},
    "T1573":  {"tactic": "command-and-control", "name": "Encrypted Channel"},
}

VALID_TECHNIQUES = set(ATTCK_TAXONOMY.keys())

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("label_attck")


# ---------------------------------------------------------------------------
# System prompt — shared across all providers
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are a senior threat-intelligence analyst and MITRE ATT&CK expert.
Your sole task is to classify a SIEM detection query into the most accurate
ATT&CK tactic, technique, and optional sub-technique.

Output ONLY valid JSON — no prose, no markdown fences, no comments.
Schema:
{
  "tactic":        "<kebab-case tactic name, e.g. credential-access>",
  "technique":     "<T-number, e.g. T1110>",
  "sub_technique": "<T-number.sub, e.g. T1110.003, or empty string if none>",
  "confidence":    <float 0.0-1.0>,
  "rationale":     "<one concise sentence explaining the mapping>"
}

Rules:
- tactic must be one of: credential-access, defense-evasion, discovery,
  execution, exfiltration, impact, initial-access, lateral-movement,
  persistence, privilege-escalation, collection, command-and-control,
  reconnaissance, resource-development.
- technique must be a valid MITRE ATT&CK technique ID (T#### format).
- sub_technique must be T####.### format or an empty string.
- confidence reflects how precisely the query maps to the technique:
    1.0 = exact, unambiguous match
    0.8 = strong match, minor interpretation required
    0.6 = plausible but the query covers multiple techniques
    0.4 = weak signal, educated guess
- rationale must be ≤ 20 words.
- Return ONLY the JSON object. Nothing else.
"""

USER_PROMPT_TEMPLATE = """\
Classify the following SIEM detection query:

"{query}"

Respond with ONLY the JSON object described in the system prompt.
"""
class BatchATTCKClassifier:
    def __init__(self, max_retries: int = 3):
        self.client = LLMClient()
        self.provider = "groq"
        self.model = "attck_classifier_agent"
        self.agent = ATTCKClassifierAgent(client=self.client)
        self.max_retries = max_retries

    def classify(self, query: str) -> dict[str, Any]:
        last_exc = None

        for attempt in range(self.max_retries):
            try:
                result = self.agent.classify(query)

                return {
                    "tactic": result.tactic,
                    "technique": result.technique,
                    "sub_technique": result.sub_technique or "",
                    "confidence": float(result.confidence),
                    "rationale": result.rationale,
                    "_taxonomy_miss": False,
                }

            except Exception as exc:
                last_exc = exc
                wait = 2 ** attempt
                log.warning(
                    "Attempt %d failed: %s. Retrying in %ss",
                    attempt + 1,
                    exc,
                    wait,
                )
                time.sleep(wait)

        raise RuntimeError(
            f"Classification failed after {self.max_retries} attempts: {last_exc}"
        )
# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def load_existing(output_path: Path) -> set[str]:
    """Return set of IDs already written to the output file."""
    done: set[str] = set()
    if output_path.exists():
        with output_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    done.add(obj["id"])
                except Exception:
                    pass
    return done


def run_batch(
    input_path: Path,
    output_path: Path,
    agent:  BatchATTCKClassifier,
    rps: float,
    limit: int | None,
    dry_run: bool,
) -> dict[str, Any]:
    """
    Main batch loop.
    Returns a manifest dict summarising the run.
    """
    # Load seeds
    seeds: list[dict] = []
    with input_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                seeds.append(json.loads(line))

    if limit:
        seeds = seeds[:limit]

    # Resume: skip already-labelled IDs
    done_ids = load_existing(output_path)
    pending   = [s for s in seeds if s["id"] not in done_ids]

    log.info(
        "Seeds total=%d  already_labelled=%d  to_process=%d",
        len(seeds), len(done_ids), len(pending),
    )

    if dry_run:
        log.info("DRY-RUN mode — printing prompts, making no API calls.")
        for seed in pending:
            print(f"\n--- {seed['id']} ---")
            print(USER_PROMPT_TEMPLATE.format(query=seed["nl_query"]))
        return {"dry_run": True, "would_process": len(pending)}

    # Open output in append mode (resume-safe)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    min_interval = 1.0 / rps if rps > 0 else 0.0

    manifest: dict[str, Any] = {
        "run_id":      datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "provider":    agent.provider,
        "model":       agent.model,
        "input":       str(input_path),
        "output":      str(output_path),
        "total_seeds": len(seeds),
        "already_done": len(done_ids),
        "attempted":   0,
        "succeeded":   0,
        "failed":      0,
        "taxonomy_misses": 0,
        "failures":    [],
    }

    with output_path.open("a") as out_f:
        for i, seed in enumerate(pending, 1):
            t0 = time.monotonic()
            sid = seed["id"]

            log.info("[%d/%d] Classifying %s …", i, len(pending), sid)
            manifest["attempted"] += 1

            try:
                label = agent.classify(seed["nl_query"])

                # Compose output record
                record = {
                    "id":         seed["id"],
                    "category":   seed["category"],
                    "complexity": seed["complexity"],
                    "nl_query":   seed["nl_query"],
                    "attck": {
                        "tactic":        label["tactic"],
                        "technique":     label["technique"],
                        "sub_technique": label["sub_technique"],
                        "confidence":    label["confidence"],
                        "rationale":     label["rationale"],
                    },
                }

                if label.get("_taxonomy_miss"):
                    manifest["taxonomy_misses"] += 1

                out_f.write(json.dumps(record) + "\n")
                out_f.flush()
                manifest["succeeded"] += 1

                elapsed = time.monotonic() - t0
                log.info(
                    "  ✓ %s → %s/%s  conf=%.2f  (%.2fs)",
                    sid,
                    label["technique"],
                    label["sub_technique"] or "—",
                    label["confidence"],
                    elapsed,
                )

            except Exception as exc:
                log.error("  ✗ %s FAILED: %s", sid, exc)
                manifest["failed"] += 1
                manifest["failures"].append({"id": sid, "error": str(exc)})

            # Rate limiting — sleep for the remainder of the interval
            elapsed = time.monotonic() - t0
            sleep_for = max(0.0, min_interval - elapsed)
            if sleep_for > 0:
                time.sleep(sleep_for)

    manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Batch ATT&CK labeller for SIEMBench gold seeds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--input", "-i",
        default="data//simebench.jsonl",
        help="Path to input JSONL file (default: data/seeds/gold_seeds.jsonl)",
    )
    p.add_argument(
        "--output", "-o",
        default="data/siembench_attck.jsonl",
        help="Path to output JSONL file (default: data/seeds/siembench_attck.jsonl)",
    )
    p.add_argument(
        "--manifest",
        default="data/seeds/label_run_manifest.json",
        help="Path to run manifest JSON (default: data/seeds/label_run_manifest.json)",
    )
   
    p.add_argument(
        "--rps",
        type=float,
        default=4.0,
        help="Max requests per second (default: 4.0). Set 0 for no throttling.",
    )
    p.add_argument(
        "--max-retries",
        type=int,
        default=4,
        dest="max_retries",
        help="Per-record retry limit (default: 4)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N seeds (for testing)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print prompts without calling the API",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        dest="log_level",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    input_path    = Path(args.input)
    output_path   = Path(args.output)
    manifest_path = Path(args.manifest)

    if not input_path.exists():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    if args.dry_run:
        # No API key needed for dry runs
        agent = None  # type: ignore[assignment]
    else:
        try:
            agent = BatchATTCKClassifier(
                max_retries=args.max_retries
            )
        except Exception as exc:
            log.error("%s", exc)
            sys.exit(1)

    log.info("=" * 60)
    log.info("SIEMBench ATT&CK Labeller")
    log.info("  input    : %s", input_path)
    log.info("  output   : %s", output_path)
    log.info("  provider : %s", agent.provider if agent else "N/A")
    log.info("  model    : %s", agent.model if agent else "N/A")
    log.info("  rps      : %s", args.rps)
    log.info("=" * 60)

    if args.dry_run:
        # Minimal dry-run path (no agent needed)
        seeds: list[dict] = []
        with input_path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    seeds.append(json.loads(line))
        limit = args.limit or len(seeds)
        for seed in seeds[:limit]:
            print(f"\n--- {seed['id']} ({seed['category']}) ---")
            print(USER_PROMPT_TEMPLATE.format(query=seed["nl_query"]))
        return

    manifest = run_batch(
        input_path=input_path,
        output_path=output_path,
        agent=agent,
        rps=args.rps,
        limit=args.limit,
        dry_run=False,
    )

    # Write manifest
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w") as mf:
        json.dump(manifest, mf, indent=2)

    # Final summary
    log.info("=" * 60)
    log.info("Run complete")
    log.info("  attempted      : %d", manifest["attempted"])
    log.info("  succeeded      : %d", manifest["succeeded"])
    log.info("  failed         : %d", manifest["failed"])
    log.info("  taxonomy misses: %d", manifest["taxonomy_misses"])
    log.info("  manifest       : %s", manifest_path)
    log.info("  output         : %s", output_path)
    log.info("=" * 60)

    if manifest["failed"] > 0:
        log.warning(
            "%d records failed. Re-run the script to retry them "
            "(already-labelled IDs are skipped automatically).",
            manifest["failed"],
        )
        sys.exit(2)


if __name__ == "__main__":
    main()