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
_BUILTIN_SEEDS = [
    # Authentication
    {"nl_query": "Detect failed SSH login attempts from a single IP address exceeding 10 failures in 5 minutes", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Alert on successful login after multiple consecutive failures (brute-force success)", "category": "authentication", "complexity": "high"},
    {"nl_query": "Find accounts with logins from more than 3 different countries within 24 hours", "category": "authentication", "complexity": "high"},
    {"nl_query": "Detect password spray attacks targeting multiple accounts from one source IP", "category": "authentication", "complexity": "high"},
    {"nl_query": "Alert when a privileged account logs in outside business hours", "category": "authentication", "complexity": "medium"},
    {"nl_query": "Find all failed Windows logon events with event ID 4625 in the last hour", "category": "authentication", "complexity": "low"},
    {"nl_query": "Detect impossible travel: same account authenticating from two countries less than an hour apart", "category": "authentication", "complexity": "high"},
    {"nl_query": "Alert on MFA being disabled for a user account immediately followed by a login", "category": "authentication", "complexity": "high"},
    # Network
    {"nl_query": "Detect port scanning activity: more than 50 unique destination ports from one source in 1 minute", "category": "network", "complexity": "medium"},
    {"nl_query": "Alert on DNS queries to known malicious domains", "category": "network", "complexity": "medium"},
    {"nl_query": "Find large outbound data transfers over 100 MB in a single session", "category": "network", "complexity": "medium"},
    {"nl_query": "Detect connections to Tor exit nodes", "category": "network", "complexity": "low"},
    {"nl_query": "Alert on SMB lateral movement: connections to more than 5 internal hosts within 10 minutes", "category": "network", "complexity": "high"},
    {"nl_query": "Detect beaconing: a host contacting the same external IP at regular intervals over 6 hours", "category": "network", "complexity": "high"},
    {"nl_query": "Alert on outbound traffic on non-standard high ports from a server host", "category": "network", "complexity": "low"},
    # Process / Execution
    {"nl_query": "Detect PowerShell execution with encoded command-line arguments", "category": "process", "complexity": "medium"},
    {"nl_query": "Alert on processes spawned by Office applications (Word, Excel) executing cmd or powershell", "category": "process", "complexity": "high"},
    {"nl_query": "Find mimikatz-like activity: lsass.exe memory reads by non-system processes", "category": "process", "complexity": "high"},
    {"nl_query": "Detect execution of unsigned binaries from temp or downloads directories", "category": "process", "complexity": "medium"},
    {"nl_query": "Alert on living-off-the-land binaries such as certutil or rundll32 making outbound network connections", "category": "process", "complexity": "high"},
    # File
    {"nl_query": "Alert on mass file deletion: more than 100 files deleted in under 60 seconds (ransomware indicator)", "category": "file", "complexity": "high"},
    {"nl_query": "Detect creation of executable files in system32 directory by non-system accounts", "category": "file", "complexity": "medium"},
    {"nl_query": "Find mass file renames to a common ransomware extension within a short time window", "category": "file", "complexity": "high"},
    # Persistence / Privilege
    {"nl_query": "Detect new scheduled tasks created by non-administrative users", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Alert when a user account is added to the Domain Admins group", "category": "privilege", "complexity": "low"},
    {"nl_query": "Find registry run key modifications that add persistence", "category": "persistence", "complexity": "medium"},
    {"nl_query": "Detect creation of a new local administrator account outside change-management hours", "category": "privilege", "complexity": "medium"},
    # Exfiltration
    {"nl_query": "Detect unusually high number of emails sent by a single user in one hour", "category": "exfiltration", "complexity": "medium"},
    {"nl_query": "Alert on FTP uploads larger than 50 MB to external IPs", "category": "exfiltration", "complexity": "low"},
    {"nl_query": "Find data uploaded to a personal cloud storage domain not on the corporate allow-list", "category": "exfiltration", "complexity": "medium"},
    # Anomaly / UEBA
    {"nl_query": "Find users accessing an abnormally high number of files compared to their 30-day baseline", "category": "anomaly", "complexity": "high"},
    {"nl_query": "Detect service account making interactive logins", "category": "anomaly", "complexity": "low"},
    {"nl_query": "Alert on any process making DNS requests at a rate exceeding 1000 per minute (DNS tunnelling)", "category": "anomaly", "complexity": "high"},
    # Cloud / IAM
    {"nl_query": "Detect creation of an access key for an IAM user that has been inactive for over 90 days", "category": "cloud", "complexity": "medium"},
    {"nl_query": "Alert on an S3 bucket policy change that makes a bucket publicly readable", "category": "cloud", "complexity": "high"},
    {"nl_query": "Find console logins to a cloud account from a region the organization has never used before", "category": "cloud", "complexity": "high"},
    {"nl_query": "Detect disabling of cloud audit logging (e.g. CloudTrail) by any principal", "category": "cloud", "complexity": "medium"},
    # Web / API
    {"nl_query": "Detect SQL injection patterns in web server access logs", "category": "web", "complexity": "medium"},
    {"nl_query": "Alert on a single API key making more than 1000 requests per minute", "category": "web", "complexity": "low"},
    {"nl_query": "Find repeated 401 and 403 responses from the same IP against an authentication endpoint", "category": "web", "complexity": "medium"},
    # Malware / C2
    {"nl_query": "Detect a process writing to and then executing a file from a world-writable directory", "category": "malware", "complexity": "high"},
    {"nl_query": "Alert on outbound connections to a domain registered within the last 7 days", "category": "malware", "complexity": "medium"},
    # Email / Phishing
    {"nl_query": "Detect creation of an inbox forwarding rule to an external email address", "category": "email", "complexity": "medium"},
    {"nl_query": "Alert when a user clicks a link in an email later confirmed as phishing", "category": "email", "complexity": "low"},
    # Insider / Data handling
    {"nl_query": "Find a user downloading a large volume of files shortly before their termination date", "category": "insider", "complexity": "high"},
    {"nl_query": "Detect printing of documents tagged as confidential outside business hours", "category": "insider", "complexity": "medium"},
    # Container / Kubernetes
    {"nl_query": "Alert on a container running with privileged mode enabled", "category": "container", "complexity": "medium"},
    {"nl_query": "Detect a kubectl exec into a production pod from an IP outside the corporate VPN", "category": "container", "complexity": "high"},
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
    from src.agents.parser_agent import ParserAgent

    nl_query = seed["nl_query"]
    t0 = time.monotonic()

    try:
        ir = ParserAgent().parse(nl_query)
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
        n_groups = len({r["_internal"]["source_seed_id"] for r in recs})
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