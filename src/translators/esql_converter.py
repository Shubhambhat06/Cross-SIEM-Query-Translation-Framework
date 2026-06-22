"""
ES|QL Converter — bridges human-authored EQL/KQL syntax to executable ES|QL.

Motivation
----------
ElasticTranslator (src/translators/elastic.py) emits EQL or KQL text — the
syntax a security engineer would type into Kibana's EQL rule editor or
Discover search bar. That text is not, by itself, something a client can
hand to `Elasticsearch.search()`: EQL has its own `_eql/search` API, and
KQL is a Kibana-side query-string convenience layer, not a wire protocol.

ES|QL (the Elasticsearch Query Language introduced in Elastic 8.11+) is a
single piped syntax that the standard `_query` REST endpoint accepts
directly. This module performs a best-effort, syntax-level conversion of
ElasticTranslator's EQL output into ES|QL so the result can actually be
submitted for execution — closing the gap identified during translator
review between "renders correct platform syntax" and "is executable".

Scope and honesty about limitations
------------------------------------
This is a *syntax bridge*, not a semantic re-implementation of EQL. It
handles the constructs ElasticTranslator is known to emit (event-category
base filter, boolean and/or chains, `stats`/`where`/`sort`/`head` pipes,
the EQL-specific functions `like~`, `match()`, `in (...)`). It does NOT
attempt to convert EQL `sequence` correlation queries — temporal sequence
matching has no direct ES|QL equivalent today and is intentionally left
untouched (raises ESQLConversionError rather than emitting a silently
wrong result). KQL filter-only input is passed through a separate,
narrower path since KQL has no pipe structure to begin with.

Place at: src/translators/esql_converter.py

Usage:
    from src.translators.esql_converter import ElasticQueryConverter

    eql_text = elastic_translator.translate(ir)
    esql     = ElasticQueryConverter.to_esql(eql_text, index_pattern="nlsiem-test")
    # esql is now safe to POST to /_query
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field

from src.utils.exceptions import TranslationError
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── EQL event categories recognised on the base filter line ───────────────
_EQL_CATEGORIES = (
    "authentication", "network", "process", "file",
    "registry", "dns", "web", "any",
)

# ── ECS field → flattened identifier rules ─────────────────────────────────
# ES|QL accepts dotted ECS field names directly (e.g. source.ip), so no
# rewriting is required there. What DOES need rewriting are EQL-only
# functions and operators with no direct ES|QL surface syntax.
_EQL_COMPARISON_PASSTHROUGH = {"==", "!=", ">", ">=", "<", "<="}


@dataclass
class ConversionResult:
    """Structured result of an EQL/KQL → ES|QL conversion attempt."""

    esql:              str
    source_dialect:    str                 # "eql" | "kql"
    index_pattern:     str
    warnings:          list[str] = dc_field(default_factory=list)
    fully_translated:  bool      = True     # False if any construct was approximated

    def to_dict(self) -> dict:
        return {
            "esql":             self.esql,
            "source_dialect":   self.source_dialect,
            "index_pattern":    self.index_pattern,
            "warnings":         self.warnings,
            "fully_translated": self.fully_translated,
        }


class ESQLConversionError(TranslationError):
    """Raised when EQL/KQL input cannot be safely converted to ES|QL."""

    def __init__(self, reason: str, query: str = ""):
        super().__init__(
            platform="elastic",
            reason=f"ES|QL conversion failed: {reason}",
        )
        self.query_excerpt = query[:200]


class ElasticQueryConverter:
    """
    Converts ElasticTranslator's EQL/KQL output into executable ES|QL.

    All methods are stateless static methods — this is a pure syntax
    transform with no configuration beyond the target index pattern.
    """

    # ── EQL function/operator → ES|QL equivalents ──────────────────────────
    # Order matters: longer/more specific patterns first.
    _EQL_FUNCTION_REWRITES: list[tuple[re.Pattern, str]] = [
        # match(field, "regex")  →  field RLIKE "regex"
        (re.compile(r'match\(\s*([\w.]+)\s*,\s*"([^"]*)"\s*\)'), r'\1 RLIKE "\2"'),
        # field like~ "*val*"    →  field LIKE "*val*"   (ES|QL LIKE is case-insensitive by default for keyword fields)
        (re.compile(r'([\w.]+)\s+like~\s*"([^"]*)"'), r'\1 LIKE "\2"'),
        # field like "*val*"     →  field LIKE "*val*"
        (re.compile(r'([\w.]+)\s+like\s+"([^"]*)"'), r'\1 LIKE "\2"'),
    ]

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    @staticmethod
    def to_esql(query: str, index_pattern: str = "nlsiem-test") -> str:
        """
        Convert EQL or KQL text into an executable ES|QL query string.

        Args:
            query:         Output of ElasticTranslator.translate(ir).
            index_pattern: Index pattern for the ES|QL FROM clause
                           (default: "nlsiem-test", matching common ECS-based
                           data stream naming conventions).

        Returns:
            A single ES|QL query string, ready to POST to the
            Elasticsearch `_query` endpoint.

        Raises:
            ESQLConversionError: If the input is empty, is an EQL sequence
                (no ES|QL equivalent), or could not be parsed at all.
        """
        
        result = ElasticQueryConverter.convert(query, index_pattern=index_pattern)
        if result.warnings:
            log.warning(
                "ES|QL conversion completed with caveats",
                extra={"warnings": result.warnings, "fully_translated": result.fully_translated},
            )
        return result.esql

    @staticmethod
    def convert(query: str, index_pattern: str = "nlsiem-test") -> ConversionResult:
        """
        Full conversion entry point returning a ConversionResult with
        diagnostics, rather than just the bare string. Prefer this over
        to_esql() when you need to know whether the conversion was exact
        or approximated (e.g. for evaluation/error-analysis logging).

        Args:
            query:         Raw EQL or KQL text from ElasticTranslator.
            index_pattern: Index pattern for the FROM clause.

        Returns:
            ConversionResult with the ES|QL string and conversion metadata.

        Raises:
            ESQLConversionError: For unsupported or unparseable input.
        """
        raw_lines = [ln.strip() for ln in (query or "").splitlines() if ln.strip()]

        # Drop translator-emitted documentation comments (// ...) — these
        # carry information (time range, enrichment notes) that has no
        # ES|QL syntactic representation and must be handled by the caller
        # via the API request body, not the query string itself.
        # Comments may appear as a whole line OR trailing after real syntax
        # on the same line (e.g. the EQL base-filter line emitted by
        # ElasticTranslator._build_eql_base, which appends a "// set ..."
        # note after the where-clause on the SAME line) — both forms are
        # stripped here so neither leaks into the structural parse below.
        comment_lines: list[str] = []
        lines: list[str] = []
        for ln in raw_lines:
            comment_idx = ln.find("//")
            if comment_idx == -1:
                lines.append(ln)
                continue
            code_part    = ln[:comment_idx].rstrip()
            comment_part = ln[comment_idx:].strip()
            if comment_part:
                comment_lines.append(comment_part)
            if code_part:
                lines.append(code_part)

        if not lines:
            raise ESQLConversionError("empty query after stripping comments", query)

        first_line = lines[0]
        first_word = first_line.split()[0].lower() if first_line.split() else ""

        if first_word == "sequence":
            raise ESQLConversionError(
                "EQL 'sequence' correlation queries have no direct ES|QL "
                "equivalent and are not converted by this module",
                query,
            )

        if first_word in _EQL_CATEGORIES:
            result = ElasticQueryConverter._convert_eql(
                lines, index_pattern=index_pattern, event_category=first_word,
            )
        else:
            # Not an EQL base line → treat as KQL filter-only text.
            result = ElasticQueryConverter._convert_kql(
                lines, index_pattern=index_pattern,
            )

        for c in comment_lines:
            result.warnings.append(
                f"Source comment not representable in ES|QL syntax — "
                f"apply via request parameters instead: {c.lstrip('/').strip()}"
            )

        return result

    # ─────────────────────────────────────────────
    # EQL → ES|QL
    # ─────────────────────────────────────────────

    @staticmethod
    def _convert_eql(
        lines:          list[str],
        index_pattern:  str,
        event_category: str,
    ) -> ConversionResult:
        """
        Convert an EQL event-filter (+ optional stats/where/sort/head
        pipeline) into ES|QL.

        EQL:
            authentication where event.outcome == "failure"
              and source.ip != null
            | stats count(*) as attempt_count by source.ip
            | where attempt_count > 50
            | sort attempt_count desc
            | head 100

        ES|QL:
            FROM nlsiem-test
            | WHERE event.category == "authentication"
                AND event.outcome == "failure"
                AND source.ip IS NOT NULL
            | STATS attempt_count = COUNT(*) BY source.ip
            | WHERE attempt_count > 50
            | SORT attempt_count DESC
            | LIMIT 100
        """
        warnings: list[str] = []
        esql_lines = [f"FROM {index_pattern}"]

        first_line   = lines[0]
        where_clause = ""
        if "where" in first_line.lower():
            # Split only on the first occurrence of the word "where"
            idx = first_line.lower().index("where")
            where_clause = first_line[idx + len("where"):].strip()

        # Continuation lines of the base filter (multi-line "and ..." chains)
        # are folded in until we hit the first pipe-prefixed line.
        body_lines      = []
        remaining_lines = []
        in_base_filter  = True
        for ln in lines[1:]:
            if in_base_filter and not ln.startswith("|"):
                body_lines.append(ln)
            else:
                in_base_filter = False
                remaining_lines.append(ln)

        full_condition = " ".join([where_clause] + body_lines).strip()

        where_segments = [f'event.category == "{event_category}"'] if event_category != "any" else []
        if full_condition and full_condition.lower() != "true":
            translated_condition, cond_warnings = ElasticQueryConverter._translate_condition(full_condition)
            warnings.extend(cond_warnings)
            where_segments.append(translated_condition)

        if where_segments:
            esql_lines.append("| WHERE " + "\n    AND ".join(where_segments))

        # ── Pipe stages: stats / where / sort / head ──────────────────────
        for ln in remaining_lines:
            stage, stage_warnings = ElasticQueryConverter._convert_pipe_stage(ln)
            warnings.extend(stage_warnings)
            if stage:
                esql_lines.append(stage)

        return ConversionResult(
            esql             = "\n".join(esql_lines),
            source_dialect   = "eql",
            index_pattern    = index_pattern,
            warnings         = warnings,
            fully_translated = len(warnings) == 0,
        )

    @staticmethod
    def _convert_pipe_stage(line: str) -> tuple[str, list[str]]:
        """Convert a single EQL pipe stage (`| stats ...` etc.) to ES|QL."""
        warnings: list[str] = []
        body = line.strip()
        if not body.startswith("|"):
            return "", [f"Unrecognised non-pipe continuation line ignored: {line!r}"]

        body = body[1:].strip()
        keyword = body.split(None, 1)[0].lower() if body.split() else ""
        rest    = body[len(keyword):].strip() if keyword else ""

        if keyword == "stats":
            esql_stats, w = ElasticQueryConverter._convert_stats(rest)
            warnings.extend(w)
            return f"| {esql_stats}", warnings

        if keyword == "where":
            translated, w = ElasticQueryConverter._translate_condition(rest)
            warnings.extend(w)
            return f"| WHERE {translated}", warnings

        if keyword == "sort":
            # EQL: "field desc"  →  ES|QL: "field DESC"
            parts = rest.rsplit(None, 1)
            if len(parts) == 2 and parts[1].lower() in ("asc", "desc"):
                return f"| SORT {parts[0]} {parts[1].upper()}", warnings
            return f"| SORT {rest}", warnings

        if keyword in ("head", "tail"):
            # ES|QL has LIMIT, not HEAD/TAIL; TAIL has no exact equivalent —
            # approximate with LIMIT and flag it explicitly.
            if keyword == "tail":
                warnings.append(
                    "EQL 'tail N' (last N events) approximated as ES|QL "
                    "'LIMIT N' — ES|QL LIMIT takes the first N rows of the "
                    "current sort order, not the last N; add an explicit "
                    "SORT before this LIMIT if tail semantics are required."
                )
            return f"| LIMIT {rest}", warnings

        warnings.append(f"Unrecognised EQL pipe command '{keyword}' passed through unmodified")
        return f"| {body}", warnings

    @staticmethod
    def _convert_stats(stats_body: str) -> tuple[str, list[str]]:
        """
        Convert EQL `count(*) as alias[, ...] [by field, ...]` into
        ES|QL `alias = COUNT(*)[, ...] [BY field, ...]`.

        ES|QL STATS uses `alias = FUNCTION(...)` ordering (alias first),
        the reverse of EQL's `FUNCTION(...) as alias`.
        """
        warnings: list[str] = []

        # Split off the BY clause if present
        by_match  = re.search(r"\bby\b", stats_body, flags=re.IGNORECASE)
        agg_part  = stats_body[: by_match.start()].strip() if by_match else stats_body.strip()
        by_part   = stats_body[by_match.end():].strip() if by_match else ""

        # agg_part may contain multiple "fn(...) as alias" separated by commas
        agg_exprs = [a.strip() for a in agg_part.split(",") if a.strip()]
        rewritten_aggs = []

        # EQL function name → ES|QL function name (most are identical;
        # unique_count is EQL-specific and maps to ES|QL's COUNT_DISTINCT)
        fn_rewrites = {
            "unique_count": "COUNT_DISTINCT",
            "count":        "COUNT",
            "sum":          "SUM",
            "avg":          "AVG",
            "min":          "MIN",
            "max":          "MAX",
            "values":       "VALUES",
        }

        agg_pattern = re.compile(
            r"(?P<fn>\w+)\((?P<arg>[^)]*)\)\s+as\s+(?P<alias>\w+)",
            flags=re.IGNORECASE,
        )
        for expr in agg_exprs:
            m = agg_pattern.match(expr)
            if not m:
                warnings.append(f"Could not parse STATS expression '{expr}' — passed through unmodified")
                rewritten_aggs.append(expr)
                continue
            fn    = m.group("fn").lower()
            arg   = m.group("arg").strip() or "*"
            alias = m.group("alias")
            esql_fn = fn_rewrites.get(fn, fn.upper())
            rewritten_aggs.append(f"{alias} = {esql_fn}({arg})")

        result = "STATS " + ", ".join(rewritten_aggs)
        if by_part:
            result += f" BY {by_part}"
        return result, warnings

    @staticmethod
    def _translate_condition(condition: str) -> tuple[str, list[str]]:
        """
        Rewrite EQL-specific functions/operators inside a boolean condition
        into their ES|QL equivalents.

        Handles, in order:
          match(field, "regex")  → field RLIKE "regex"
          field like~ "pattern"  → field LIKE "pattern"
          field like "pattern"   → field LIKE "pattern"
          field in (a, b, c)     → field IN (a, b, c)        [case-normalised]
          field not in (a, b)    → field NOT IN (a, b)
          field != null          → field IS NOT NULL
          field == null          → field IS NULL
          and / or                → AND / OR                  [word-boundary safe]
        """
        warnings: list[str] = []
        text = condition

        for pattern, repl in ElasticQueryConverter._EQL_FUNCTION_REWRITES:
            text = pattern.sub(repl, text)

        # null comparisons
        text = re.sub(r'([\w.]+)\s*!=\s*null\b', r'\1 IS NOT NULL', text, flags=re.IGNORECASE)
        text = re.sub(r'([\w.]+)\s*==\s*null\b',  r'\1 IS NULL',     text, flags=re.IGNORECASE)

        # in / not in keyword casing (ES|QL keywords are case-insensitive but
        # uppercasing keeps generated output consistent with STATS/WHERE/SORT)
        text = re.sub(r'\bnot\s+in\b', 'NOT IN', text, flags=re.IGNORECASE)
        text = re.sub(r'\bin\b',       'IN',     text, flags=re.IGNORECASE)

        # boolean joiners — word-boundary guarded so we don't touch
        # substrings like "android" or field names containing "and"
        text = re.sub(r'\band\b', 'AND', text, flags=re.IGNORECASE)
        text = re.sub(r'\bor\b',  'OR',  text, flags=re.IGNORECASE)
        text = re.sub(r'\bnot\b', 'NOT', text, flags=re.IGNORECASE)

        # Flag any remaining EQL-only constructs we don't yet rewrite,
        # so silent mistranslation never passes as a clean conversion.
        if re.search(r'\bcidrMatch\s*\(', text, flags=re.IGNORECASE):
            warnings.append(
                "EQL cidrMatch() has no direct ES|QL equivalent in this "
                "converter version — verify CIDR conditions manually"
            )
        if re.search(r'\bwildcard\s*\(', text, flags=re.IGNORECASE):
            warnings.append(
                "EQL wildcard() function passed through unmodified — "
                "verify manually against ES|QL LIKE semantics"
            )

        return text.strip(), warnings

    # ─────────────────────────────────────────────
    # KQL → ES|QL  (filter-only path)
    # ─────────────────────────────────────────────

    @staticmethod
    def _convert_kql(lines: list[str], index_pattern: str) -> ConversionResult:
        """
        Convert KQL filter-only text (`field: "value" AND ...`) into ES|QL.

        KQL has no pipe stages by construction (ElasticTranslator only
        emits KQL for the FILTER-only action), so this path is a single
        WHERE clause built from colon-syntax field:value pairs.
        """
        warnings: list[str] = []
        kql_text = " ".join(lines).strip()

        if kql_text == "*":
            return ConversionResult(
                esql           = f"FROM {index_pattern}",
                source_dialect = "kql",
                index_pattern  = index_pattern,
                warnings       = [],
            )

        # field: "value"   → field == "value"
        # field: *value*   → field LIKE "*value*"
        # NOT field: "v"   → NOT field == "v"
        def _rewrite_pair(match: re.Match) -> str:
            negate = match.group("neg") or ""
            field  = match.group("field")
            value  = match.group("value").strip()

            if value.startswith("*") or value.endswith("*"):
                # already quoted or bare wildcard token
                value_str = value if value.startswith('"') else f'"{value}"'
                expr = f"{field} LIKE {value_str}"
            elif value.startswith("("):
                # list membership e.g. ("a" or "b") — convert OR-list to IN(...)
                inner = value.strip("()")
                items = [v.strip() for v in re.split(r'\s+or\s+', inner, flags=re.IGNORECASE)]
                expr  = f"{field} IN ({', '.join(items)})"
            else:
                value_str = value if value.startswith('"') else f'"{value}"' if not value.replace(".", "", 1).isdigit() else value
                expr = f"{field} == {value_str}"

            return f"{negate}{expr}"

        pair_pattern = re.compile(
            r'(?P<neg>NOT\s+)?(?P<field>[\w.]+):\s*(?P<value>"[^"]*"|\([^)]*\)|\*?[\w.\-*]+\*?)',
        )
        rewritten = pair_pattern.sub(lambda m: _rewrite_pair(m), kql_text)

        # Normalise boolean joiners to ES|QL casing
        rewritten = re.sub(r'\bAND\b', 'AND', rewritten)
        rewritten = re.sub(r'\bOR\b',  'OR',  rewritten)
        rewritten = re.sub(r'^NOT\s+\(', '!(', rewritten)  # leading NOT(...) — left for manual review
        if rewritten.startswith("!("):
            warnings.append(
                "Leading NOT(...) group from KQL retained as-is — verify "
                "ES|QL boolean negation placement manually"
            )

        # Range comparisons (field >= N) pass through unchanged — already
        # valid ES|QL syntax.

        esql = f"FROM {index_pattern}\n| WHERE {rewritten}"

        return ConversionResult(
            esql             = esql,
            source_dialect   = "kql",
            index_pattern    = index_pattern,
            warnings         = warnings,
            fully_translated = len(warnings) == 0,
        )