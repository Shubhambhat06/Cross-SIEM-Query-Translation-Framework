"""
ATT&CK Taxonomy Loader

Parses the MITRE ATT&CK STIX bundle and builds three indexes:
    - tactics:       {tactic_id: TacticEntry}
    - techniques:    {technique_id: TechniqueEntry}
    - sub_techniques:{sub_technique_id: SubTechniqueEntry}

Used by ATT&CKClassifierAgent for chain-of-thought reasoning over
the full taxonomy without needing to embed the entire bundle in a prompt.

Usage:
    from src.knowledge_base.mitre.attck_taxonomy_loader import ATTCKTaxonomyLoader
    loader = ATTCKTaxonomyLoader()
    t = loader.get_technique("T1110")
    print(t.name, t.tactic_names)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BUNDLE_PATH = Path("knowledge_base/mitre/enterprise-attack.json")


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class TacticEntry:
    tactic_id:   str
    name:        str
    shortname:   str          # e.g. "lateral-movement"
    description: str


@dataclass
class TechniqueEntry:
    technique_id:  str        # e.g. "T1110"
    name:          str
    description:   str
    tactic_names:  list[str]  # e.g. ["credential-access"]
    is_subtechnique: bool = False
    parent_id:     str | None = None   # set for sub-techniques e.g. "T1110"
    platforms:     list[str] = field(default_factory=list)
    detection:     str = ""
    # (improved) precomputed at load time so search_techniques() never has
    # to re-tokenize the same name/description text on every single call.
    _name_tokens:  frozenset[str] = field(default_factory=frozenset, repr=False, compare=False)
    _desc_tokens:  frozenset[str] = field(default_factory=frozenset, repr=False, compare=False)


class ATTCKTaxonomyLoaderError(Exception):
    """Raised when the MITRE ATT&CK bundle can't be loaded or parsed."""


# ── Loader ────────────────────────────────────────────────────────────────

class ATTCKTaxonomyLoader:
    """
    Loads and indexes the MITRE ATT&CK STIX bundle.

    Indexes built on first instantiation are cached in-process.
    Pass bundle_path to override the default location.
    """

    def __init__(self, bundle_path: Path = BUNDLE_PATH) -> None:
        self._bundle_path = bundle_path
        self._tactics:        dict[str, TacticEntry]    = {}
        self._techniques:     dict[str, TechniqueEntry] = {}
        self._sub_techniques: dict[str, TechniqueEntry] = {}
        self._name_index:     dict[str, str]            = {}  # lowercase name → id

        # (improved) secondary lookup indexes for get_tactic(), so it's an
        # O(1) dict lookup instead of an O(n) linear scan over every tactic
        # on every single call. Built once in _load().
        self._tactic_by_id:        dict[str, TacticEntry] = {}
        self._tactic_by_shortname: dict[str, TacticEntry] = {}
        self._tactic_by_name:      dict[str, TacticEntry] = {}

        # (improved) combined technique + sub-technique list, built once,
        # so search_techniques() doesn't re-concatenate two dict.values()
        # views into a fresh list on every call.
        self._all_searchable: list[TechniqueEntry] = []

        self._load()

    # ── Public API ────────────────────────────────────────────────────────

    def get_tactic(self, tactic_id_or_name: str) -> TacticEntry | None:
        """Look up a tactic by ID (TA0001), shortname (lateral-movement),
        or full display name — all as O(1) dict lookups."""
        key = tactic_id_or_name.lower().replace(" ", "-")
        return (
            self._tactic_by_id.get(key)
            or self._tactic_by_shortname.get(key)
            or self._tactic_by_name.get(key)
        )

    def get_technique(self, technique_id: str) -> TechniqueEntry | None:
        """Look up a technique or sub-technique by ID (T1110 or T1110.001)."""
        tid = technique_id.upper().strip()
        return self._techniques.get(tid) or self._sub_techniques.get(tid)

    def get_technique_by_name(self, name: str) -> TechniqueEntry | None:
        """
        (new) Look up a technique/sub-technique by its exact display name,
        case-insensitive — e.g. "Password Guessing" -> T1110.001.

        This uses `_name_index`, which was built during _load() in the
        original code but never actually exposed through any public method
        — dead weight that did nothing. Wiring it up here makes it useful
        for fuzzy/manual lookups (e.g. tooling, tests, CLI debugging)
        without touching the ID-based lookup path anything else relies on.
        """
        tid = self._name_index.get(name.strip().lower())
        return self.get_technique(tid) if tid else None

    def search_techniques(self, query: str, top_k: int = 10) -> list[TechniqueEntry]:
        """
        Simple keyword search over technique names and descriptions.
        Returns up to top_k results ranked by match quality.
        Used by the Classifier Agent to narrow candidates before CoT reasoning.
        """
        query_lower = query.lower()
        tokens = set(re.findall(r"\b\w+\b", query_lower))

        scored: list[tuple[int, TechniqueEntry]] = []
        # (improved) iterate the precomputed combined list instead of
        # concatenating self._techniques.values() + self._sub_techniques.values()
        # into a brand-new list on every single call.
        for tech in self._all_searchable:
            score = 0
            name_lower = tech.name.lower()

            # Exact name match gets highest weight
            if query_lower in name_lower:
                score += 10
            # (improved) token overlap now reuses tokens computed once at
            # load time (tech._name_tokens / tech._desc_tokens) instead of
            # re-running re.findall() over the same description text on
            # every search call — this is the expensive part when there
            # are ~700 techniques and search_techniques() is called once
            # per classification.
            score += len(tokens & tech._name_tokens) * 3
            score += len(tokens & tech._desc_tokens)

            if score > 0:
                scored.append((score, tech))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored[:top_k]]

    def get_techniques_for_tactic(self, tactic_shortname: str) -> list[TechniqueEntry]:
        """Return all techniques (not sub-techniques) belonging to a tactic."""
        return [
            t for t in self._techniques.values()
            if tactic_shortname.lower() in [n.lower() for n in t.tactic_names]
            and not t.is_subtechnique
        ]

    def get_sub_techniques(self, parent_id: str) -> list[TechniqueEntry]:
        """Return all sub-techniques for a parent technique ID."""
        return [
            s for s in self._sub_techniques.values()
            if s.parent_id == parent_id.upper()
        ]

    def all_tactics(self) -> list[TacticEntry]:
        return list(self._tactics.values())

    def all_techniques(self) -> list[TechniqueEntry]:
        return list(self._techniques.values())

    def summary(self) -> dict:
        return {
            "tactics":        len(self._tactics),
            "techniques":     len(self._techniques),
            "sub_techniques": len(self._sub_techniques),
            "bundle_path":    str(self._bundle_path),
        }

    # ── Internal loading ──────────────────────────────────────────────────

    @staticmethod
    def _extract_mitre_external_id(ext_refs: list[dict]) -> str:
        """
        (new, shared helper) Pull the MITRE ATT&CK ID out of a STIX object's
        `external_references` list, preferring the entry explicitly sourced
        from "mitre-attack" — the same filtering technique's already used,
        now shared with tactics instead of tactics using a naive `[0]`.

        Returns "" if no matching reference exists (including when the
        list is present but empty), instead of raising IndexError.
        """
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id", "")
        # Fall back to the first reference's external_id if none was
        # explicitly tagged "mitre-attack" but a reference does exist —
        # still never indexes into an empty list.
        if ext_refs:
            return ext_refs[0].get("external_id", "")
        return ""

    def _load(self) -> None:
        if not self._bundle_path.exists():
            raise ATTCKTaxonomyLoaderError(
                f"MITRE ATT&CK bundle not found at '{self._bundle_path}'. "
                f"Download enterprise-attack.json from MITRE's attack-stix-data "
                f"repository and place it at this path, or pass bundle_path= "
                f"to ATTCKTaxonomyLoader()."
            )

        try:
            with open(self._bundle_path, encoding="utf-8") as f:
                bundle = json.load(f)
        except json.JSONDecodeError as exc:
            raise ATTCKTaxonomyLoaderError(
                f"MITRE ATT&CK bundle at '{self._bundle_path}' is not valid JSON: {exc}"
            ) from exc

        objects = bundle.get("objects", [])

        # Pass 1: index tactics (x-mitre-tactic objects)
        for obj in objects:
            if obj.get("type") != "x-mitre-tactic":
                continue

            # (fixed) previously: obj.get("external_references", [{}])[0]
            # — that default only applies when the KEY is missing. If the
            # key is present but an empty list (legal, happens in real
            # STIX data), `[][0]` raises IndexError and takes down loading
            # of the ENTIRE taxonomy over a single malformed tactic entry.
            # Reproduced and confirmed as a real crash before this fix.
            tid = self._extract_mitre_external_id(obj.get("external_references", []))
            if not tid:
                continue

            entry = TacticEntry(
                tactic_id   = tid,
                name        = obj.get("name", ""),
                shortname   = obj.get("x_mitre_shortname", ""),
                description = obj.get("description", "")[:500],
            )
            self._tactics[tid] = entry

            # (improved) build the O(1) lookup indexes used by get_tactic()
            self._tactic_by_id[tid.lower()] = entry
            if entry.shortname:
                self._tactic_by_shortname[entry.shortname.lower()] = entry
            if entry.name:
                self._tactic_by_name[entry.name.lower()] = entry

        # Pass 2: index techniques and sub-techniques (attack-pattern objects)
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue

            ext_refs = obj.get("external_references", [])
            tech_id  = self._extract_mitre_external_id(ext_refs)

            if not tech_id:
                continue

            # Resolve tactic shortnames from kill_chain_phases
            tactic_names = [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            is_sub = obj.get("x_mitre_is_subtechnique", False)
            parent_id = None
            if is_sub and "." in tech_id:
                parent_id = tech_id.split(".")[0]

            name = obj.get("name", "")
            description = obj.get("description", "")[:600]

            # (improved) tokenize name/description ONCE here at load time,
            # instead of inside search_techniques() where it would be
            # redone via re.findall() for every technique on every single
            # search call. With ~700 techniques and one search per
            # classification, this avoids repeating the same regex work
            # over and over for text that never changes after load.
            name_tokens = frozenset(re.findall(r"\b\w+\b", name.lower()))
            desc_tokens = frozenset(re.findall(r"\b\w+\b", description.lower()))

            entry = TechniqueEntry(
                technique_id    = tech_id,
                name            = name,
                description     = description,
                tactic_names    = tactic_names,
                is_subtechnique = is_sub,
                parent_id       = parent_id,
                platforms       = obj.get("x_mitre_platforms", []),
                detection       = obj.get("x_mitre_detection", "")[:400],
                _name_tokens    = name_tokens,
                _desc_tokens    = desc_tokens,
            )

            if is_sub:
                self._sub_techniques[tech_id] = entry
            else:
                self._techniques[tech_id] = entry

            # Build lowercase name index for fuzzy lookup
            self._name_index[entry.name.lower()] = tech_id

        # (improved) build the combined searchable list once, here, instead
        # of reconstructing list(...) + list(...) inside search_techniques()
        # on every call.
        self._all_searchable = list(self._techniques.values()) + list(self._sub_techniques.values())


@lru_cache(maxsize=1)
def get_taxonomy() -> ATTCKTaxonomyLoader:
    """
    Module-level cached accessor.
    First call loads and indexes the bundle (~300ms).
    All subsequent calls return the cached instance instantly.

    Usage:
        from src.knowledge_base.mitre.attck_taxonomy_loader import get_taxonomy
        taxonomy = get_taxonomy()
    """
    return ATTCKTaxonomyLoader()