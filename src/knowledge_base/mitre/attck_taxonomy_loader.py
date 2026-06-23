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
        self._load()

    # ── Public API ────────────────────────────────────────────────────────

    def get_tactic(self, tactic_id_or_name: str) -> TacticEntry | None:
        """Look up a tactic by ID (TA0001) or shortname (lateral-movement)."""
        key = tactic_id_or_name.lower().replace(" ", "-")
        for t in self._tactics.values():
            if t.tactic_id.lower() == key or t.shortname == key or t.name.lower() == key:
                return t
        return None

    def get_technique(self, technique_id: str) -> TechniqueEntry | None:
        """Look up a technique or sub-technique by ID (T1110 or T1110.001)."""
        tid = technique_id.upper().strip()
        return self._techniques.get(tid) or self._sub_techniques.get(tid)

    def search_techniques(self, query: str, top_k: int = 10) -> list[TechniqueEntry]:
        """
        Simple keyword search over technique names and descriptions.
        Returns up to top_k results ranked by match quality.
        Used by the Classifier Agent to narrow candidates before CoT reasoning.
        """
        query_lower = query.lower()
        tokens = set(re.findall(r"\b\w+\b", query_lower))

        scored: list[tuple[int, TechniqueEntry]] = []
        for tech in list(self._techniques.values()) + list(self._sub_techniques.values()):
            score = 0
            name_lower = tech.name.lower()
            desc_lower = tech.description.lower()

            # Exact name match gets highest weight
            if query_lower in name_lower:
                score += 10
            # Token overlap in name
            name_tokens = set(re.findall(r"\b\w+\b", name_lower))
            score += len(tokens & name_tokens) * 3
            # Token overlap in description
            desc_tokens = set(re.findall(r"\b\w+\b", desc_lower))
            score += len(tokens & desc_tokens)

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

    def _load(self) -> None:
        with open(self._bundle_path, encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])

        # Pass 1: index tactics (x-mitre-tactic objects)
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                tid = obj.get("external_references", [{}])[0].get("external_id", "")
                entry = TacticEntry(
                    tactic_id   = tid,
                    name        = obj.get("name", ""),
                    shortname   = obj.get("x_mitre_shortname", ""),
                    description = obj.get("description", "")[:500],
                )
                self._tactics[tid] = entry

        # Pass 2: index techniques and sub-techniques (attack-pattern objects)
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue

            ext_refs = obj.get("external_references", [])
            tech_id  = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    break

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

            entry = TechniqueEntry(
                technique_id    = tech_id,
                name            = obj.get("name", ""),
                description     = obj.get("description", "")[:600],
                tactic_names    = tactic_names,
                is_subtechnique = is_sub,
                parent_id       = parent_id,
                platforms       = obj.get("x_mitre_platforms", []),
                detection       = obj.get("x_mitre_detection", "")[:400],
            )

            if is_sub:
                self._sub_techniques[tech_id] = entry
            else:
                self._techniques[tech_id] = entry

            # Build lowercase name index for fuzzy lookup
            self._name_index[entry.name.lower()] = tech_id


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
