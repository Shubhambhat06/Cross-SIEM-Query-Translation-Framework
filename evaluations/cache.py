"""
evaluation/cache.py

Disk-based cache for evaluation.

Every evaluated NL query is hashed and stored as JSON.
Future evaluations reuse the cached response instead of
calling the LLM again.

This dramatically reduces API usage on free-tier providers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from evaluations.config import (
    CACHE_DIR,
    ENABLE_CACHE,
    OVERWRITE_CACHE,
)


class EvaluationCache:

    def __init__(
        self,
        cache_dir: Path = CACHE_DIR,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    # ---------------------------------------------------------
    # Internal
    # ---------------------------------------------------------

    def _hash(
        self,
        query: str,
    ) -> str:
        """
        Stable filename from query.
        """

        return hashlib.sha256(
            query.encode("utf-8")
        ).hexdigest()

    def _path(
        self,
        query: str,
    ) -> Path:

        return self.cache_dir / (
            self._hash(query) + ".json"
        )

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    def exists(
        self,
        query: str,
    ) -> bool:

        if not ENABLE_CACHE:
            return False

        return self._path(query).exists()

    def load(
        self,
        query: str,
    ) -> dict[str, Any]:

        path = self._path(query)

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:

            return json.load(f)

    def save(
        self,
        query: str,
        result: dict[str, Any],
    ) -> None:

        if not ENABLE_CACHE:
            return

        path = self._path(query)

        if (
            path.exists()
            and not OVERWRITE_CACHE
        ):
            return

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                result,
                f,
                indent=2,
                ensure_ascii=False,
            )

    def get(
        self,
        query: str,
    ) -> dict | None:

        if self.exists(query):

            return self.load(query)

        return None

    def clear(self):

        for file in self.cache_dir.glob("*.json"):
            file.unlink()

    def stats(self):

        files = list(
            self.cache_dir.glob("*.json")
        )

        size = sum(
            f.stat().st_size
            for f in files
        )

        return {

            "cached_queries": len(files),

            "size_mb": round(
                size / 1024 / 1024,
                2,
            ),
        }


if __name__ == "__main__":

    cache = EvaluationCache()

    query = "Detect brute force SSH logins"

    cache.save(

        query,

        {

            "prediction": "T1110",

            "confidence": 0.95,

        },

    )

    print(cache.get(query))

    print(cache.stats())