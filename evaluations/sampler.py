"""
evaluation/sampler.py

Utilities for selecting a representative subset of the benchmark dataset.

Uses stratified sampling across ATT&CK tactic and query complexity
to maximize diversity while minimizing API usage.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from collections import defaultdict

from evaluations.config import (
    DATASET_PATH,
    DEFAULT_SAMPLE_SIZE,
    RANDOM_SEED,
)

from evaluations.models import Sample


class BenchmarkSampler:
    """
    Creates balanced evaluation samples.
    """

    def __init__(
        self,
        dataset_path: Path = DATASET_PATH,
        seed: int = RANDOM_SEED,
    ):
        self.dataset_path = Path(dataset_path)
        self.seed = seed
        random.seed(seed)
    def load(self) -> list[Sample]:
        """
        Load the benchmark dataset from JSONL.
        """

        samples = []

        with open(self.dataset_path, "r", encoding="utf-8") as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                item = json.loads(line)

                samples.append(
                    Sample(
                        sample_id=item["id"],

                        nl_query=item["nl_query"],

                        ground_truth=[
                            item["attck"]["technique"]
                        ]
                        + (
                            [item["attck"]["sub_technique"]]
                            if item["attck"].get("sub_technique")
                            else []
                        ),

                        tactic=item["attck"]["tactic"],

                        complexity=item["complexity"],

                        metadata=item,
                    )
                )
        return samples

    def stratified_sample(
        self,
        sample_size: int = DEFAULT_SAMPLE_SIZE,
    ) -> list[Sample]:
        """
        Sample evenly across tactic and complexity.
        """

        dataset = self.load()

        buckets = defaultdict(list)

        for sample in dataset:

            key = (
                sample.tactic,
                sample.complexity,
            )

            buckets[key].append(sample)

        selected = []

        while (
            len(selected) < sample_size
            and buckets
        ):

            empty = []

            for key, values in list(buckets.items()):

                if values:

                    chosen = random.choice(values)

                    selected.append(chosen)

                    values.remove(chosen)

                if len(selected) >= sample_size:
                    break

                if not values:
                    empty.append(key)

            for key in empty:
                del buckets[key]

        random.shuffle(selected)

        return selected

    def random_sample(
        self,
        sample_size: int = DEFAULT_SAMPLE_SIZE,
    ) -> list[Sample]:
        """
        Return a random subset of the benchmark.
        """

        dataset = self.load()

        return random.sample(
            dataset,
            min(sample_size, len(dataset)),
        )


if __name__ == "__main__":

    sampler = BenchmarkSampler()

    samples = sampler.stratified_sample()

    print("=" * 60)
    print(f"Loaded {len(samples)} evaluation samples")
    print("=" * 60)

    for sample in samples:

        print(
            f"[{sample.sample_id}]",
            sample.tactic,
            sample.complexity,
            "->",
            sample.nl_query,
        )