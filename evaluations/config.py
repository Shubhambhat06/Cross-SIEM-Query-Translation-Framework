"""
evaluation/config.py

Central configuration for the NL-SIEM evaluation framework.

Nothing in the framework should hard-code paths,
sample sizes or output directories.
"""

from pathlib import Path

# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT /
    "data" /
    "siembench_attck.jsonl"
)

OUTPUT_DIR = PROJECT_ROOT / "evaluation"

CACHE_DIR = OUTPUT_DIR / "cache"

RAW_OUTPUT_DIR = OUTPUT_DIR / "raw"

REPORT_DIR = OUTPUT_DIR / "reports"

PLOT_DIR = OUTPUT_DIR / "plots"

# ============================================================
# Evaluation
# ============================================================

# Keep small for Groq free tier
DEFAULT_SAMPLE_SIZE = 40

RANDOM_SEED = 42

# Parallel workers
MAX_WORKERS = 4

# Retry API calls
MAX_RETRIES = 3

# ============================================================
# Cache
# ============================================================

ENABLE_CACHE = True

OVERWRITE_CACHE = False

# ============================================================
# Metrics
# ============================================================

ENABLE_LATENCY = True

ENABLE_COST = True

ENABLE_DRIFT = True

ENABLE_EXECUTION = True

# ============================================================
# Reports
# ============================================================

EXPORT_JSON = True

EXPORT_CSV = True

EXPORT_LATEX = True

EXPORT_PLOTS = True

# ============================================================
# Create folders automatically
# ============================================================

for folder in (
    OUTPUT_DIR,
    CACHE_DIR,
    RAW_OUTPUT_DIR,
    REPORT_DIR,
    PLOT_DIR,
):
    folder.mkdir(
        parents=True,
        exist_ok=True,
    )
