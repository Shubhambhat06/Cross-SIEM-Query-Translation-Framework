<div align="center">

<img src="docs/architecture/architecture.svg" alt="NL-SIEM Architecture" width="720"/>

# NL-SIEM

### Cross-Platform SIEM Query Translation via Large Language Models and Intermediate Representation

<p align="center">
  <a href="https://arxiv.org/abs/XXXX.XXXXX"><img src="https://img.shields.io/badge/arXiv-XXXX.XXXXX-b31b1b.svg?style=flat-square" alt="arXiv"/></a>
  <a href="https://github.com/yourusername/siem-query-translator/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-3c763d?style=flat-square" alt="License"/></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3572a5?style=flat-square" alt="Python"/>
  <img src="https://img.shields.io/badge/Status-Under%20Review-f39c12?style=flat-square" alt="Status"/>
  <img src="https://img.shields.io/badge/Dataset-SIEMBench%20v1-8e44ad?style=flat-square" alt="Dataset"/>
</p>

<p align="center">
  <b>Splunk SPL</b> &nbsp;·&nbsp; <b>IBM QRadar AQL</b> &nbsp;·&nbsp; <b>Elastic EQL</b> &nbsp;·&nbsp; <b>Microsoft Sentinel KQL</b> &nbsp;·&nbsp; <b>Wazuh XML</b>
</p>

</div>

---

## Abstract

Security Operations Center (SOC) analysts routinely operate across heterogeneous SIEM environments, each with incompatible, platform-specific query languages. Rewriting detection logic manually for each platform is a significant operational bottleneck — time-consuming, error-prone, and demanding deep per-platform expertise. This work presents **NL-SIEM**, a multi-agent LLM framework that translates natural language threat detection intent into syntactically valid, semantically equivalent queries across five major SIEM platforms simultaneously.

Our approach introduces a **platform-agnostic Intermediate Representation (IR)** — a structured JSON schema that decouples natural language understanding from SIEM syntax generation. Combined with retrieval-augmented generation (RAG) over curated SIEM documentation and few-shot chain-of-thought prompting, NL-SIEM achieves strong syntactic validity and high semantic fidelity across all five platforms. We further release **SIEMBench**, the first publicly available benchmark dataset of 200+ annotated natural language to multi-platform SIEM query pairs, organized across six MITRE ATT&CK tactic categories.

---

## Why This Problem Matters

| Pain Point | Impact |
|---|---|
| 5 major SIEM platforms, 5 incompatible query languages | Every detection rule must be manually rewritten per platform |
| No shared intermediate representation exists | Cross-platform portability is a manual, expert-only task |
| Detection engineering talent is scarce | Query authoring bottleneck slows incident response |
| No benchmark exists for this task | Research progress cannot be measured or compared |

NL-SIEM addresses all four. A single natural language description — *"Detect repeated failed SSH logins from the same source IP within 10 minutes"* — produces five executable, platform-native detection queries in under two seconds.

---

## Core Contributions

1. **The NL-SIEM Pipeline** — An end-to-end multi-agent architecture: natural language → IR → five SIEM query outputs, with a clean abstraction boundary between comprehension and generation.

2. **The Intermediate Representation (IR) Schema** — A platform-agnostic, formally specified JSON schema encoding detection intent: field references, logical operators, temporal windows, aggregation functions, and threshold conditions. The IR is the paper's primary technical contribution.

3. **SIEMBench v1** — 200+ expert-annotated NL–query pairs across Splunk, QRadar, Elastic, Sentinel, and Wazuh, stratified by MITRE ATT&CK tactic and query complexity. Released openly.

4. **A Multi-Dimensional Evaluation Framework** — Syntactic validity, semantic equivalence (BLEU, field-match F1), and execution match across locally hosted and cloud-hosted SIEM instances.

5. **Ablation Study** — Systematic comparison of zero-shot vs. few-shot prompting, with-IR vs. without-IR generation, and GPT-4o vs. Gemini vs. Llama 3, isolating the contribution of each architectural choice.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Natural Language Input                 │
│   "Show failed logins from the same IP > 50 times       │
│    in the last 24 hours"                                 │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                     Parser Agent                         │
│   LLM + few-shot chain-of-thought prompting             │
│   RAG retrieval over SIEM documentation corpus          │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│          Intermediate Representation (IR)                │
│                                                          │
│  {                                                       │
│    "action": "filter+aggregate",                         │
│    "event_type": "authentication",                       │
│    "filter": {"field": "status", "op": "eq",            │
│               "value": "failed"},                        │
│    "group_by": ["src_ip"],                               │
│    "time_window": "24h",                                 │
│    "threshold": {"count": ">50"}                         │
│  }                                                       │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼           ...
   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │  Splunk  │   │  QRadar  │   │  Elastic │
   │  SPL     │   │  AQL     │   │  EQL     │
   └──────────┘   └──────────┘   └──────────┘
```

**Splunk SPL**
```spl
index=* status=failed earliest=-24h
| stats count by src_ip
| where count > 50
```

**Elastic EQL**
```eql
sequence by src_ip with maxspan=24h
  [authentication where status == "failed"]
  | stats count > 50
```

**Microsoft Sentinel KQL**
```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| summarize count() by IpAddress
| where count_ > 50
```

---

## Dataset — SIEMBench v1

SIEMBench is the first benchmark dataset specifically designed for cross-platform SIEM query translation research.

| Property | Value |
|---|---|
| Total query pairs | 200+ |
| Platforms covered | Splunk, QRadar, Elastic, Sentinel, Wazuh |
| MITRE ATT&CK tactics | 6 (Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement, Exfiltration) |
| Complexity levels | Simple (single filter), Intermediate (aggregation), Complex (multi-condition, temporal) |
| Annotation method | Expert-authored ground truth + dual security analyst review |
| Format | JSON (NL query, IR, per-platform ground truth, tactic label, complexity label) |

```json
{
  "id": "SB-042",
  "nl_query": "Detect outbound connections to known threat intelligence IPs in the last hour",
  "tactic": "exfiltration",
  "complexity": "intermediate",
  "ir": {
    "action": "filter",
    "event_type": "network",
    "filter": {"field": "dst_ip", "op": "in", "value": "$TI_IP_LIST"},
    "direction": "outbound",
    "time_window": "1h"
  },
  "ground_truth": {
    "splunk": "index=network_traffic Direction=outbound earliest=-1h | lookup threat_intel dst_ip OUTPUT is_malicious | where is_malicious=true",
    "elastic": "network where destination.ip in (~threat_intel_ips) and network.direction == \"outbound\" and @timestamp >= now()-1h",
    "sentinel": "CommonSecurityLog | where TimeGenerated >= ago(1h) | where DestinationIP in (ThreatIntelIndicators)",
    "qradar": "SELECT * FROM events WHERE destinationip IN (SELECT ioc FROM threat_intel) LAST 1 HOURS",
    "wazuh": "<rule id=\"100042\"><if_sid>0</if_sid><match>outbound</match><description>TI IP match</description></rule>"
  }
}
```

---

## Experimental Results

### Syntactic Validity (%)

| Model | Splunk | QRadar | Elastic | Sentinel | Wazuh | Avg |
|---|---|---|---|---|---|---|
| GPT-4o + IR + RAG | **94.1** | **89.3** | **92.7** | **93.5** | **87.2** | **91.4** |
| GPT-4o + IR | 88.6 | 83.1 | 87.4 | 89.0 | 81.5 | 85.9 |
| GPT-4o (zero-shot) | 71.2 | 64.8 | 69.3 | 72.1 | 61.4 | 67.8 |
| Llama 3 + IR + RAG | 82.3 | 76.9 | 80.1 | 81.7 | 74.6 | 79.1 |

### Semantic Equivalence — BLEU-4 Score

| Model | Splunk | QRadar | Elastic | Sentinel | Wazuh | Avg |
|---|---|---|---|---|---|---|
| GPT-4o + IR + RAG | **0.71** | **0.64** | **0.69** | **0.72** | **0.61** | **0.67** |
| GPT-4o (zero-shot) | 0.43 | 0.38 | 0.41 | 0.44 | 0.35 | 0.40 |

> *Full results, ablation tables, and error analysis in the paper.*

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/siem-query-translator.git
cd siem-query-translator

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your API key: GOOGLE_API_KEY or OPENAI_API_KEY
```

---

## Quickstart

```python
from src.main import NLSIEMTranslator

translator = NLSIEMTranslator()

result = translator.translate(
    "Detect more than 10 failed login attempts from the same user within 5 minutes"
)

print(result["ir"])           # Intermediate Representation
print(result["splunk"])       # Splunk SPL
print(result["elastic"])      # Elastic EQL
print(result["sentinel"])     # Microsoft Sentinel KQL
print(result["qradar"])       # IBM QRadar AQL
print(result["wazuh"])        # Wazuh XML Rule
```

---

## Repository Structure

```
siem-query-translator/
├── src/
│   ├── agents/            # Parser, validator, translation agents
│   ├── ir/                # IR schema definition and validators
│   ├── translators/       # Per-platform output formatters
│   ├── llm/               # LLM client, prompts, response parser
│   ├── rag/               # Embeddings, vector store, retriever
│   ├── evaluation/        # Syntax, semantic, execution metrics
│   └── utils/             # Config, logging, exceptions
├── knowledge_base/        # SIEM documentation for RAG retrieval
├── datasets/
│   ├── raw/               # Source NL query bank
│   ├── benchmark/         # SIEMBench v1 annotated dataset
│   └── processed/         # Tokenized and embedded splits
├── experiments/
│   ├── few_shot/
│   ├── zero_shot/
│   ├── rag/
│   └── results/           # Raw outputs and aggregated metrics
├── scripts/               # Evaluation runner, dataset export tools
├── tests/                 # Unit tests for all modules
└── docs/                  # Architecture diagrams and paper drafts
```

---

## Running Evaluations

```bash
# Run full evaluation on SIEMBench v1
python scripts/run_evaluation.py --dataset datasets/benchmark/siembench_v1.json \
                                  --model gpt-4o \
                                  --condition rag+ir \
                                  --output experiments/results/raw/

# Generate aggregated metric tables
python scripts/export_tables.py --results experiments/results/raw/ \
                                 --output experiments/results/aggregated/
```

---

## Citation

If you use NL-SIEM or SIEMBench in your research, please cite:

```bibtex
@article{nlsiem2025,
  title     = {NL-SIEM: Cross-Platform SIEM Query Translation via
               Large Language Models and Intermediate Representation},
  author    = {Your Name and Supervisor Name},
  journal   = {arXiv preprint arXiv:XXXX.XXXXX},
  year      = {2025},
  url       = {https://arxiv.org/abs/XXXX.XXXXX}
}
```

---

## License

This project is released under the [MIT License](LICENSE).  
The SIEMBench dataset is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

<div align="center">
<sub>Built during a research internship · Contributions and issues welcome</sub>
</div>
