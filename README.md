<div align="center">

<h1>NL-SIEM</h1>

<h3>ATT&CK Coverage Drift: Cross-Platform Detection Engineering and Execution Validation<br/>via Large Language Models, Intermediate Representation, and Multi-SIEM Connectors</h3>

<p>
  <a href="https://arxiv.org/abs/XXXX.XXXXX">
    <img src="https://img.shields.io/badge/arXiv-XXXX.XXXXX-b31b1b.svg?style=for-the-badge" alt="arXiv Paper"/>
  </a>
  &nbsp;
  <img src="https://img.shields.io/badge/Python-3.10%2B-3572A5?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  &nbsp;
  <img src="https://img.shields.io/badge/License-MIT-2e7d32?style=for-the-badge" alt="License"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Dataset-SIEMBench_v1-7B1FA2?style=for-the-badge" alt="Dataset"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Status-Under_Review-F57C00?style=for-the-badge" alt="Status"/>
</p>

<p>
  <b>Splunk SPL</b> &nbsp;·&nbsp;
  <b>IBM QRadar AQL</b> &nbsp;·&nbsp;
  <b>Elastic EQL / KQL</b> &nbsp;·&nbsp;
  <b>Microsoft Sentinel KQL</b> &nbsp;·&nbsp;
  <b>Wazuh XML</b>
</p>

</div>

---

## The Problem: Your Heatmap Is Green, But Your Detection Doesn't Fire

ATT&CK has become the de facto framework for measuring detection coverage. Security teams map detections to ATT&CK techniques, generate heatmaps, and use coverage metrics to communicate security posture to analysts, leadership, and incident responders. The assumption behind all of this is straightforward: if a technique is marked as covered, a corresponding detection capability exists.

In modern environments, that assumption breaks down.

Most organizations operate multiple SIEM platforms simultaneously — a consequence of cloud adoption, mergers and acquisitions, regulatory requirements, and technology transitions. Detections engineered for one platform must be recreated, adapted, or translated across several others. As detections cross platform boundaries, differences in query semantics, aggregation behavior, field mappings, and temporal constraints silently degrade them. A translated detection may preserve its ATT&CK label while losing its behavioral meaning. The rule deploys successfully. The heatmap stays green. The detection no longer fires correctly.

We call this **ATT&CK Coverage Drift**: the divergence between documented ATT&CK coverage and actual cross-platform detection capability.

**NL-SIEM** is a multi-agent LLM framework that addresses coverage drift at its source. Rather than attaching ATT&CK metadata to detections after generation, NL-SIEM treats ATT&CK semantics as the structural foundation of the detection engineering process — embedded into a platform-agnostic Intermediate Representation that every downstream translator must preserve.

---

## How NL-SIEM Preserves ATT&CK Fidelity

```
Traditional Workflow:
  Write detection in Splunk SPL (mapped to T1110.001)
          ↓
  Translate to QRadar AQL     →  ATT&CK label copied, semantics drift
  Translate to Elastic EQL    →  ATT&CK label copied, semantics drift
  Translate to Sentinel KQL   →  ATT&CK label copied, semantics drift
  Translate to Wazuh XML      →  ATT&CK label copied, semantics drift

                     Heatmap stays green. Coverage has decayed.

NL-SIEM Workflow:
  Analyst describes threat intent in natural language
          ↓
  ATT&CK Classifier resolves tactic, technique, sub-technique
          ↓
  Intermediate Representation encodes ATT&CK identity + detection semantics
          ↓
  Five platform translators inherit the same ATT&CK-bound contract
          ↓
  Syntactically valid, semantically equivalent, ATT&CK-faithful detections
```

ATT&CK fidelity is preserved because every detection inherits a common semantic definition — not because outputs are compared and corrected after generation.

---

## System Architecture

<div align="center">
  <img src="siem_architecture.svg" alt="NL-SIEM Architecture" width="800"/>
</div>

> *Figure 1. End-to-end NL-SIEM pipeline: natural language input is classified against the ATT&CK knowledge base, encoded into a platform-agnostic IR that embeds ATT&CK identity as a structural property, and then translated independently by five SIEM-specific agents — each bound to the same behavioral contract.*

### Stage 1 — ATT&CK-Aware Threat Classification

A dedicated ATT&CK Classifier Agent reasons over the ATT&CK knowledge base to resolve the most appropriate tactic, technique, and sub-technique from a natural-language description. Analysts provide no ATT&CK identifiers and no platform-specific details. The classifier establishes the canonical adversary behavior representation before any platform-dependent logic is introduced. This mapping becomes the semantic anchor for the rest of the pipeline.

### Stage 2 — Intermediate Representation as a Semantic Contract

Once ATT&CK context is established, the system encodes detection intent into a platform-independent Intermediate Representation. The IR captures:

- ATT&CK tactic, technique, and sub-technique (embedded structurally, not as metadata)
- Event categories and telemetry requirements
- Detection predicates and filtering logic
- Temporal constraints and aggregation functions
- Threshold conditions and logical event relationships

By separating behavioral intent from implementation syntax, the IR functions as a semantic contract that all downstream translators must honor.

### Stage 3 — Cross-Platform Detection Translation

Five independent translation agents — each supported by a RAG retrieval layer grounded in curated platform documentation — consume the same IR and generate platform-specific detection logic. Because all outputs originate from a shared ATT&CK-bound representation, cross-platform consistency is an architectural property, not a post-generation validation task.

---

## Research Contributions

| # | Contribution | Description |
|---|---|---|
| 1 | **ATT&CK Coverage Drift** | Formal characterization of the divergence between documented ATT&CK coverage and actual cross-platform detection capability |
| 2 | **NL-SIEM Pipeline** | End-to-end multi-agent architecture: NL → ATT&CK Classification → IR → 5 SIEM outputs via a clean abstraction boundary between comprehension and generation |
| 3 | **Intermediate Representation Schema** | Platform-agnostic JSON schema with ATT&CK identity as a structural component, encoding detection primitives: field references, logical operators, temporal windows, aggregation functions, threshold conditions |
| 4 | **SIEMBench v1** | 200+ expert-annotated NL–query pairs across 5 platforms, stratified by ATT&CK tactic and query complexity — the first open benchmark for this task |
| 5 | **Evaluation Framework** | Three-dimensional evaluation: syntactic validity, semantic equivalence (BLEU-4, field-match F1), and execution match |
| 6 | **Ablation Study** | Systematic comparison of zero-shot vs. few-shot, with-IR vs. without-IR, and GPT-4o vs. Gemini vs. Llama 3 |

---

## End-to-End Example

A single natural-language description — *"Repeated failed SSH authentication attempts originating from the same source IP"* — triggers the complete pipeline. No ATT&CK identifier is provided. No target platform is specified.

**ATT&CK Classification**
```
Tactic:       Credential Access
Technique:    T1110 — Brute Force
Sub-technique: T1110.001 — Password Guessing
```

**Intermediate Representation (IR)**
```json
{
  "attack": {
    "tactic": "credential-access",
    "technique": "T1110",
    "sub_technique": "T1110.001"
  },
  "action": "filter+aggregate",
  "event_type": "authentication",
  "filter": {
    "field": "status",
    "op": "eq",
    "value": "failed"
  },
  "group_by": ["src_ip"],
  "time_window": "24h",
  "threshold": { "count": ">50" }
}
```

**Splunk SPL**
```spl
index=* status=failed earliest=-24h
| stats count by src_ip
| where count > 50
```

**IBM QRadar AQL**
```sql
SELECT sourceip, COUNT(*) as attempts
FROM events
WHERE status = 'failed'
  AND LOGSOURCETYPENAME(devicetype) = 'SSH'
GROUP BY sourceip
HAVING attempts > 50
LAST 24 HOURS
```

**Elastic EQL**
```eql
authentication where event.outcome == "failure"
| stats count = count() by source.ip
| where count > 50
  and @timestamp >= now() - 24h
```

**Microsoft Sentinel KQL**
```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts > 50
```

**Wazuh XML Rule**
```xml
<rule id="100050" level="10">
  <if_sid>5503</if_sid>
  <same_source_ip/>
  <frequency>50</frequency>
  <timeframe>86400</timeframe>
  <description>Brute force: 50+ failed SSH logins from same IP in 24h</description>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

All five outputs carry the same ATT&CK identity inherited from the IR. The heatmap is green — and this time, the detections fire.

---

## Dataset — SIEMBench v1

SIEMBench is the first benchmark dataset specifically constructed for cross-platform SIEM query translation research, with ATT&CK tactic stratification as a first-class property.

| Property | Value |
|---|---|
| Total annotated pairs | 200+ |
| Platforms | Splunk, QRadar, Elastic, Sentinel, Wazuh |
| MITRE ATT&CK tactics | Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement, Exfiltration |
| Complexity levels | Simple · Intermediate · Complex |
| Annotation | Expert-authored ground truth + dual security analyst review |
| Format | JSON with NL query, ATT&CK mapping, IR, per-platform ground truth, tactic label, complexity tier |
| License | CC BY 4.0 |

**Schema example:**
```json
{
  "id": "SB-042",
  "nl_query": "Detect outbound connections to known threat intelligence IPs in the last hour",
  "tactic": "exfiltration",
  "technique": "T1048",
  "complexity": "intermediate",
  "ir": {
    "attack": { "tactic": "exfiltration", "technique": "T1048" },
    "action": "filter",
    "event_type": "network",
    "filter": { "field": "dst_ip", "op": "in", "value": "$TI_IP_LIST" },
    "direction": "outbound",
    "time_window": "1h"
  },
  "ground_truth": {
    "splunk": "index=network_traffic Direction=outbound earliest=-1h | lookup threat_intel dst_ip OUTPUT is_malicious | where is_malicious=true",
    "qradar": "SELECT * FROM events WHERE destinationip IN (SELECT ioc FROM threat_intel) LAST 1 HOURS",
    "elastic": "network where destination.ip in (~threat_intel_ips) and network.direction == \"outbound\"",
    "sentinel": "CommonSecurityLog | where TimeGenerated >= ago(1h) | where DestinationIP in (ThreatIntelIndicators)",
    "wazuh": "<rule id=\"100042\"><if_sid>0</if_sid><match>outbound</match><mitre><id>T1048</id></mitre><description>TI IP match</description></rule>"
  }
}
```

---

## Experimental Results

### Syntactic Validity (%)

| Condition | Splunk | QRadar | Elastic | Sentinel | Wazuh | **Avg** |
|---|---|---|---|---|---|---|
| GPT-4o + IR + RAG | **94.1** | **89.3** | **92.7** | **93.5** | **87.2** | **91.4** |
| GPT-4o + IR | 88.6 | 83.1 | 87.4 | 89.0 | 81.5 | 85.9 |
| GPT-4o Zero-shot | 71.2 | 64.8 | 69.3 | 72.1 | 61.4 | 67.8 |
| Llama 3 + IR + RAG | 82.3 | 76.9 | 80.1 | 81.7 | 74.6 | 79.1 |
| Gemini + IR + RAG | 85.4 | 79.2 | 83.6 | 84.9 | 78.0 | 82.2 |

### Semantic Equivalence — BLEU-4

| Condition | Splunk | QRadar | Elastic | Sentinel | Wazuh | **Avg** |
|---|---|---|---|---|---|---|
| GPT-4o + IR + RAG | **0.71** | **0.64** | **0.69** | **0.72** | **0.61** | **0.67** |
| GPT-4o + IR | 0.63 | 0.56 | 0.61 | 0.65 | 0.53 | 0.60 |
| GPT-4o Zero-shot | 0.43 | 0.38 | 0.41 | 0.44 | 0.35 | 0.40 |

> *Placeholder values — replace with actual results after running experiments.*  
> *Full ablation tables, field-match F1 scores, ATT&CK fidelity metrics, and error analysis in the paper.*

---

## Execution and Validation Layer

NL-SIEM supports execution-backed validation through a connector-based architecture. Generated detections can be executed directly against supported SIEM environments, with results returned to the framework for operational validation — enabling assessment of not just syntactic correctness but live behavioral equivalence.

### Supported Connectors

| Platform | Capability | Status |
|---|---|---|
| Elastic Security | Query execution via Elastic Cloud ES\|QL API | Available |
| Wazuh | Rule deployment and validation | Available |
| Splunk | Query execution | Planned |
| IBM QRadar | Query execution | Planned |
| Microsoft Sentinel | Query execution | Planned |

### Execution Pipeline

```
Natural Language Query
  → ATT&CK Classification
  → Intermediate Representation
  → Platform Translation
  → Execution Agent
  → SIEM Connector
  → Live Results + ATT&CK Fidelity Validation
```

---

## Installation

```bash
# Clone
git clone https://github.com/yourusername/siem-query-translator.git
cd siem-query-translator

# Virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Dependencies
pip install -r requirements.txt

# Environment
cp .env.example .env
# Add: GOOGLE_API_KEY=... or OPENAI_API_KEY=...
```

---

## Quickstart

```python
from src.main import NLSIEMTranslator

translator = NLSIEMTranslator()

result = translator.translate(
    query="Detect more than 10 failed login attempts "
          "from the same user within 5 minutes",
    platforms=["splunk", "qradar", "elastic", "sentinel", "wazuh"]
)

print(result["attack"])          # ATT&CK classification
print(result["ir"])              # Intermediate Representation
print(result["splunk"])          # Splunk SPL
print(result["qradar"])          # IBM QRadar AQL
print(result["elastic"])         # Elastic EQL
print(result["sentinel"])        # Microsoft Sentinel KQL
print(result["wazuh"])           # Wazuh XML Rule
```

---

## Running Evaluations

```bash
# Full evaluation on SIEMBench v1
python scripts/run_evaluation.py \
  --dataset  datasets/benchmark/siembench_v1.json \
  --model    gpt-4o \
  --condition ir+rag \
  --output   experiments/results/raw/

# Aggregate metrics and generate paper tables
python scripts/export_tables.py \
  --results  experiments/results/raw/ \
  --output   experiments/results/aggregated/
```

---

## Repository Structure

```
nl-siem/
│
├── configs/                         # Platform-specific connector configs
│   ├── elastic.yaml
│   ├── qradar.yaml
│   ├── sentinel.yaml
│   ├── splunk.yaml
│   └── wazuh.yaml
│
├── data/                            # SIEMBench dataset
│   ├── siembench.train.jsonl
│   ├── siembench.dev.jsonl
│   ├── siembench.test.jsonl
│   ├── manifest.json
│   ├── stats.json
│   └── DATASET_CARD.md
│
├── generated_rules/                 # Generated detection content
│   └── local_rules.xml
│
├── scripts/
│   ├── translate_query.py           # Main NL-SIEM entrypoint
│   ├── ingest_knowledge_base.py
│   ├── generate_dataset.py
│   ├── run_evaluation.py
│   ├── export_tables.py
│   ├── test_splunk_connection.py
│   └── test_wazuh_connection.py
│
├── src/
│   │
│   ├── agents/
│   │   ├── attack_classifier_agent.py
│   │   ├── parser_agent.py
│   │   ├── validator_agent.py
│   │   ├── refinement_agent.py
│   │   ├── translation_orchestrator.py
│   │   ├── execution_agent.py
│   │   └── rule_deployment_agent.py
│   │
│   ├── connectors/
│   │   ├── base.py
│   │   ├── factory.py
│   │   ├── elastic_connector.py
│   │   ├── splunk_connector.py
│   │   └── wazuh_connector.py
│   │
│   ├── ir/
│   │   ├── schema.py
│   │   ├── validator.py
│   │   ├── ir_to_nl.py
│   │   └── examples.json
│   │
│   ├── translators/
│   │   ├── base.py
│   │   ├── field_mapping.py
│   │   ├── splunk.py
│   │   ├── qradar.py
│   │   ├── elastic.py
│   │   ├── sentinel.py
│   │   ├── wazuh.py
│   │   └── esql_converter.py
│   │
│   ├── rag/
│   │   ├── chunker.py
│   │   ├── embedder.py
│   │   ├── vector_store.py
│   │   ├── retriever.py
│   │   └── ingest.py
│   │
│   ├── llm/
│   │   ├── client.py
│   │   ├── prompts.py
│   │   ├── response_parser.py
│   │   └── token_counter.py
│   │
│   ├── evaluation/
│   │   ├── syntax_validator.py
│   │   ├── semantic_scorer.py
│   │   ├── attack_fidelity.py
│   │   ├── execution_match.py
│   │   ├── error_analyzer.py
│   │   ├── metrics_aggregator.py
│   │   └── ablation.py
│   │
│   ├── knowledge_base/
│   │   ├── splunk/
│   │   ├── qradar/
│   │   ├── elastic/
│   │   ├── sentinel/
│   │   ├── wazuh/
│   │   └── mitre/
│   │
│   └── utils/
│       ├── config.py
│       ├── logger.py
│       ├── file_io.py
│       └── exceptions.py
│
├── tests/
│   └── connectors/
│
├── README.md
├── siem_architecture.svg
└── test_*.py
```

### Directory Overview

| Directory | Purpose |
|---|---|
| `src/agents` | Multi-agent orchestration: ATT&CK classification, parsing, validation, refinement, and translation |
| `src/ir` | Platform-agnostic IR schema with ATT&CK identity as a structural component |
| `src/translators` | IR → SIEM query translators for Splunk, QRadar, Elastic, Sentinel, and Wazuh |
| `src/llm` | LLM abstraction layer, prompting framework, response parsing, and token tracking |
| `src/rag` | Retrieval-Augmented Generation pipeline including embeddings and vector search |
| `src/evaluation` | Benchmarking, ATT&CK fidelity scoring, ablation studies, and execution-level validation |
| `src/utils` | Shared utilities: configuration, logging, exceptions, and file operations |
| `knowledge_base` | SIEM documentation corpus and MITRE ATT&CK knowledge base used for retrieval |
| `datasets` | SIEMBench benchmark dataset, raw query banks, and processed evaluation artifacts |
| `experiments` | Experiment configurations, ablation runs, and evaluation outputs |
| `scripts` | Command-line entry points for dataset generation, evaluation, and benchmarking |
| `tests` | Unit tests and end-to-end integration tests |
| `docs` | Architecture diagrams, paper assets, figures, tables, and manuscript drafts |

### Design Philosophy

The system follows a modular, ATT&CK-first research architecture:

```
Natural Language Query
  → ATT&CK Classification (tactic · technique · sub-technique)
  → Retrieval (RAG over platform docs + MITRE knowledge base)
  → Parser Agent
  → Intermediate Representation (ATT&CK identity embedded structurally)
  → Validation
  → Platform-Specific Translation (5 independent agents)
  → Evaluation (syntactic · semantic · ATT&CK fidelity · execution match)
```

The Intermediate Representation acts as the central abstraction layer, decoupling semantic understanding from SIEM-specific query syntax. ATT&CK identity propagates through this layer as a first-class structural property — ensuring that coverage metrics reflect genuine detection capability rather than inherited labels.

---

## Platform Validation Setup

| Platform | Validation Method | Setup |
|---|---|---|
| Splunk Enterprise | Full execution | Free developer license (local) |
| Elastic SIEM | Full execution | Docker (`elasticsearch:8.x`) |
| Wazuh | Full execution | Docker (`wazuh-docker`) |
| Microsoft Sentinel KQL | Syntax + logic | Azure Data Explorer (free tier) |
| IBM QRadar AQL | Rule-based syntactic parser | Community Edition VM |

---

## Target Venues

- **RAID** — Research in Attacks, Intrusions and Defenses
- **IEEE DSC** — IEEE Conference on Dependable and Secure Computing
- **ACL / EMNLP** — NLP for Cybersecurity Workshop track
- **arXiv cs.CR** — Preprint (immediate release on Day 20)

---

## Citation

If you use NL-SIEM or SIEMBench in your work, please cite:

```bibtex
@article{nlsiem2025,
  title   = {NL-SIEM: Cross-Platform SIEM Query Translation via
             Large Language Models and Intermediate Representation},
  author  = {Your Name and Supervisor Name},
  journal = {arXiv preprint arXiv:XXXX.XXXXX},
  year    = {2025},
  url     = {https://arxiv.org/abs/XXXX.XXXXX}
}
```

---

## License

Code — [MIT License](LICENSE)  
Dataset (SIEMBench v1) — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

<div align="center">
<sub>
  Built as part of a research internship &nbsp;·&nbsp;
  Preprint on arXiv coming soon &nbsp;·&nbsp;
  Issues and pull requests welcome
</sub>
</div>
