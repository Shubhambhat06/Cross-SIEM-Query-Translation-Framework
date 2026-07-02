<div align="center">

<h1>NL-SIEM</h1>

<h3>Cross-Platform SIEM Detection Generation and ATT&CK Coverage Drift 
Prevention via Intermediate Representation and Multi-Agent LLMs</h3>

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3572A5?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-2e7d32?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Dataset-SIEMBench_v1-7B1FA2?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Under_Review-F57C00?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Black_Hat_Arsenal-India_2026-black?style=for-the-badge"/>
</p>

<p>
  <b>Elastic ES|QL</b> &nbsp;·&nbsp;
  <b>Elastic EQL</b> &nbsp;·&nbsp;
  <b>Wazuh XML</b> &nbsp;·&nbsp;
  <b>Splunk SPL</b> &nbsp;·&nbsp;
  <b>IBM QRadar AQL</b> &nbsp;·&nbsp;
  <b>Microsoft Sentinel KQL</b>
</p>

</div>

---

## The Problem: Your Heatmap Is Green But Your Detection Doesn't Fire

ATT&CK coverage heatmaps are how security teams communicate detection 
posture. The assumption behind them is that a technique marked covered 
has a working detection behind it.

In multi-SIEM environments, that assumption breaks silently.

Organizations accumulate SIEM platforms over time — cloud migrations, 
acquisitions, regulatory mandates, vendor transitions. Detections get 
ported across platforms manually or through informal scripting. When 
they cross platform boundaries, differences in field naming, time 
window semantics, aggregation behavior, and threshold expression 
silently degrade them. The ported rule deploys. The heatmap stays 
green. The detection no longer catches the same behavior.

We call this **ATT&CK Coverage Drift**: the divergence between 
documented ATT&CK coverage and actual cross-platform detection 
capability.

It also happens within a single vendor. Elastic Security's transition 
from EQL to ES|QL means existing rule libraries need conversion — 
the two languages differ fundamentally in execution model, not just 
syntax.

**NL-SIEM** prevents drift by treating ATT&CK identity as a structural 
input to detection generation, not a label attached afterward.

---

## How It Works

```
Traditional workflow:
  Write detection in Splunk → ATT&CK label copied to each port
  Port to QRadar            → label survives, semantics drift
  Port to Elastic           → label survives, semantics drift
  Port to Wazuh             → label survives, semantics drift
  Heatmap: green. Coverage: decayed.

NL-SIEM workflow:
  Analyst describes behavior in plain English
    ↓
  ATT&CK Classifier resolves tactic / technique / sub-technique
    ↓
  Intermediate Representation encodes ATT&CK identity +
  detection semantics as a required structural field, not metadata
    ↓
  Independent translation agents for each platform
  all inherit the same ATT&CK-bound contract
    ↓
  Syntactically valid, semantically consistent,
  ATT&CK-faithful detections across every platform
```

---

## Architecture

<p align="center">
  <img src="svg-export-1x.png" width="800">
  <br>
  <em>Figure 1: NL-SIEM Multi-Agent Architecture</em>
</p>

---

## End-to-End Example

Input: *"Repeated failed SSH authentication attempts from the same 
source IP over 24 hours"*

No ATT&CK identifier provided. No platform selected.

**ATT&CK Classification**
```
Tactic:        Credential Access
Technique:     T1110 — Brute Force
Sub-technique: T1110.001 — Password Guessing
```

**Intermediate Representation**
```json
{
  "attack": {
    "tactic":        "credential-access",
    "technique":     "T1110",
    "sub_technique": "T1110.001"
  },
  "action":      "filter+aggregate",
  "event_type":  "authentication",
  "filter": {
    "field": "status",
    "op":    "eq",
    "value": "failed"
  },
  "group_by":    ["src_ip"],
  "time_window": "24h",
  "threshold":   { "count": ">50" }
}
```

**Elastic ES|QL** ✓ live execution validated
```sql
FROM logs-*
| WHERE event.category == "authentication"
    AND event.outcome  == "failure"
    AND @timestamp >= NOW() - 24 hours
| STATS failed_count = COUNT() BY source.ip
| WHERE failed_count > 50
| EVAL mitre_sub_technique = "T1110.001"
```

**Wazuh XML** ✓ live deployment validated
```xml
<rule id="100050" level="10">
  <if_sid>5503</if_sid>
  <same_source_ip/>
  <frequency>50</frequency>
  <timeframe>86400</timeframe>
  <description>
    Brute force: 50+ failed SSH logins from
    single source IP in 24h [T1110.001]
  </description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

**Splunk SPL**
```
index=* status=failed earliest=-24h
| stats count by src_ip
| where count > 50
```

**IBM QRadar AQL**
```sql
SELECT sourceip, COUNT(*) AS attempts
FROM events
WHERE status = 'failed'
GROUP BY sourceip
HAVING attempts > 50
LAST 24 HOURS
```

**Microsoft Sentinel KQL**
```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts > 50
```

The time window travels as `24 hours` in ES|QL and `86400` seconds 
in Wazuh's `<timeframe>`. The ATT&CK sub-technique propagates into 
every output. The IR is the single source of truth.

---

## EQL → ES|QL Syntax Bridge

`src/translators/esql_converter.py`

Elastic's detection ecosystem is mid-transition from EQL to ES|QL. 
The bridge handles conversion for filter-and-aggregate-class rules.

| Mismatch | EQL | ES|QL mapping |
|---|---|---|
| Event-type scoping | `authentication where ...` implicit | Explicit `WHERE event.category` injected from IR `event_type` |
| Aggregation | `stats count = count() by source.ip` | `STATS count = COUNT() BY source.ip` |
| Threshold | `where count > 50` | `WHERE count > 50` |
| ECS alias expansion | Short aliases valid in event-type blocks | Fully qualified paths required; pre-processing step in bridge |
| Null handling in groups | Null keys included | `COALESCE` wrapper injected |
| Time anchor | `within` measures inter-event span | `@timestamp` filter from query time — documented semantic difference |
| Sequence correlation | Native `sequence` keyword | **Not supported — `ESQLConversionError` raised explicitly** |

Sequence constructs throw an error rather than producing a wrong 
answer. That is intentional. Sequence support is the next roadmap 
item.

All filter+aggregate ES|QL output is verified against Elastic's 
`_query/esql` validation endpoint.

---

## SIEMBench v1

`data/siembench.jsonl` · `data/siembench.train.jsonl` · 
`data/siembench.dev.jsonl` · `data/siembench.test.jsonl`

241 JSONL records pairing natural-language queries with ATT&CK 
annotations and IR encodings. The first open benchmark for 
cross-platform detection generation that treats ATT&CK provenance 
as a first-class property.

| Property | Value |
|---|---|
| Total records | 241 |
| Format | JSONL |
| ATT&CK tactics | Initial Access · Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Discovery · Exfiltration |
| Complexity tiers | Simple · Intermediate · Complex |
| Fields per record | NL query · tactic · technique · sub-technique · complexity · IR |
| License | CC BY 4.0 |

```json
{
  "id":            "SB-042",
  "nl_query":      "Detect outbound connections to known threat 
                    intel IPs, last hour",
  "tactic":        "exfiltration",
  "technique":     "T1048",
  "sub_technique": "T1048.003",
  "complexity":    "intermediate",
  "ir": {
    "attack": {
      "tactic":        "exfiltration",
      "technique":     "T1048",
      "sub_technique": "T1048.003"
    },
    "action":      "filter+aggregate",
    "event_type":  "network",
    "filter": {
      "field": "dst_ip",
      "op":    "in",
      "value": "$TI_IP_LIST"
    },
    "group_by":    ["destination.ip"],
    "time_window": "1h",
    "threshold":   { "count": ">1" }
  }
}
```

---

## Connectors

| Platform | Capability | Status |
|---|---|---|
| Elastic Security | ES|QL live execution via `_query/esql` | ✓ Implemented · validated at C-ISFCR |
| Elastic Security | EQL→ES|QL bridge (filter+aggregate) | ✓ Implemented · partial |
| Wazuh | Rule deployment + validation via Wazuh API | ✓ Implemented · validated at C-ISFCR |
| Splunk | SPL REST API execution | Near-term |
| IBM QRadar | AQL query execution | Near-term |
| Microsoft Sentinel | Azure Monitor API | Near-term |

The Elastic and Wazuh connectors have been used in a production 
detection engineering workflow at PESU C-ISFCR, PES University. 
This is execution-backed validation — not syntax checking.

---

## Free-tier LLM support

This is a deliberate design constraint, not a fallback. `src/llm/client.py`
talks to four providers, all usable without a paid API key:

| Provider | Free tier | Best model |
|---|---|---|
| **Groq** | 30 req/min, 14,400 tokens/min | `llama-3.3-70b-versatile` |
| **Google Gemini** | 15 req/min, 1M tokens/min (Flash) | `gemini-2.0-flash` |
| **Ollama** | Unlimited, fully local | `llama3.2` |
| **OpenRouter** | Aggregated free models | `meta-llama/llama-3.1-70b-instruct:free` |

```python
from src.llm.client import LLMClient

# Auto-detect provider from LLM_PROVIDER env var (default: groq)
client = LLMClient.from_env()

# Or explicit
client = LLMClient(provider="ollama", model="llama3.2")
```

`OLLAMA_HOST` defaults to `http://localhost:11434` for fully offline
operation. `src/llm/token_counter.py` tracks token usage and estimated
cost per run across whichever provider is active.

---

## Frontend Dashboard

`frontend/` — a React 18 + Vite single-page dashboard that gives analysts
a UI over the pipeline above, instead of requiring a Python shell for
every translation.

| Page | What it does | Talks to |
|---|---|---|
| Dashboard | Translation volume, platform count, coverage %, connector health at a glance | `GET /stats`, `GET /connectors/status` |
| Translator | Free-text query in, ATT&CK-mapped IR + per-platform queries out | `POST /translate` |
| ATT&CK Mapping | Kill-chain heatmap and pipeline diagram for the active translation | derived from the last `/translate` response |
| Benchmarks | Per-platform accuracy and latency | `GET /benchmarks` |
| Connectors | Live connection status per platform connector | `GET /connectors/status` |
| Upload | Drag-and-drop ingestion of log samples to improve translation accuracy | `POST /upload` |
| Executions | History of pipeline runs, expandable per-run detail | `GET /executions` |

**Stack:** React 18 · Vite · Tailwind CSS v4 · Recharts (benchmarks) ·
React Flow (pipeline diagram) · React Syntax Highlighter (query output) ·
React Icons

```
frontend/
├── index.html
├── vite.config.js
├── package.json
├── src/
│   ├── main.jsx
│   ├── index.css
│   ├── services/
│   │   └── api.js              axios client, base URL from VITE_API_URL
│   └── components/
│       ├── App.jsx             sidebar/navbar shell + page routing
│       ├── SideBar.jsx
│       ├── Navbar.jsx
│       ├── Dashboard.jsx
│       ├── StatCards.jsx
│       ├── QueryTranslator.jsx
│       ├── QueryCard.jsx
│       ├── TranslationResults.jsx
│       ├── History.jsx
│       ├── AttackMappingPage.jsx
│       ├── AttackMapping.jsx
│       ├── AttackHeatmap.jsx
│       ├── PipelineGraph.jsx
│       ├── Benchmarks.jsx
│       ├── BenchmarkChart.jsx
│       ├── BenchmarkCard.jsx
│       ├── ConnectorStatus.jsx
│       ├── ConnectorCard.jsx
│       ├── Upload.jsx
│       └── Executions.jsx
```

---

## Backend API Layer

The dashboard talks to a thin FastAPI layer over `TranslationOrchestrator`
— it exposes the existing pipeline over HTTP rather than reimplementing
any of it.

```
src/api/
├── server.py          FastAPI app, CORS config, route registration
├── routes/
│   ├── translate.py    POST /translate
│   ├── connectors.py   GET  /connectors/status
│   ├── benchmarks.py   GET  /benchmarks
│   ├── uploads.py      POST /upload
│   └── executions.py   GET  /executions
└── schemas.py          Pydantic response models shared with the frontend
```

| Endpoint | Method | Description |
|---|---|---|
| `/translate` | POST | Runs `TranslationOrchestrator.translate()`; returns `{ success, run_id, ir, translations, error }` |
| `/connectors/status` | GET | Live/last-known connection state per platform connector |
| `/benchmarks` | GET | Accuracy/latency figures per platform from `experiments/results/` |
| `/upload` | POST | Accepts log sample files, queues them for `src/rag/ingest.py` |
| `/executions` | GET | Recent pipeline run history with status and duration |

Run it with:

```bash
uvicorn src.api.server:app --reload --port 8000
```

> Adjust the module path above if your server entrypoint lives elsewhere —
> this reflects the route shape the frontend already expects, not
> necessarily an exact file that ships in this repo today.

---

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- (Optional) [Ollama](https://ollama.com), if you want the LLM to run fully offline

### 1. Clone the repo

```bash
git clone https://github.com/Shubhambhat06/nl-siem.git
cd nl-siem
```

### 2. Backend setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

Minimum required packages (see `requirements.txt` for the full pinned
list):

```
pydantic>=2.0
pydantic-settings
rich
numpy
sentence-transformers
faiss-cpu
groq            # or: google-generativeai / ollama / openai (for OpenRouter)
nltk
rouge-score
fastapi
uvicorn
```

Configure your LLM provider — pick **one**:

```bash
cp .env.example .env
```

```ini
# .env — pick ONE provider, leave the others blank
LLM_PROVIDER=groq
GROQ_API_KEY=your_key_here

# LLM_PROVIDER=gemini
# GOOGLE_API_KEY=your_key_here

# LLM_PROVIDER=ollama
# OLLAMA_HOST=http://localhost:11434

LOG_LEVEL=INFO
```

The RAG embedding pipeline (`src/rag/embedder.py`) runs entirely
locally via `sentence-transformers` — no embedding API key is ever
needed.

(Optional) Populate `knowledge_base/<platform>/*.txt` with official SIEM
docs and build the index before your first run:

```python
from src.rag.ingest import ingest_knowledge_base
ingest_knowledge_base()   # chunk → embed → index, one-time setup
```

### 3. Start the backend

```bash
uvicorn src.api.server:app --reload --port 8000
```

### 4. Frontend setup

In a separate terminal:

```bash
cd frontend
npm install
```

Point the frontend at your backend (defaults to `http://localhost:8000`):

```bash
cp .env.example .env
```

```ini
VITE_API_URL=http://localhost:8000
```

```bash
npm run dev
```

Open `http://localhost:5173` — the dashboard should load, and Connectors
should show live status once the backend is reachable.

---

## Quickstart

### From the dashboard

Open the **Translator** tab, describe a detection in plain language, and
hit **Translate** (or ⌘/Ctrl + Enter). The ATT&CK mapping, IR, and
per-platform queries appear below, and the run is pinned to **ATT&CK
Mapping** and **Executions** automatically.

### From Python

```python
from src.agents.translation_orchestrator import TranslationOrchestrator

orc = TranslationOrchestrator.from_env()
result = orc.translate(
    "Detect SSH brute force exceeding 50 attempts in 10 minutes"
)

print(result.splunk)
print(result.qradar)
print(result.elastic)
print(result.sentinel)
print(result.wazuh)
print(result.summary())
```

### Enable RAG grounding

```python
orc = TranslationOrchestrator.from_env(enable_rag=True)
result = orc.translate("Detect lateral movement via SMB on port 445")
```

### Batch translation for ablation studies

```python
for condition in ["zero_shot", "few_shot", "rag"]:
    orc = TranslationOrchestrator.from_env(condition=condition)
    result = orc.translate(query)
    save_result(result, condition)
```

### Direct module usage (no orchestrator)

```python
from src.agents.parser_agent import ParserAgent
from src.translators import translate_one
from src.llm.client import LLMClient

agent = ParserAgent(client=LLMClient.from_env())
parse_result = agent.parse("Find outbound connections to known bad IPs")

spl = translate_one(parse_result.ir, "splunk")
```

---

## Running the ATT&CK Coverage Audit

```bash
# Pre-deployment audit
python scripts/run_attck_coverage_audit.py --mode pre

# Post-deployment audit  
python scripts/run_attck_coverage_audit.py --mode post

# Results land in:
# experiments/results/attck_coverage/pre_deployment_audit.json
# experiments/results/attck_coverage/post_deployment_audit.json
```

---

## Running Evaluations

```bash
# Full evaluation on SIEMBench v1
python scripts/run_evaluation.py \
  --dataset data/siembench.test.jsonl \
  --condition ir+rag \
  --output experiments/results/

# Ablation configs live in experiments/configs/
# ablation_ir_rag.yaml · ablation_ir_only.yaml · ablation_zero_shot.yaml
python scripts/run_evaluation.py \
  --config experiments/configs/ablation_zero_shot.yaml
```

---

## Repository Structure

```
nl-siem/
│
├── configs/                    platform connector configs
│   ├── elastic.yaml
│   ├── wazuh.yaml
│   ├── splunk.yaml
│   ├── qradar.yaml
│   └── sentinel.yaml
│
├── data/                       SIEMBench v1 dataset
│   ├── siembench.jsonl         full dataset (241 records)
│   ├── siembench.train.jsonl
│   ├── siembench.dev.jsonl
│   ├── siembench.test.jsonl
│   ├── siembench_attck.jsonl   ATT&CK-annotated split
│   ├── stats.json
│   ├── manifest.json
│   └── DATASET_CARD.md
│
├── experiments/
│   ├── configs/                ablation experiment configs
│   │   ├── ablation_ir_rag.yaml
│   │   ├── ablation_ir_only.yaml
│   │   └── ablation_zero_shot.yaml
│   └── results/attck_coverage/
│       ├── pre_deployment_audit.json
│       └── post_deployment_audit.json
│
├── knowledge_base/             MITRE ATT&CK enterprise JSON
│
├── scripts/                    CLI entrypoints
│   ├── translate_query.py
│   ├── ingest_knowledge_base.py
│   ├── build_siembench.py
│   ├── generate_dataset.py
│   ├── label_attck.py
│   ├── run_attck_coverage_audit.py
│   ├── run_evaluation.py
│   └── export_tables.py
│
├── src/
│   ├── agents/                 pipeline orchestration
│   │   ├── attck_classifier_agent.py
│   │   ├── parser_agent.py
│   │   ├── validator_agent.py
│   │   ├── refinement_agent.py
│   │   ├── translation_orchestrator.py
│   │   ├── execution_agent.py
│   │   └── rule_deployment_agent.py
│   │
│   ├── ir/                     IR schema and validation
│   │   ├── schema.py
│   │   ├── attck_schema.py
│   │   ├── validator.py
│   │   ├── ir_to_nl.py
│   │   └── examples.json
│   │
│   ├── translators/            per-platform translation
│   │   ├── elastic.py
│   │   ├── esql_converter.py   EQL→ES|QL bridge
│   │   ├── wazuh.py
│   │   ├── splunk.py
│   │   ├── qradar.py
│   │   ├── sentinel.py
│   │   ├── field_mapping.py
│   │   └── base.py
│   │
│   ├── connectors/             execution layer
│   │   ├── elastic_connector.py
│   │   ├── wazuh_connector.py
│   │   ├── splunk_connector.py
│   │   ├── factory.py
│   │   └── base.py
│   │
│   ├── rag/                    local retrieval pipeline
│   │   ├── retriever.py
│   │   ├── embedder.py         all-MiniLM-L6-v2
│   │   ├── vector_store.py     FAISS-backed
│   │   ├── chunker.py
│   │   └── ingest.py
│   │
│   ├── evaluation/             benchmarking and scoring
│   │   ├── syntax_validator.py
│   │   ├── semantic_scorer.py
│   │   ├── attck_fidelity_scorer.py
│   │   ├── attck_coverage_auditor.py
│   │   ├── execution_match.py
│   │   ├── error_analyzer.py
│   │   ├── metrics_aggregator.py
│   │   └── ablation.py
│   │
│   ├── knowledge_base/         indexed SIEM + MITRE docs
│   │   ├── elastic/
│   │   ├── wazuh/
│   │   ├── splunk/
│   │   ├── qradar/
│   │   ├── sentinel/
│   │   └── mitre/
│   │
│   ├── llm/                    LLM abstraction layer
│   │   ├── client.py
│   │   ├── prompts.py
│   │   ├── response_parser.py
│   │   └── token_counter.py
│   │
│   └── utils/
│       ├── config.py
│       ├── logger.py
│       ├── file_io.py
│       └── exceptions.py
│
└── tests/
    └── connectors/
        ├── test_splunk_connector.py
        └── test_wazuh_connector.py
```

---

## Project structure

This reflects what is implemented today, not a roadmap.

```
nl-siem/
│
├── .env.example
├── requirements.txt
│
├── docs/
│   └── architecture/
│       └── siem_architecture.svg      five-layer pipeline diagram
│
├── frontend/                          React + Vite dashboard (see above)
│
├── knowledge_base/                    SIEM doc corpora for RAG (user-populated)
│   ├── splunk/
│   ├── qradar/
│   ├── elastic/
│   ├── sentinel/
│   └── wazuh/
│
└── src/
    ├── api/                           REST layer over the orchestrator (see above)
    │
    ├── utils/                         Layer 0 — foundation
    │   ├── config.py                  pydantic-settings, env-driven
    │   ├── logger.py                  structured logging, run-ID tagging
    │   ├── exceptions.py               NLSIEMError hierarchy
    │   └── file_io.py                 JSON / JSONL / CSV load-save
    │
    ├── ir/                            Layer 1 — Intermediate Representation
    │   ├── schema.py                  IRQuery Pydantic model (core contribution)
    │   ├── validator.py               validate_ir() / coerce_ir() / validate_batch()
    │   ├── ir_to_nl.py                 reverse IR → NL (semantic verification)
    │   └── examples.json              10 worked IR examples (few-shot source)
    │
    ├── translators/                   Layer 2 — per-platform formatters
    │   ├── base.py                    BaseSIEMTranslator abstract class
    │   ├── field_mapping.py           canonical field → per-platform field
    │   ├── splunk.py                  IR → SPL
    │   ├── qradar.py                  IR → AQL
    │   ├── elastic.py                 IR → EQL / KQL (auto-routed by query shape)
    │   ├── sentinel.py                IR → Sentinel KQL
    │   └── wazuh.py                   IR → Wazuh rule XML
    │
    ├── llm/                           Layer 3 — LLM interface
    │   ├── client.py                  Groq / Gemini / Ollama / OpenRouter wrapper
    │   ├── prompts.py                 system prompts, few-shot templates
    │   ├── response_parser.py         JSON extraction from raw LLM output
    │   └── token_counter.py           token + cost tracking per run
    │
    ├── rag/                           Layer 4 — local retrieval-augmented generation
    │   ├── chunker.py                 sliding-window text chunking
    │   ├── embedder.py                sentence-transformers (all-MiniLM-L6-v2)
    │   ├── vector_store.py            FAISS IndexFlatIP, save/load
    │   ├── retriever.py               embed query → search → format context
    │   └── ingest.py                  one-time chunk → embed → index pipeline
    │
    └── agents/                        Layer 5 — orchestration
        ├── parser_agent.py            NL → IR (LLM + optional RAG, retry on failure)
        ├── validator_agent.py         per-platform static syntax validator
        ├── refinement_agent.py        self-critique re-prompt loop on validation failure
        └── translation_orchestrator.py main pipeline entry point
```

---

## Validation, not execution

`src/agents/validator_agent.py` performs **static syntax validation**
against each of the five platforms — it checks structural correctness
(required keywords, valid pipe commands, well-formed XML, balanced
clauses) without connecting to a live SIEM instance. This is what
currently backs the pipeline's self-correction loop: when validation
fails, `RefinementAgent` re-prompts the LLM with the specific error
before giving up.

This is an important distinction to be precise about: **syntactic
validity is not the same claim as execution correctness.** A query can
pass every structural check in `validator_agent.py` and still fail
against a real SIEM instance due to schema drift, missing indices, or
platform version differences. Live execution connectors (an
Elasticsearch sandbox via Docker, a Wazuh manager deployment target)
are the natural next step and are not yet part of this repository.

---

## What is implemented vs. what is planned

Being direct about this matters more than the architecture diagram
looking complete.

**Implemented today, in this repo:**
- Full NL → IR → 5-platform pipeline, callable end-to-end
- IR schema with Pydantic v2 validation and LLM-output coercion
  (handles common aliasing mistakes: `"filter_aggregate"` →
  `"filter+aggregate"`, `"auth"` → `"authentication"`, etc.)
- All five platform translators, each with platform-specific operator
  mapping and a static syntax validator
- Free-tier LLM client supporting four providers with no paid API key
- Fully local RAG pipeline (chunk → embed → FAISS → retrieve)
- Self-correcting agent loop: parse → translate → validate → refine
  on failure
- React + Vite dashboard for the pipeline above

**Not yet implemented — do not assume these exist:**
- Live execution connectors against real SIEM instances
- A published benchmark dataset (SIEMBench or equivalent)
- Automated test suite (`tests/`)
- CLI scripts (`scripts/translate_query.py`,
  `scripts/run_evaluation.py`, etc.) — all usage today is via direct
  Python import, as shown in Quickstart above
- ATT&CK tactic/technique auto-classification — `tactic` and
  `technique_id` are optional IR fields the caller can set manually,
  not something the pipeline infers
- The `src/api/` FastAPI layer the frontend expects — the route shapes
  above describe what the dashboard calls, not confirmed shipped code

If you're building on top of this for a CTF, hackathon, or research
prototype, the honest framing is: *intermediate representation +
multi-agent translation is built and works; execution-backed
validation and a published benchmark are the open problems.*

---

## Adding a new SIEM target

Every translator inherits from `BaseSIEMTranslator`
(`src/translators/base.py`), which provides:

- `_resolve(field)` — canonical → platform field name via
  `field_mapping.py`
- `_map_op(operator)` — IR comparison operator → platform operator
  syntax
- `translate(ir) -> str` — the only method you call externally;
  wraps your `_translate()` with error handling

To add a sixth platform, subclass `BaseSIEMTranslator`, implement
`_translate(self, ir: IRQuery) -> str` and `validate(self, query: str)
-> bool`, add field mappings to `field_mapping.py`, and register the
translator wherever `translate_all()` dispatches across platforms.

---

## Limitations

- EQL sequence constructs are not converted by the current bridge.
  `ESQLConversionError` is raised explicitly rather than emitting
  an approximate translation. Sequence support is the next roadmap
  item.
- Splunk, QRadar, and Sentinel execution connectors are not yet
  implemented. Translation agents for these platforms are functional;
  live execution validation is pending.
- The RAG retrieval layer uses `all-MiniLM-L6-v2`, a general-purpose
  encoder not fine-tuned on security text. Techniques with similar
  surface descriptions are a known misclassification risk.
- Retrieval hyperparameters (k=5 classifier, k=2 per platform for
  translators) were set heuristically.

---

## Research

Built at PESU Centre for Information Security, Forensics and Cyber 
Resilience (C-ISFCR), PES University, Bengaluru.

Companion paper: *Detecting What You Think You Detect: Cross-Platform 
SIEM Query Generation and ATT&CK Coverage Drift Prevention via 
Intermediate Representation and Multi-Agent LLMs* — preprint under 
review.

---

## Citation

```bibtex
@article{bhat2025nlsiem,
  title   = {Detecting What You Think You Detect: Cross-Platform SIEM
             Query Generation and ATT\&CK Coverage Drift Prevention
             via Intermediate Representation and Multi-Agent LLMs},
  author  = {Bhat, Shubham Dattatraya},
  year    = {2025},
  note    = {Preprint under review. Research conducted at PESU C-ISFCR,
             PES University, Bengaluru.}
}
```

---

## License

Code — [MIT License](LICENSE)  
Dataset (SIEMBench v1) — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

<div align="center">
<sub>
Built at PESU C-ISFCR · Black Hat Arsenal India 2026 · 
Issues and PRs welcome
</sub>
</div>
