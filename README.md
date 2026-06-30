<div align="center">

<h1>NL-SIEM</h1>

<h3>Cross-Platform SIEM Detection Generation via Intermediate Representation
and a Multi-Agent LLM Pipeline</h3>

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3572A5?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-2e7d32?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/LLM-Free_Tier_Only-7B1FA2?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Active_Development-F57C00?style=for-the-badge"/>
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

## What this is

Security teams that run more than one SIEM platform face a quiet but
expensive problem: a detection rule written for Splunk does not behave
the same way when manually ported to QRadar, Elastic, Sentinel, or
Wazuh. Field names diverge, time-window semantics differ, aggregation
behavior is platform-specific, and threshold logic that is declarative
in one engine has to be hand-reconstructed in another. The rule still
deploys. It may even still fire — just not on the same conditions the
original analyst intended.

**NL-SIEM** addresses this by inserting a platform-agnostic
**Intermediate Representation (IR)** between natural language input and
SIEM-specific output. One NL query produces one IR object. That IR is
independently translated by five platform-specific formatters, so
syntactic and semantic differences are isolated to each translator
rather than accumulating through a manual, ad-hoc porting process.

The full pipeline — from raw English sentence to five syntactically
validated, platform-native queries — runs end-to-end today using
**free-tier LLM providers only** (Groq, Gemini, Ollama, or
OpenRouter). No OpenAI or Anthropic API key is required anywhere in
the system.

---

## How it works

```
Natural language query
  "Detect SSH brute force exceeding 50 attempts in 10 minutes"
       │
       ▼
ParserAgent  (LLM + optional RAG over SIEM docs)
       │  builds prompt → calls free-tier LLM in JSON mode
       │  parses response → coerces into schema → retries on failure
       ▼
Intermediate Representation (IR)
  { action, event_type, filter, time_window,
    aggregation, threshold, fields, tactic, technique_id }
       │
       ├──────────────┬──────────────┬──────────────┬──────────────┐
       ▼              ▼              ▼              ▼              ▼
  SplunkTranslator QRadarTranslator ElasticTranslator SentinelTranslator WazuhTranslator
       │              │              │              │              │
       ▼              ▼              ▼              ▼              ▼
     SPL            AQL          EQL / KQL         KQL           XML rule
       │              │              │              │              │
       └──────────────┴──────────────┴──────────────┴──────────────┘
                              ▼
                      ValidatorAgent
              (per-platform static syntax check)
                              ▼
                  [RefinementAgent — optional]
           re-prompts the LLM to fix any syntax failures
                              ▼
                      TranslationResult
        (5 queries + IR + validation report + full metadata)
```

Every stage is independently testable. The IR is the seam: nothing
downstream of it needs to know how the IR was produced, and nothing
upstream of it needs to know which platforms it will be translated
into.

---

## Architecture

<p align="center">
  <img src="docs/architecture/siem_architecture.svg" width="800">
  <br>
  <em>Figure 1 — Five-layer pipeline: NL input → LLM translation engine
  → Intermediate Representation → five SIEM formatters → evaluation layer</em>
</p>

---

## End-to-end example

Input: *"Detect SSH brute force exceeding 50 attempts in 10 minutes"*

**Intermediate Representation** (what `ParserAgent` produces)
```json
{
  "action": "filter+aggregate",
  "event_type": "authentication",
  "filter": {
    "operator": "and",
    "conditions": [
      { "field": "status", "op": "eq", "value": "failed" }
    ]
  },
  "time_window": { "duration": "10m" },
  "aggregation": {
    "function": "count",
    "group_by": ["src_ip"],
    "alias": "attempt_count"
  },
  "threshold": { "field": "attempt_count", "op": "gt", "value": 50 },
  "fields": ["src_ip", "attempt_count"]
}
```

**Splunk SPL** (`src/translators/splunk.py`)
```
index=* earliest=-10m latest=now status="failed"
| stats count as attempt_count by src_ip
| where attempt_count > 50
| sort -attempt_count
| table src_ip, attempt_count
```

**QRadar AQL** (`src/translators/qradar.py`)
```sql
SELECT sourceip, COUNT(*) AS attempt_count
FROM events
WHERE status = 'failed'
GROUP BY sourceip
HAVING attempt_count > 50
ORDER BY attempt_count DESC
LAST 10 MINUTES
```

**Elastic EQL** (`src/translators/elastic.py`)
```
authentication where event.outcome == "failure"
| stats count() as attempt_count by source.ip
| where attempt_count > 50
| sort attempt_count desc
```

**Sentinel KQL** (`src/translators/sentinel.py`)
```kql
SecurityEvent
| where TimeGenerated > ago(10m)
| where Status == "failed"
| summarize attempt_count = count() by IpAddress
| where attempt_count > 50
| order by attempt_count desc
```

**Wazuh XML** (`src/translators/wazuh.py`)
```xml
<rule id="100001" level="10">
  <if_sid>5503</if_sid>
  <match>failed</match>
  <same_source_ip/>
  <frequency>50</frequency>
  <timeframe>600</timeframe>
  <group>authentication_failures,</group>
  <description>Detect SSH brute force exceeding 50 attempts in 10 minutes</description>
</rule>
```

Five formatters, one IR, zero manual re-interpretation of the original
intent.

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

## Installation

```bash
git clone <repository-url>
cd nl-siem

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
```

Configure your provider:

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

---

## Quickstart

### One-shot translation

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

RAG retrieval pulls relevant chunks from your indexed knowledge base
via `src/rag/retriever.py`, which is backed by a FAISS index built by
`src/rag/ingest.py`. Populate `knowledge_base/<platform>/*.txt` with
official SIEM documentation, then run:

```python
from src.rag.ingest import ingest_knowledge_base
ingest_knowledge_base()   # chunk → embed → index, one-time setup
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
├── knowledge_base/                    SIEM doc corpora for RAG (user-populated)
│   ├── splunk/
│   ├── qradar/
│   ├── elastic/
│   ├── sentinel/
│   └── wazuh/
│
└── src/
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

## License

MIT.

---

<div align="center">
<sub>
Issues and PRs welcome.
</sub>
</div>
