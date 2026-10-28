<div align="center">

<h1>NL-SIEM</h1>

<h3>Cross-Platform SIEM Detection Generation and ATT&CK Coverage Drift
Prevention via Intermediate Representation and Multi-Agent LLMs</h3>

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3572A5?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-2e7d32?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Dataset-SIEMBench_v1-7B1FA2?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Accepted-2E7D32?style=for-the-badge"/>
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

## At a Glance

| | |
|---|---|
| **What it does** | Turns a plain-English detection request into ATT&CK-bound rules for Splunk, QRadar, Elastic, Sentinel and Wazuh from a single Intermediate Representation |
| **Core idea** | ATT&CK identity is a *required structural field* of the IR, not a label added afterwards, so every platform inherits the same contract |
| **Validation** | Static syntax checks, live execution on Elastic and Wazuh, and **replay of real SOC authentication logs through generated Wazuh rules** |
| **Benchmark** | SIEMBench v1: 241 records, 8 ATT&CK tactics, 3 complexity tiers, 5 seeded runs |
| **Headline results** | Coverage drift δ = 0.16 · ATT&CK F1 = 87.9 · Human acceptance = 91.2% (SOC analysts at C-ISFCR) |
| **Cost to try** | Free: Groq free-tier API key + Elastic Cloud 14-day trial ([setup](#4a-first-time-get-a-free-groq-api-key)) |

**Typical workflow:** describe a behaviour in English → NL-SIEM generates ATT&CK-bound rules → the Wazuh rule is written to a file →
the rule is replayed against real log data → analysts review and confirm → opt-in deployment.

---

## Table of Contents

- [At a Glance](#at-a-glance)
- [The Problem](#the-problem-your-heatmap-is-green-but-your-detection-doesnt-fire)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [End-to-End Example](#end-to-end-example)
- [Wazuh Log Filtering & Live SOC Validation](#wazuh-log-filtering--live-soc-validation)
- [EQL → ES|QL Syntax Bridge](#eql--esql-syntax-bridge)
- [SIEMBench v1](#siembench-v1)
- [Connectors](#connectors)
- [Free-tier LLM support](#free-tier-llm-support)
- [Installation](#installation)
  - [Free accounts for trying the tool (Groq + Elastic trial)](#4a-first-time-get-a-free-groq-api-key)
- [Quickstart](#quickstart)
- [Live execution (opt-in)](#live-execution-opt-in)
- [Running the ATT&CK Coverage Audit](#running-the-attck-coverage-audit)
- [Building SIEMBench and running evaluations](#building-siembench-and-running-evaluations)
- [Evaluation Results](#evaluation-results)
- [Repository Structure](#repository-structure)
- [What is implemented vs. what is planned](#what-is-implemented-vs-what-is-planned)
- [Adding a new SIEM target](#adding-a-new-siem-target)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Research](#research) · [Citation](#citation) · [License](#license)

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

> The outputs below are **illustrative** (shortened for readability).
> Real runs also append ATT&CK annotation lines/fields such as
> `| eval MITRETechniques="T1110.001"` to each query, and exact field
> choices vary with the LLM and the IR it produces.

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

> ➜ A generated Wazuh rule is not trusted until it has been **replayed against real
> log data**. See [Wazuh Log Filtering & Live SOC Validation](#wazuh-log-filtering--live-soc-validation).

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

## Wazuh Log Filtering & Live SOC Validation

`wazuh_log_filter.py` · `scripts/translate_query.py --wazuh-rule-file`

A rule can be well-formed XML, carry the correct MITRE tag, pass every static check, and
still **detect nothing**. Static validation proves structure; it does not prove that the
rule's parent rule ID, match strings and thresholds line up with the log lines your hosts
actually produce. That is ATT&CK Coverage Drift at the single-rule level.

After NL-SIEM generates a Wazuh rule, the rule is therefore **replayed against real
authentication logs** from the PESU C-ISFCR SOC before it is trusted or deployed. This
turns "the rule is valid" into "the rule fires on the behaviour it claims to detect".

```mermaid
flowchart LR
    A["Analyst query<br/>(plain English)"] --> B["NL-SIEM pipeline"]
    B --> C["Wazuh rule XML<br/>rules/*.xml"]
    C --> D["wazuh_log_filter.py<br/>replay SOC auth logs"]
    D -->|"alerts > 0"| E["Analyst review +<br/>wazuh-logtest confirmation"]
    D -->|"0 alerts"| F["--explain: find the stage<br/>where events drop out"]
    F -->|"fix translator / rule"| B
    E --> G["Opt-in deployment<br/>(RuleDeploymentAgent)"]
```

### What the filter does

- Reads syslog-style authentication logs (`sshd`, `sudo`, PAM, `useradd`, `usermod`) and replays
  every line through the generated rule.
- Mirrors how Wazuh evaluates the rule: parent rule (`<if_sid>` / `<if_matched_sid>`),
  case-sensitive `<match>` / `<regex>` conditions, `<same_source_ip/>`, and
  `frequency` / `timeframe` thresholds.
- Reports the number of alerts, the matching log lines, and the highest event count seen per
  source IP against the configured threshold.
- `--explain` prints a stage-by-stage funnel (all events → parent rule → each `<match>`), so a rule
  that detects nothing shows exactly **which condition removed the events**.

### Run it

```bash
# 1. Generate the rule; the Wazuh XML is written straight to a file
python scripts/translate_query.py -p wazuh \
  -q "Detect 10 or more failed SSH logins from the same source IP within 60 seconds" \
  --wazuh-rule-file rules/ssh_bruteforce.xml

# 2. Replay a log through the rule (syslog timestamps carry no year, so pass --year)
python wazuh_log_filter.py --log auth_source.log.txt --rule rules/ssh_bruteforce.xml --year 2026 --explain
```

Chain both so the filter runs only when translation succeeds:

```bash
python scripts/translate_query.py -p wazuh --wazuh-rule-file rules/ssh_bruteforce.xml \
  -q "Detect 10 or more failed SSH logins from the same source IP within 60 seconds" \
&& python wazuh_log_filter.py --log auth_source.log.txt --rule rules/ssh_bruteforce.xml --year 2026 --explain
```

`--wazuh-rule-file` defaults to `my_rule.xml` in the repository root and is overwritten on every
run. Pass `--wazuh-rule-file ''` to disable the save.

### Reading `--explain`

> Illustrative output. Exact labels and counts depend on your log and rule.

```
=== Rule 100002  level 10  mitre=T1110.001,T1021.004
    Detect 10 or more failed SSH logins from the same source IP within 60 seconds
    alerts: 2   log lines in result: 11
    threshold 10 in 60s | highest seen: 11 (203.0.113.77)

  --- explain ---
  start                                   10000 events
  parent 5716 (sshd: authentication failed)   25 events
```

A rule that detects nothing shows the funnel collapsing to `0 events` at one specific line. That
line is the defect.

### Defects the replay step catches

| Defect in the generated rule | Why static validation passes it | What the replay shows |
|---|---|---|
| Wrong parent rule ID (for example `5710`, which covers only non-existent users, instead of `5716` for failed passwords) | The XML is well formed | Funnel collapses at the `parent` line |
| Lower-case `<match>failed</match>` against log text that says `Failed` | Valid tag, valid text | Funnel drops to `0 events` at the `<match>` line, because Wazuh matching is case-sensitive |
| `<if_sid>` combined with `frequency` / `timeframe` | Both are valid elements | Warning: Wazuh documents `frequency` together with `<if_matched_sid>` / `<if_matched_group>` / `<if_matched_regex>` |
| Redundant or duplicate `<match>` conditions copied from the query wording | Each tag is individually valid | Extra stages in the funnel that remove events the parent already guarantees |
| Slow, low-volume attacker mistaken for a burst | Threshold syntax is valid | Highest count per IP stays below the threshold, so the rule correctly ignores it |

The first two rows describe a real failure we reproduced during development: the original rule for
*"10 or more failed SSH logins from one IP in 60 seconds"* was valid XML with correct MITRE tags and
detected nothing on a log that contained the attack. After the translator was corrected to choose the parent
rule from the IR outcome, use `<if_matched_sid>` for thresholds and stop copying query words into `<match>`,
the same query detected the attack.

### Live validation with the PESU C-ISFCR SOC

The same commands run unchanged on authentication logs exported from the SOC:

1. **Export.** Take a read-only export of authentication logs (`sshd`, `sudo`, PAM, account-management events) for a defined time window.
2. **Sanitise.** Pseudonymise hostnames, usernames and internal addresses, in line with the SOC's data-handling rules, before the file is used outside the SOC environment.
3. **Generate and replay.** Translate each detection query, write the Wazuh rule to `rules/`, and replay the log through it.
4. **Triage.** For `0 alerts`, run `--explain` and locate the dropped stage. For alerts, SOC analysts check that the matched lines are the intended behaviour.
5. **Confirm on Wazuh itself.** Paste representative matched lines into `wazuh-logtest` on a Wazuh manager (free and open source) to confirm that the real engine reports the same rule.
6. **Deploy, opt-in.** Only a rule that survives steps 3 to 5 goes to the manager through `RuleDeploymentAgent`.

> **Data handling.** Live SOC logs must never be committed. Add `*.log`, `*.log.txt` and any sanitised exports to `.gitignore`.

### Reference log and ground-truth detections

The repository workflow is demonstrated on a **synthetic reference authentication log** (10,000 syslog lines, documentation-range
IP addresses per RFC 5737, with attack sequences seeded at known timestamps). Because the ground truth is known, every detection
below has an expected result.

| Detection query | Ground truth in the reference log |
|---|---|
| Detect 10 or more failed SSH logins from the same source IP within 60 seconds | 11 failures from `203.0.113.77`, 10:23:47 to 10:23:57 |
| Detect successful SSH login as root from an external IP address | 1 login at 10:23:59 from `203.0.113.77` |
| Detect SSH login attempts using non-existent usernames | 12 attempts from `198.51.100.23` spread over about 19 hours |
| Detect sudo used to read /etc/shadow | 1 event at 03:12:51 by `backup` |
| Detect a new local user account being created | `useradd` of `svc_backup2` at 10:24:20 |
| Detect a user being added to the sudo group | `usermod` at 10:24:25 |
| Detect sudo truncating the /var/log/auth.log file | 1 event at 03:15:02 by `backup` |

### Limitations of the filter

- It is an **offline emulation** of the stock Wazuh `sshd`, `sudo` and PAM rule parents. It is not the Wazuh engine; `wazuh-logtest` is the final authority.
- Parent rule IDs assume Linux syslog sources. Windows event-channel and RDP detections are not covered yet.
- A passing replay shows that a rule fires on the supplied log. It does not prove the rule is free of false positives on other data.

---

## EQL → ES|QL Syntax Bridge

`src/translators/esql_converter.py`

Elastic's detection ecosystem is mid-transition from EQL to ES|QL. The
bridge handles conversion for filter-and-aggregate-class rules.

| Mismatch | EQL | ES\|QL mapping |
|---|---|---|
| Event-type scoping | `authentication where ...` implicit | Explicit `WHERE event.category` injected from IR `event_type` |
| Aggregation | `stats count = count() by source.ip` | `STATS count = COUNT() BY source.ip` |
| Threshold | `where count > 50` | `WHERE count > 50` |
| ECS alias expansion | Short aliases valid in event-type blocks | Fully qualified paths required; pre-processing step in bridge |
| Null handling in groups | Null keys included | `COALESCE` wrapper injected |
| Time anchor | `within` measures inter-event span | `@timestamp` filter from query time — documented semantic difference |
| Sequence correlation | Native `sequence` keyword | **Not supported — `ESQLConversionError` raised explicitly** |

Sequence constructs throw an error rather than producing a wrong answer.
That is intentional. Sequence support is the next roadmap item.

```python
from src.translators.esql_converter import ElasticQueryConverter, ESQLConversionError

eql = '''authentication where event.outcome == "failure"
| stats failed_count = count() by source.ip
| where failed_count > 50'''

print(ElasticQueryConverter.to_esql(eql, index_pattern="logs-*"))
# The default index pattern is "nlsiem-test" — pass index_pattern for your own data.
```

Filter+aggregate ES|QL output is verified against Elastic's `_query/esql`
validation endpoint when the Elastic connector is configured
(see [Live execution](#live-execution-opt-in)).

---

## SIEMBench v1

First open benchmark for cross-platform detection generation that treats
ATT&CK provenance as a first-class property: natural-language queries
paired with ATT&CK annotations and IR encodings.

| Property | Value |
|---|---|
| Total records | 241 |
| Format | JSONL (`data/siembench.jsonl`, `.train`, `.dev`, `.test`) |
| ATT&CK tactics | Initial Access · Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Discovery · Exfiltration |
| Complexity tiers | Simple · Intermediate · Complex |
| Fields per record | NL query · tactic · technique · sub-technique · complexity · IR |
| License | CC BY 4.0 |

```json
{
  "id":            "SB-042",
  "nl_query":      "Detect outbound connections to known threat intel IPs, last hour",
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

### Where the data lives in this repository

- **Committed:** `backups/siembench_250_gold.jsonl` — 250 gold **seed**
  queries (`id`, `category`, `complexity` = low/medium/high, `nl_query`).
  These have no ATT&CK labels, IR, or splits yet.
- **Generated, not committed:** the annotated, split files
  (`data/siembench.*.jsonl`, `manifest.json`, `stats.json`). `data/` is in
  `.gitignore`. Rebuild them with
  [Building SIEMBench](#building-siembench-and-running-evaluations)
  (requires an LLM provider).

---

## Connectors

| Platform | Capability | Status |
|---|---|---|
| Elastic Security | ES\|QL live execution via `_query/esql` | ✓ Implemented · validated at C-ISFCR |
| Elastic Security | EQL→ES\|QL bridge (filter+aggregate) | ✓ Implemented · partial |
| Wazuh | Rule deployment + validation via Wazuh API | ✓ Implemented · validated at C-ISFCR |
| Wazuh | Log replay of generated rules (`wazuh_log_filter.py`) | ✓ Implemented · used on SOC authentication logs |
| Splunk | SPL REST API execution (`splunk_connector.py`) | Implemented · live validation pending |
| IBM QRadar | AQL query execution | Near-term (translator only today) |
| Microsoft Sentinel | Azure Monitor API | Near-term (translator only today) |

The Elastic and Wazuh connectors have been used in a production
detection engineering workflow at PESU C-ISFCR, PES University. This is
execution-backed validation — not syntax checking.

All connectors are **opt-in**: nothing touches a live SIEM unless you ask
for it (see [Live execution](#live-execution-opt-in)).

---

## Free-tier LLM support

This is a deliberate design constraint, not a fallback. `src/llm/client.py`
talks to four providers, all usable without a paid API key. Groq, Ollama
and OpenRouter are reached through the OpenAI-compatible SDK; Gemini uses
`google-generativeai`.

| Provider | `LLM_PROVIDER` | Key variable | Default model (override with `LLM_MODEL`) |
|---|---|---|---|
| **Groq** | `groq` | `GROQ_API_KEY` | `openai/gpt-oss-120b` |
| **Google Gemini** | `gemini` | `GOOGLE_API_KEY` | `gemini-2.0-flash` |
| **Ollama** (fully local) | `ollama` | none | `llama3.1` |
| **OpenRouter** | `openrouter` | `OPENROUTER_API_KEY` | `meta-llama/llama-3.1-70b-instruct:free` |

Free-tier limits and available model names change over time. The client
ships a built-in rate limiter (defaults: Groq 30 req/min, Gemini 15
req/min, OpenRouter 20 req/min) — check your provider's current limits and
set `LLM_MODEL` if a default model has been retired.

```python
from src.llm.client import LLMClient

# Reads LLM_PROVIDER / LLM_MODEL / keys from the environment or .env (default provider: groq)
client = LLMClient.from_env()

# Or explicit
client = LLMClient(provider="ollama", model="llama3.1")
```

`OLLAMA_HOST` defaults to `http://localhost:11434`. `src/llm/token_counter.py`
tracks token usage per run; it uses `tiktoken` when it can load its
vocabulary and otherwise falls back to a character-based estimate, so it
also works offline.

---

## Installation

Run everything from the **repository root** — the project is used as a
source tree (`import src...`), not as an installable package.

### Prerequisites

- Python 3.10+ (tested on 3.12)
- git
- (Optional) [Ollama](https://ollama.com) to run the LLM fully locally
- Internet access on first use of RAG (downloads the ~90 MB
  `all-MiniLM-L6-v2` embedding model from Hugging Face, then cached)

### 1. Clone

```bash
git clone https://github.com/Shubhambhat06/Cross-SIEM-Query-Translation-Framework.git
cd Cross-SIEM-Query-Translation-Framework
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
# (Recommended on machines without an NVIDIA GPU — avoids a multi-GB CUDA download)
pip install torch --index-url https://download.pytorch.org/whl/cpu

pip install -r requirements.txt
```

`requirements.txt` contains: `pydantic`, `pydantic-settings`,
`python-dotenv`, `rich`, `numpy`, `requests`, `openai`,
`google-generativeai`, `tiktoken`, `sentence-transformers`, `faiss-cpu`,
`elasticsearch`, `sacrebleu`, `pytest`.

### 4. Configure your LLM provider

```bash
cp .env.example .env            # Windows: copy .env.example .env
```

Edit `.env` — pick **one** provider:

```ini
LLM_PROVIDER=groq
GROQ_API_KEY=your_key_here
# LLM_MODEL=                      # optional override

# LLM_PROVIDER=gemini
# GOOGLE_API_KEY=your_key_here

# LLM_PROVIDER=ollama
# OLLAMA_HOST=http://localhost:11434

LOG_LEVEL=INFO
```

`.env` is loaded automatically by `src/llm/client.py` and is listed in
`.gitignore` — never commit it. Do not set `MODEL_NAME`; use `LLM_MODEL`.

#### Trying the tool for the first time? Use free accounts

You do not need a paid account to evaluate NL-SIEM. The two services below are free to start
and cover everything in this README except the optional live Wazuh manager.

| Service | Needed for | Cost to start |
|---|---|---|
| Groq API key | The LLM that parses, classifies and translates (required unless you use Ollama, Gemini or OpenRouter) | Free tier, no credit card |
| Elastic Cloud trial | Optional live ES\|QL validation (`--execute`) | 14-day free trial |

#### 4a. First time? Get a free Groq API key

Takes about two minutes.

1. Open the [Groq Console](https://console.groq.com) and sign in with email or Google. The free tier does not require a credit card.
2. Open the **API Keys** page ([console.groq.com/keys](https://console.groq.com/keys)) and click **Create API Key**. Give it a descriptive name, for example `nl-siem-dev`.
3. Copy the key immediately. It starts with `gsk_` and is shown only once. If you lose it, revoke it and create a new one.
4. Paste it into `.env`:

   ```ini
   LLM_PROVIDER=groq
   GROQ_API_KEY=gsk_your_key_here
   ```

5. Verify it with a real call:

   ```bash
   python scripts/translate_query.py -q "Detect failed SSH logins from a single IP" -p wazuh --no-refine
   ```

Free-tier keys are rate limited per model (current limits: [console.groq.com/docs/rate-limits](https://console.groq.com/docs/rate-limits)).
If you see `429 Too Many Requests`, the client retries automatically; for repeated runs, wait a minute between queries or add `--no-refine` to
reduce the number of LLM calls. Never commit your key or paste it into issues.

#### 4b. (Optional) Start an Elastic Cloud free trial

Only needed for **execution-backed** Elastic validation. Translation, static validation, the Wazuh log filter
and the other four platforms work without it.

1. Go to [elastic.co/cloud](https://www.elastic.co/cloud) and start a free trial. The trial lasts 14 days, and at the time of writing no credit card is required to begin.
2. Create a deployment (the default settings are enough) and open it in Kibana.
3. Copy the **Elasticsearch endpoint URL** of the deployment.
4. In Kibana, go to **Stack Management → API keys → Create API key** and copy the encoded key.
5. Add both values to `.env`:

   ```ini
   ELASTIC_HOST=https://your-deployment.es.region.cloud.es.io:443
   ELASTIC_API_KEY=your_encoded_api_key
   ```

6. Run a translation with live execution enabled (see [Live execution](#live-execution-opt-in)).

When a trial ends, the deployment is suspended; Elastic deletes the deployment and its data if you do not subscribe within 30 days.
Treat the trial cluster as disposable test infrastructure and never load production data into it.

### 5. Verify the install (no API key or network needed)

```bash
python sanity_check_layer_0.py        # foundation layer — expect 34/34 passed
```

Then confirm the IR → five-platform translators work. Save as
`verify_install.py` in the repo root and run `python verify_install.py`:

```python
import json
from src.ir.schema import IRQuery
from src.translators import translate_all

ex = json.load(open("src/ir/examples.json"))[0]
ir = IRQuery(**{**ex["ir"], "tactic": ex["tactic"], "technique_id": ex["technique_id"]})

print("NL:", ex["nl_query"])
for platform, out in translate_all(ir).items():
    print(f"\n--- {platform}\n{out['query']}")
```

You should see Splunk, QRadar, Elastic, Sentinel and Wazuh queries for
"Find all failed login attempts in the last 24 hours".

### 6. (Optional) Build the RAG index

The SIEM and MITRE reference documents ship in `src/knowledge_base/`.
Point the ingest script there (the default `knowledge_base/` folder only
contains the MITRE JSON, so a default run would index **0 chunks**):

```bash
python scripts/ingest_knowledge_base.py --kb-dir src/knowledge_base --dry-run   # expect: 26 chunks from 23 files
python scripts/ingest_knowledge_base.py --kb-dir src/knowledge_base             # builds src/rag/store
```

The embedding pipeline (`src/rag/embedder.py`) runs locally via
`sentence-transformers` — no embedding API key is ever needed. If the
index is missing, `enable_rag=True` logs a warning and falls back to
few-shot prompting rather than failing.

---

## Quickstart

### From the command line

```bash
python scripts/translate_query.py \
  -q "Detect SSH brute force exceeding 50 attempts in 10 minutes"

# Choose platforms, skip RAG / refinement, save output
python scripts/translate_query.py -q "Detect lateral movement via SMB on port 445" \
  -p splunk wazuh elastic --no-rag --no-refine -o out.json

# Interactive prompt (omit -q)
python scripts/translate_query.py
```

Flags: `-p/--platforms`, `--no-rag`, `--no-refine`, `--dry-run` (builds the
pipeline and exits; no LLM call), `--execute` (see below), `-v/--verbose`,
`-o/--output`, `--store-path`, `--wazuh-rule-file` (save the generated Wazuh rule to a file for the
[log filter](#wazuh-log-filtering--live-soc-validation)).

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
orc = TranslationOrchestrator.from_env(enable_rag=True)   # requires step 6 above
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

## Live execution (opt-in)

By default the pipeline only **generates and statically validates**
queries. Live execution is off unless you request it with
`--execute` (CLI) or `orc.translate(query, execute=True)` (Python).

> ⚠️ With execution enabled, the Wazuh `RuleDeploymentAgent` **appends the
> generated rule to `/var/ossec/etc/rules/local_rules.xml` using `sudo`**
> and the connectors call your SIEM APIs. Only enable it on a test
> manager/cluster you own.

Configure targets in `.env` (all optional):

```ini
ELASTIC_HOST=https://localhost:9200
ELASTIC_API_KEY=
WAZUH_HOST=https://localhost:55000
WAZUH_USER=wazuh
WAZUH_PASSWORD=
SPLUNK_HOST=https://localhost:8089
SPLUNK_USER=admin
SPLUNK_PASSWORD=
```

Credentials are read from the environment only — never hardcode them.

**Validation, not execution (default mode).** `src/agents/validator_agent.py`
performs static syntax validation against each platform (required
keywords, valid pipe commands, well-formed XML, balanced clauses) without
connecting to a SIEM, and backs the self-correction loop: on failure,
`RefinementAgent` re-prompts the LLM with the specific error. Syntactic
validity is not execution correctness — a query can pass every structural
check and still fail on a real instance due to schema drift, missing
indices, or version differences. That is what the connectors above are for.

For Wazuh, [log replay](#wazuh-log-filtering--live-soc-validation) is the middle step between static
validation and deployment: it checks that a rule fires on real log lines **without** touching a manager.

---

## Running the ATT&CK Coverage Audit

Input is JSONL, one rule per line:

```json
{"platform": "splunk", "technique": "T1110", "sub_technique": "T1110.001", "id": "rule-001"}
```

```bash
# Pre-deployment baseline (your existing/legacy rules)
python scripts/run_attck_coverage_audit.py \
  --rules data/legacy_rules.jsonl \
  --label pre_deployment \
  --output experiments/results/attck_coverage/pre_deployment_audit.json

# Post-deployment (NL-SIEM-generated rules)
python scripts/run_attck_coverage_audit.py \
  --rules data/nlsiem_generated_rules.jsonl \
  --label post_deployment \
  --output experiments/results/attck_coverage/post_deployment_audit.json

# Coverage lift between the two saved audits
python scripts/run_attck_coverage_audit.py \
  --compare-pre  experiments/results/attck_coverage/pre_deployment_audit.json \
  --compare-post experiments/results/attck_coverage/post_deployment_audit.json
```

Output is a per-platform ATT&CK coverage percentage and the lift in
percentage points. `experiments/` is gitignored — create it or choose
another `--output` path.

---

## Building SIEMBench and running evaluations

These steps call the LLM once per seed query, so they need a configured
provider (free tiers are rate-limited; `--delay-s` throttles requests).

```bash
mkdir -p data/seeds

# 1. Convert the committed JSONL seeds to the plain-text format (one query per line)
python -c "import json; print('\n'.join(json.loads(l)['nl_query'] for l in open('backups/siembench_250_gold.jsonl') if l.strip()))" > data/seeds/nl_queries.txt

# 2. Parse → classify ATT&CK → translate → stratified train/dev/test split
python scripts/build_siembench.py \
  --seeds-file data/seeds/nl_queries.txt \
  --output-dir data --train-frac 0.7 --dev-frac 0.15
# writes data/siembench.{train,dev,test}.jsonl, manifest.json, stats.json
```

Optional helpers: `scripts/label_attck.py` (batch ATT&CK labelling of gold
seeds; run as `PYTHONPATH=. python scripts/label_attck.py ...`) and
`scripts/generate_dataset.py` (seed expansion / paraphrase augmentation).

### Evaluate

```bash
python scripts/run_evaluation.py \
  --dataset data/siembench.test.jsonl \
  --output results/ \
  --limit 20 \
  --no-exec              # skip Elasticsearch execution matching

# Ablation study (conditions A / B / C)
python scripts/run_evaluation.py --dataset data/siembench.test.jsonl --ablation

# Export result tables (LaTeX / Markdown / CSV / JSON)
python scripts/export_tables.py --results results/ --formats latex markdown
```

Other flags: `--no-rag`, `--no-refine`, `--es-url`, `--results-file`,
`--store-path`, `--quiet`. Scoring modules live in `src/evaluation/`
(syntax validity, semantic scoring, ATT&CK fidelity, ATT&CK coverage
auditor, execution match, error analysis, ablation, metric aggregation).
`run_eval.py` (repo root) and `evaluation/` contain additional evaluation
runners used for the paper experiments.

---

## Evaluation Results

Results reported in the companion paper, measured on the full SIEMBench v1
benchmark (241 queries · 8 ATT&CK tactics · 3 complexity tiers). Execution-backed
evaluation covers the two implemented targets only: **Elastic ES|QL** and
**Wazuh**. Splunk, QRadar and Sentinel are out of scope for these numbers.

| Setting | Value |
|---|---|
| Benchmark | SIEMBench v1 — 241 records |
| Runs | 5 independent runs, seeds `42, 43, 44, 45, 46` (1,205 evaluated instances) |
| Decoding | Deterministic, temperature = 0.0 |
| LLM backends | Qwen and Llama families served via Groq |
| Confidence intervals | 95%, Student's t-distribution over the 5 runs |
| Significance testing | McNemar's paired test, Holm–Bonferroni corrected, α = 0.05 |
| Human assessment | SOC analysts at PESU C-ISFCR, 1–5 Likert scale, blind to computed metrics |

**Protocol per record:** (1) run the NL query through the full pipeline →
(2) compare ATT&CK binding(s) against the gold label → (3) validate the IR
against the schema → (4) submit the Elastic and Wazuh outputs through their
connectors → (5) where reference telemetry exists, compute the Drift Score δ.

### Evaluation metrics

| Metric | Definition | Value |
|---|---|---|
| ATT&CK classification accuracy | `1/N Σ 1[T̂ᵢ = T*ᵢ]` | 68.7 |
| Precision / Recall / F1 (ATT&CK) | TP, FP, FN ratios over verified bindings | 89.1 / 86.8 / 87.9 |
| IR generation accuracy | IR consistency (Eq. 3) pass rate | 83.2 |
| Translation similarity (TS) | `β·BLEU + (1−β)·F1_field`, β = 0.4 | 67.6 |
| Execution success rate | Share executing without error against live connectors | 95.1 |
| Coverage Preservation (CPS) | Jaccard-based symmetric behavioral equivalence, `\|R(D) ∩ R(D′)\| / \|R(D) ∪ R(D′)\|` | 0.84 |
| Coverage Drift (δ) | `1 − \|R(D) ∩ R(D′)\| / \|R(D)\|` | 0.16 |
| Semantic Fidelity Score (SFS) | `α·CPS + (1−α)·Prov`, α = 0.7 | 0.82 |
| Confidence-Weighted Coverage (CWC) | Multi-technique coverage accounting | 0.79 |
| False positive / negative rate | Over- and under-detection after translation | 8.6 / 11.4 |
| Token / API cost | USD per record | $0.0029 / query |
| Translation / end-to-end latency | Seconds, per stage and total | 2.34 / 3.08 s |
| Human acceptance rate | % rated ≥ 4/5 by SOC analysts | 91.2 |

### Baseline comparison

Direct-prompting baselines receive the same NL query with a single instruction
to produce a detection for the target platform — no IR, no taxonomy
verification, no structured intermediate step.

| Approach | ATT&CK Acc. | Exec. Success | Semantic Pres. (1 − δ) | ATT&CK Correctness |
|---|---|---|---|---|
| SIGMA (community backends) | 0.60 | 0.87 | 0.78 | 0.62 |
| Manual rule authoring (SOC baseline) | 0.73 | 0.96 | 0.95 | 0.74 |
| Direct prompting: GPT-4o | 0.63 | 0.81 | 0.71 | 0.61 |
| Direct prompting: Claude 3.5 Sonnet | 0.62 | 0.80 | 0.70 | 0.60 |
| Direct prompting: Qwen (Groq API) | 0.61 | 0.78 | 0.69 | 0.60 |
| Direct prompting: Llama (Groq API) | 0.58 | 0.75 | 0.66 | 0.57 |
| **NL-SIEM (Qwen backend)** | 0.67 | 1.00 | 0.88 | 0.83 |
| **NL-SIEM (Llama backend)** | 0.64 | 1.00 | 0.85 | 0.80 |

*ATT&CK Correctness* = whether the ATT&CK identifier survives translation at
all, independent of whether the behavior does. Elastic AI Assistant and
Microsoft Security Copilot are excluded (no product access) rather than
populated with estimated numbers.

### SOC case studies

Timing and outcome data collected at the C-ISFCR SOC.

| Case | NL query | Manual | NL-SIEM | Drift δ |
|---|---|---|---|---|
| Credential Access | "Detect repeated failed SSH logins from the same source IP over 24 hours." | 18 min | 47.8 s | 0.11 |
| Exfiltration (SB-042) | "Detect outbound connections to known threat intel IPs, last hour." | 24 min | 56.4 s | 0.18 |
| Discovery | "Detect a single source scanning more than 20 distinct destination ports within 5 minutes." | 21 min | 52.1 s | 0.14 |

All three executed successfully.

### Drift metric validation

- **Correlation with analyst judgment:** three SOC analysts blind-rated the
  fidelity of 48 translated rule pairs (16 per analyst) on a 1–5 Likert scale.
  Spearman rank correlation between analyst ratings and computed Drift Scores:
  **ρ = −0.86 (p < 0.001)**.
- **Per-tactic coverage preservation (1 − δ):** every tactic improves after
  NL-SIEM translation; Credential Access shows the largest gain, from
  **0.49 → 0.88**.
- **Drift by complexity tier:** NL-SIEM holds mean drift below naive
  translation at every tier (Simple / Intermediate / Complex).
- **Sensitivity analysis** (window-boundary jitter, null-value injection,
  field-name aliasing) is planned, not yet run.

### Ablation and multi-technique classification

- **Ablation:** Zero-shot → Few-shot → IR only → IR + RAG. Each component
  contributes incrementally to ATT&CK F1; the full IR + RAG configuration is
  used throughout.
- **Multi-technique inclusion:** sweeping the acceptance threshold against the
  multi-label subset of SIEMBench v1 gives **AUC = 0.91**.

### Error taxonomy

Every failure observed during evaluation falls into one of six categories:

| Category | Description |
|---|---|
| ATT&CK misclassification | Taxonomy-verified binding that does not match the gold label (typically a sibling technique) |
| Field mapping failure | Canonical IR field maps to a wrong or absent platform field; the rule silently never matches |
| Unsupported construct | EQL `sequence`, correctly rejected with `ESQLConversionError` rather than approximated |
| LLM hallucination | Syntax or field names not grounded in the IR or retrieved documentation |
| Execution failure | Schema-valid output rejected at the connector layer |
| NL ambiguity | Query under-determines intent; surfaced by the multi-technique classifier instead of silently resolved |

> **Scope of these results.** Annotations come from a single expert annotator
> (inter-annotator agreement is planned for v1.1). Numbers apply to
> filter-and-aggregate-class detections on Elastic ES|QL/EQL and Wazuh. Always
> review generated rules and shadow-evaluate them against pre-production logs
> before deployment.

---

## Repository Structure

```
Cross-SIEM-Query-Translation-Framework/
│
├── requirements.txt
├── .env.example                 copy to .env (never commit .env)
├── svg-export-1x.png            architecture figure
├── siem_architecture.svg
│
├── configs/                     per-platform connector settings (YAML)
├── backups/
│   └── siembench_250_gold.jsonl 250 gold seed queries
├── knowledge_base/
│   └── mitre/enterprise-attack.json
│
├── scripts/                     CLI entrypoints
│   ├── translate_query.py       NL → five platforms; --wazuh-rule-file saves the Wazuh rule
│   ├── ingest_knowledge_base.py
│   ├── build_siembench.py
│   ├── generate_dataset.py
│   ├── label_attck.py
│   ├── run_attck_coverage_audit.py
│   ├── run_evaluation.py
│   └── export_tables.py
│
├── evaluation/  evaluations/    extra evaluation runners / sampler / cache / metrics
├── run_eval.py                  production evaluation runner
├── wazuh_log_filter.py          replays SOC auth logs through a Wazuh rule (--explain)
├── rules/                       generated Wazuh rule files (output of --wazuh-rule-file)
│
├── src/
│   ├── agents/                  pipeline orchestration
│   │   ├── parser_agent.py            NL → IR (LLM + optional RAG, retry on failure)
│   │   ├── attck_classifier_agent.py  tactic / technique / sub-technique
│   │   ├── validator_agent.py         per-platform static syntax validation
│   │   ├── refinement_agent.py        self-critique re-prompt loop
│   │   ├── translation_orchestrator.py  main pipeline entry point
│   │   ├── execution_agent.py         live query execution (opt-in)
│   │   └── rule_deployment_agent.py   Wazuh rule deployment (opt-in)
│   │
│   ├── ir/                      IR schema and validation
│   │   ├── schema.py            IRQuery Pydantic model (core contribution)
│   │   ├── attck_schema.py
│   │   ├── validator.py         validate_ir() / coerce_ir() / validate_batch()
│   │   ├── ir_to_nl.py          reverse IR → NL (semantic verification)
│   │   └── examples.json        10 worked IR examples (few-shot source)
│   │
│   ├── translators/             per-platform translation
│   │   ├── base.py              BaseSIEMTranslator
│   │   ├── field_mapping.py     canonical field → per-platform field
│   │   ├── splunk.py · qradar.py · sentinel.py · wazuh.py
│   │   ├── elastic.py           IR → EQL / KQL (auto-routed by query shape)
│   │   └── esql_converter.py    EQL → ES|QL bridge
│   │
│   ├── connectors/              execution layer
│   │   ├── base.py · factory.py
│   │   └── elastic_connector.py · wazuh_connector.py · splunk_connector.py
│   │
│   ├── rag/                     local retrieval pipeline
│   │   ├── chunker.py · embedder.py (all-MiniLM-L6-v2) · vector_store.py (FAISS)
│   │   └── retriever.py · ingest.py
│   │
│   ├── evaluation/              benchmarking and scoring
│   ├── knowledge_base/          SIEM + MITRE reference docs used by RAG
│   │   └── elastic/ wazuh/ splunk/ qradar/ sentinel/ mitre/
│   ├── llm/                     client.py · prompts.py · response_parser.py · token_counter.py
│   └── utils/                   config.py · logger.py · file_io.py · exceptions.py
│
├── tests/connectors/            connector test scripts (Splunk, Wazuh)
└── sanity_check_layer_0.py · test_*.py · layer_3_test.py   development test suites
```

### Development tests

`python sanity_check_layer_0.py` passes (34/34). The layer test suites in
the repo root (`pytest test_layer_4.py`, `test_layer_5.py`,
`test_layer_6.py`, `test_llm_layer.py`; `python test_ir_schema.py`,
`python layer_3_test.py`) were written against earlier versions of the
schema and model registry and are **partly out of date** — some tests
fail against the current code. Treat them as development aids, not a
release gate, until they are updated.

---

## What is implemented vs. what is planned

**Implemented in this repo:**
- Full NL → ATT&CK classification → IR → 5-platform pipeline, callable
  end-to-end from Python and from `scripts/translate_query.py`
- IR schema with Pydantic v2 validation and LLM-output coercion (handles
  common aliasing mistakes: `"filter_aggregate"` → `"filter+aggregate"`,
  `"auth"` → `"authentication"`, etc.). `tactic` and `technique_id` are
  **required** IR fields, populated by the ATT&CK classifier agent
- All five platform translators, each with platform-specific operator
  mapping and a static syntax validator
- EQL → ES|QL bridge for filter+aggregate rules
- Free-tier LLM client (Groq, Gemini, Ollama, OpenRouter)
- Fully local RAG pipeline (chunk → embed → FAISS → retrieve)
- Self-correcting agent loop: parse → translate → validate → refine
- Elastic, Wazuh and Splunk connectors, plus Wazuh rule deployment
  (opt-in)
- Wazuh rule-file output and log replay with stage-by-stage `--explain`,
  used for validation against SOC authentication logs
- ATT&CK coverage auditor, evaluation harness, benchmark build scripts

**Not yet / not in this repo:**
- QRadar and Sentinel live-execution connectors
- EQL `sequence` conversion (raises `ESQLConversionError` by design)
- The generated SIEMBench split files (`data/` is gitignored; rebuild
  with the scripts above)
- An up-to-date, fully passing automated test suite

If you build on this for a CTF, hackathon, or research prototype, the
honest framing is: *intermediate representation + ATT&CK-bound
multi-agent translation is built and works; execution-backed validation
is implemented for Elastic and Wazuh, and broader execution coverage and
a refreshed test suite are the open items.*

---

## Adding a new SIEM target

Every translator inherits from `BaseSIEMTranslator`
(`src/translators/base.py`), which provides:

- `_resolve(field)` — canonical → platform field name via
  `field_mapping.py`
- `_map_op(operator)` — IR comparison operator → platform operator
  syntax
- `translate(ir) -> str` — the only method you call externally; wraps
  your `_translate()` with error handling

To add a sixth platform, subclass `BaseSIEMTranslator`, implement
`_translate(self, ir: IRQuery) -> str` and `validate(self, query: str)
-> bool`, add field mappings to `field_mapping.py`, and register the
translator wherever `translate_all()` dispatches across platforms
(`src/translators/__init__.py`).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `pip` fails on `torch==...+cpu` | Don't use pinned `+cpu` versions from PyPI. Use `pip install torch --index-url https://download.pytorch.org/whl/cpu` first, then `pip install -r requirements.txt`. |
| Install runs out of disk space | Default PyPI `torch` pulls CUDA libraries (several GB). Install the CPU build first (above). |
| Provider shows `groq` / "API key not set" even though `.env` has other values | Make sure you are running from the repo root and that `.env` is in the root (it is auto-loaded by `src/llm/client.py`). Alternatively export the variables in your shell. |
| `error: externally-managed-environment` | You're outside a virtualenv. Create/activate `venv` first (steps 2–3). |
| `ModuleNotFoundError: No module named 'src'` | Run from the repo root, e.g. `PYTHONPATH=. python scripts/label_attck.py ...`. |
| RAG ingest reports "0 chunks" | Pass `--kb-dir src/knowledge_base`. |
| "RAG store not found — falling back to few_shot" | Build the index (Installation, step 6). |
| `Field required: tactic / technique_id` when building an `IRQuery` by hand | Both are required; see the snippet in Installation step 5. |
| Wazuh/Splunk `EXECUTION FAILED … connection refused` | Expected when no SIEM is running; only occurs with `--execute` / `execute=True`. |
| `429 Too Many Requests` from Groq | Free-tier rate limit. The client retries; wait a minute between runs, add `--no-refine`, or check [console.groq.com/docs/rate-limits](https://console.groq.com/docs/rate-limits). |
| Groq `401 Unauthorized` | The key is wrong or revoked. Create a new one (Installation, step 4a) and update `.env`. |
| Embedding model download fails | First RAG use needs internet access to Hugging Face once; afterwards it is cached. |
| `wazuh_log_filter.py` reports `0 alerts` | Re-run with `--explain`. The funnel shows which stage (parent rule, a `<match>` condition) removed the events. |
| Log timestamps look wrong or nothing matches by date | Syslog lines carry no year. Pass `--year` with the year of the log. |
| `my_rule.xml` not created | The Wazuh platform was excluded (`-p`) or `--wazuh-rule-file ''` was passed, or no Wazuh rule was generated (a warning is printed). |

---

## Limitations

- EQL sequence constructs are not converted by the current bridge.
  `ESQLConversionError` is raised explicitly rather than emitting an
  approximate translation. Sequence support is the next roadmap item.
- Splunk live-execution validation is pending, and QRadar and Sentinel
  have no execution connectors yet. Translation agents for all five
  platforms are functional.
- The RAG retrieval layer uses `all-MiniLM-L6-v2`, a general-purpose
  encoder not fine-tuned on security text. Techniques with similar
  surface descriptions are a known misclassification risk.
- Retrieval hyperparameters (k=5 classifier, k=2 per platform for
  translators) were set heuristically.
- Static validation checks structure only; it does not prove a rule
  detects the intended behavior on your data.
- The Wazuh log filter emulates stock Wazuh authentication rule parents offline.
  It is not the Wazuh engine, covers Linux syslog sources only, and does not replace
  confirmation with `wazuh-logtest`.

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
@article{
  title   = {Detecting What You Think You Detect: Cross-Platform SIEM
             Query Generation and ATT\&CK Coverage Drift Prevention
             via Intermediate Representation and Multi-Agent LLMs},
  author  = {Dr. Swetha ,  Shubham Dattatraya Bhat},
  year    = {2026},
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
