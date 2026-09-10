# exploit-path-traversal — documentation

AI-assisted, staged path-traversal discovery and verification toolkit.
Run as `exploit-path-traversal`. Use only against systems you are authorised to test.

Path traversal detection is a **black-box behavioural test** — you send an input
and infer a vulnerability from the response. There is no "100 %". Every part of
this tool is built toward one goal:

> **maximise the true-positive detection rate across encoding / normalisation
> variants while keeping false positives near zero.**

## The pipeline

| Stage | Command | Input | Output | Doc |
|------:|---------|-------|--------|-----|
| 1 | `stage1` | a URL to crawl and/or OpenAPI / HAR / Postman files | `stage1-vectors.json` | [stage-1.md](stage-1.md) |
| 2 | `stage2` | `stage1-vectors.json` (or a target surface — runs stage 1 first) | `stage2-findings.json` | [stage-2.md](stage-2.md) |
| 3 | `stage3` | `stage1-vectors.json` (or a target surface — runs stage 1 first) | `stage3-findings.json` | [stage-3.md](stage-3.md) |
| 4 | `report` | `stage2-findings.json` (+ the stage 1 artifact) | `report.md` | [stage-4-report.md](stage-4-report.md) |

Stage 3 is **tiered mechanism-attribution probing**: it organizes traversal
test inputs into tiers based on the defensive mechanism they target, so every
finding is attributed to *which parser / filter / validation layer was
bypassed* rather than merely "a payload worked".

## Documents

| File | What it covers |
|------|----------------|
| [architecture.md](architecture.md) | package layout, data flow, design principles |
| [configuration.md](configuration.md) | environment / `.env`, every CLI flag, HTTP controls |
| [data-model.md](data-model.md) | `RawRequest`, `InputVector`, the two JSON artifacts, the findings schema |
| [stage-1.md](stage-1.md) | **every step** Stage 1 performs |
| [stage-2.md](stage-2.md) | **every step** Stage 2 performs |
| [stage-3.md](stage-3.md) | **every step** Stage 3 performs — the tiered mechanism-attribution model |
| [stage-4-report.md](stage-4-report.md) | how the Markdown report is built |
| [payloads.md](payloads.md) | the encoding taxonomy, canaries, depth ladder, write-side payloads |
| [verdicts.md](verdicts.md) | how a response is classified; thresholds and confidence values |
| [agent.md](agent.md) | the AI layer in both stages, and the parked "agent role" decision |
| [scoring.md](scoring.md) | the deterministic traversal-relevance score and the A–L coverage model |
| [limitations.md](limitations.md) | what the tool cannot see, and why |
| [labs.md](labs.md) | the five local vulnerable labs used for end-to-end verification |

## Quick start

```bash
./install.sh
cp .env.example .env          # fill in EPT_AI_BASE_URL / _MODEL / _API_KEY (optional)

# one shot: crawl + enumerate + probe
exploit-path-traversal stage2 -u https://target.example.com

# tiered mechanism-attribution probing
exploit-path-traversal stage3 --in ./ept-out/stage1-vectors.json

# or step by step
exploit-path-traversal stage1 -u https://target.example.com --openapi ./api.yaml
exploit-path-traversal stage2 --in ./ept-out/stage1-vectors.json
exploit-path-traversal stage3 --in ./ept-out/stage1-vectors.json
exploit-path-traversal report --in ./ept-out/stage2-findings.json
```

The AI layer is optional. Without `EPT_AI_*` set, all stages run fully on their
deterministic paths and say so.
