# exploit-path-traversal

AI-assisted, staged path-traversal discovery and verification toolkit.

Use it only against systems you are **authorized** to test.

**Full documentation is in [`docs/`](docs/README.md)** — including
[stage-1.md](docs/stage-1.md) and [stage-2.md](docs/stage-2.md), which walk
through every step the tool performs.

> Successor to the old `path-traversal` encoding brute-forcer. That single-file
> tool has been removed; its encoding taxonomy (`encoding-techniques.md`) is
> distilled into `probe/payloads.py` and documented in
> [docs/payloads.md](docs/payloads.md).

## What it is

Path traversal detection is a blackbox behavioral test — there is no "100%".
The tool is built to **maximize true-positive rate across
encoding/normalization variants while keeping false positives near zero**, in
four stages:

| Stage | Name | Status |
|------:|------|--------|
| 1 | Input-vector enumeration | **available** (`stage1`) |
| 2 | Baseline-first differential probing | **available** (`stage2`) |
| 3 | Verification / evidence | folded into Stage 2 (reproduce + round-trip; real OOB still planned) |
| 4 | Markdown report | **available** (`report`) |

See [DESIGN.md](DESIGN.md) for architecture and roadmap.

## Install

```bash
git clone <this repo> && cd path-traversal
./install.sh
```

`install.sh` uses `pipx` if present, otherwise builds a project virtualenv and
symlinks `exploit-path-traversal` into `~/.local/bin`.

Requires Python 3.9+. Runtime dep: `httpx`. `PyYAML` is optional (only for YAML
OpenAPI specs — JSON specs need nothing).

## AI agent config

The agent talks to any OpenAI-compatible `/chat/completions` API. Copy
`.env.example` to `.env` in your working directory, or export:

```bash
export EPT_AI_BASE_URL=https://api.openai.com/v1
export EPT_AI_MODEL=gpt-4o-mini
export EPT_AI_API_KEY=sk-...
```

Without these, Stage 1 still runs with deterministic scoring only and tells you
the AI pass was skipped. Use `--no-ai` to force that.

## Stage 1 — input-vector enumeration

Builds a source-to-sink dataflow inventory: every attacker-influenced value
that could reach, select, construct, modify, resolve, or indirectly determine a
filesystem path — not just params named `file`/`path`. Each vector is scored for
traversal-relevance (rule-based, then refined by the agent) and tagged with a
coverage dimension (A–L).

### Usage

```bash
# crawl a site
exploit-path-traversal stage1 -u https://target.example.com

# crawl + import an API spec and a proxy capture
exploit-path-traversal stage1 -u https://target.example.com \
    --openapi ./openapi.yaml --har ./session.har

# spec only, no crawl, no AI
exploit-path-traversal stage1 --openapi ./swagger.json --no-ai

# authed crawl, tighter scope, slower
exploit-path-traversal stage1 -u https://app.example.com \
    --scope app.example.com,api.example.com \
    -H 'Authorization: Bearer eyJ...' -b 'session=abc123' \
    --depth 3 --rate 2
```

### Key options

| Flag | Meaning |
|------|---------|
| `-u, --url` | base URL to crawl |
| `--seed URL` | extra seed URL (repeatable) |
| `--openapi / --har / --postman FILE` | import a spec/capture (repeatable) |
| `--scope hosts` | comma-separated host allowlist (default: seed's registrable domain) |
| `--depth / --max-pages` | crawl bounds (default 2 / 200) |
| `--rate / --timeout` | requests/sec and per-request timeout (default 5 / 15) |
| `--no-js` | skip JavaScript endpoint extraction |
| `-H 'K: V'` / `-b 'k=v'` | extra header / cookie (repeatable) |
| `--insecure` | skip TLS verification |
| `--no-ai` | deterministic scoring only |
| `--app-hint` | one line about the app, passed to the agent |
| `-o, --out DIR` | output directory (default `./ept-out`) |
| `--json-only` | write JSON, skip the terminal summary |

### Output

- terminal: header, crawl/import stats, top vectors by relevance, the A–L
  coverage matrix with gap notes
- `<out>/stage1-vectors.json`: the full inventory — the input to Stage 2

Output style is deliberately plain: bold/dim only, honours `NO_COLOR` and
non-TTY, no decorative symbols.

## Stage 2 — baseline-first differential probing

For each selected vector: establish a **known-good baseline** fingerprint and a
**negative control** (well-formed missing resource), then send traversal
payloads and classify each response by *how it differs from normal behavior* —
never on status code alone. Verdicts: `confirmed` (canary file content in the
body), `likely` (unlike baseline and control, shaped like a file read; or a
reflected escaped upload path), `inconclusive`, `not-vulnerable`. Confirmed /
likely findings are re-sent to check they reproduce.

### Usage

```bash
# run stage 1 then probe, in one go
exploit-path-traversal stage2 -u https://target.example.com

# probe an existing stage 1 artifact
exploit-path-traversal stage2 --in ./ept-out/stage1-vectors.json

# from an API spec, Windows canary, only JSON-body vectors, force a baseline
exploit-path-traversal stage2 --openapi ./api.json --canary windows \
    --location json-body --baseline 'report=q3-report.txt'
```

### Key options

| Flag | Meaning |
|------|---------|
| `--in FILE` | `stage1-vectors.json` to probe (else give `-u`/`--openapi`/… to run stage 1 first) |
| `--min-relevance` | only probe vectors at/above this score (default 0.4) |
| `--location` | comma-separated locations to probe (`query,json-body,…`) |
| `--only ID` | probe just one vector id (repeatable) |
| `--baseline 'name=value'` | force a known-good value for a field (repeatable) |
| `--canary` | `unix` (default, `/etc/passwd`), `windows`, or `both` |
| `--depth-max` | max `../` depth (default 6) |
| `--max-payloads` | payload cap per vector (default 60) |
| `--thorough` | more canary targets + payloads |
| `--no-ai` | skip AI adjudication of likely/inconclusive findings |
| `--rate` / `--timeout` / `--insecure` / `-H` / `-b` | HTTP controls (as in stage 1) |

### Output

- terminal: verdict counts, then each non-clean finding with its winning
  payload, signals, AI note (if any), and a `curl --path-as-is` repro line
- `<out>/stage2-findings.json`: every finding with baseline + control
  fingerprints and the full probe list

### Limitations

- upload/write-side traversal is `confirmed` only if the escaped file is
  reachable via a guessed URL; otherwise it caps at `likely` (no OOB channel yet)
- suffix-constrained sinks (app appends `.txt`) may read `inconclusive` /
  `not-vulnerable` for the `/etc/passwd` canary even though traversal-shaped
  (null-byte variants are tried but modern runtimes reject them)
- raw `../` in a URL path isn't sent (httpx normalizes it) — only encoded
  separators for path-segment vectors

## Stage 4 — Markdown report

```bash
exploit-path-traversal report --in ./ept-out/stage2-findings.json
```

Writes `report.md`: summary counts, an actionable-findings table, per-finding
detail (winning payload, similarity, signals, baseline + control fingerprints,
AI note, `curl --path-as-is` repro), a not-vulnerable appendix, and the Stage 1
A–L coverage matrix (auto-loaded from the sibling `stage1-vectors.json`).
