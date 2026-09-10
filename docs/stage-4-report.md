# Stage 4 — Markdown report

**Command:** `exploit-path-traversal report --in <stage2-findings.json>`
**Entry point:** `report/report_md.py::write_report`
**Output:** `<out>/report.md`

## Steps

1. Load `stage2-findings.json` (`--in`).
2. Load the Stage 1 artifact for the coverage table: `--stage1 <file>`, else the
   sibling `stage1-vectors.json` next to `--in` if present. Missing / unreadable
   → the coverage section is simply omitted.
3. `render(stage2, stage1)` builds the Markdown:

   - **Header** — tool version, generated time (from `started`), source artifact,
     target (from Stage 1), the probing config (`canary`, `depth_max`,
     `max_payloads`, AI on/off), duration, and a standing disclaimer that this is
     a black-box test and every finding must be verified.
   - **Summary** — a verdict-count table (`confirmed` / `likely` / `inconclusive`
     / `not vulnerable` / vectors probed) and, if there are any `confirmed` /
     `likely` findings, an actionable table (`# | verdict | confidence |
     endpoint | vector`).
   - **Findings** — every finding except `not-vulnerable`, ordered
     `confirmed → likely → inconclusive → error`, then by confidence. Per
     finding: endpoint, Stage 1 relevance, reproduced flag, round-trip URL,
     winning payload (label, note, value, status, length), body similarity vs
     baseline / control, the signal list, baseline (`value` + fingerprint, or
     "unavailable" + note), negative control (value + fingerprint), AI
     adjudication, and a fenced `curl --path-as-is` repro block.
   - **Probed, not vulnerable** — a compact list (endpoint, vector, payload
     count) so the report shows what was tested and cleared.
   - **Stage 1 coverage (A–L)** — the dimension / status / count / area table,
     when the Stage 1 artifact was found.
   - **AI errors** — any `ai_errors` from Stage 2.

4. Write `<out>/report.md`.

The report is plain Markdown (tables + fenced code), suitable for pasting into a
ticket or a PR. It contains no colour and no tool-internal jargon beyond the
verdict names.
