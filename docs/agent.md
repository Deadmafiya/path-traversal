# The AI layer

The agent is **optional and thin**. Deterministic code does all crawling,
parsing, payload synthesis, probing and the final verdicts. The AI is a
refinement pass, never a driver. With `EPT_AI_*` unset (or `--no-ai`), both
stages run fully and report `ai.enabled = false` with the reason.

## Client (`agent/client.py`)

`AIClient.chat_json(system, user)` → `POST {base_url}/chat/completions` with
`model`, a system + user message, `temperature`, `max_tokens`, and
`response_format: {type: "json_object"}`. On a 400 that mentions
`response_format`, it retries without that field. The reply content is parsed by
`_extract_json`, which:

1. tries a fenced ```` ```json … ``` ```` block, then the largest `{…}`/`[…]`,
   then the whole string
2. if all fail, strips a lone opening fence and runs `_close_truncated`: walks
   the JSON tracking string/escape state and bracket depth, drops an incomplete
   trailing token, and appends the missing `"`/`}`/`]` — so a response cut off
   mid-array still yields its complete elements

This matters for slow / token-limited models that truncate.

## Stage 1 — refinement (`agent/classifier.py`, `agent/prompts.py`)

Runs after rule-scoring. Vectors are sent in batches of `EPT_AI_BATCH_SIZE`
(25). For each batch the model returns compact JSON:

- `scored[]` — `{id, relevance 0-1, reason ≤12w, path_role?, fs_operation?}`
  → merged into `ai_relevance` / `ai_reason` (and `path_role` / `fs_operation`
  if valid)
- `inferred_vectors[]` (≤5) — vectors enumeration likely missed (derived,
  second-order, JWT claims, cache/temp/log filenames, internal-service fields,
  archive entries) → new `InputVector`s, `source="ai-inferred"`, `request_ref=-1`
  (reported, never probed)
- `coverage_gaps[]` (≤4) — under-explored A–L dimensions → merged into the
  report's gap list

A batch that errors or returns a non-object is recorded in `ai.errors` and
skipped.

## Stage 2 — adjudication (`agent/verify.py`)

Runs only for `likely` / `inconclusive` findings where a baseline was accepted.
The model is given the vector identity, the winning payload, and three response
bodies (baseline, negative control, payload) and returns
`{verdict, confidence, reason}`.

- `not-vulnerable` @ ≥0.8 → finding becomes `not-vulnerable`
- `not-vulnerable` @ <0.8 → confidence lowered
- `likely` / `confirmed` → confidence raised (the deterministic verdict is **not**
  upgraded by the AI)

Deterministic `confirmed` and `not-vulnerable` are never sent.

## REVISIT — the "agent role" decision (parked)

The operator explicitly flagged this area to revisit **after real-target
experience**, and chose to keep it parked for now. The current design is the
thin hybrid above. A future change is expected to move more decision-making into
the agent — likely a tool-calling loop where the agent chooses what to crawl /
probe next.

Keep the seam clean. The touch points are:

- `stages/stage1.py` step 4 ↔ `agent/classifier.py` + `agent/prompts.py`
- `stages/stage2.py` step 10 ↔ `agent/verify.py`
- `agent/client.py` — currently one `chat_json` call; a loop would add
  tool-call plumbing here

Crawling, extraction, scoring, payloads and the differ must not need to change
when the agent's role expands.
