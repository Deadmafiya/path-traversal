# Stage 2 — baseline-first differential probing

**Command:** `exploit-path-traversal stage2`
**Entry point:** `exploit_path_traversal/stages/stage2.py` → `run(opts, settings, log)`
**Input:** `stage1-vectors.json` (via `--in`, or produced on the fly from a target surface)
**Output:** `<out>/stage2-findings.json`

The core rule: **never ask "did the payload return 200?"** Ask "how does this
response differ from the application's known-good behaviour, and is that
difference caused by filesystem path resolution?" Every verdict is a comparison
against a per-vector **baseline** (a known-good value) and a **negative control**
(a well-formed but non-existent value).

---

## Pipeline overview

```
0. obtain a stage 1 artifact           (run stage 1 first if only -u/specs given)
1. select vectors to probe             (min-relevance, location, id filters)
   for each selected vector:
     2. build the request template      (probe/prepared.from_template)
     3. establish the baseline          (probe/baseline.establish)      -> baseline fingerprint
     4. build the negative control      (probe/baseline.negative_control)
     5. choose the payload set          (probe/payloads: read vs write, extension-aware)
     6. probe loop                      (probe/fingerprint.capture + probe/differ.classify)
        -> best verdict for this vector
     7. write-side round-trip           (only for multipart "likely")
     8. suffix-constrained note         (read-side, baseline value has an extension)
     9. reproduction gate               (re-send the winning payload 2x)
    10. AI adjudication (optional)      (agent/verify.adjudicate)
    11. assemble the finding record
12. sort findings, write stage2-findings.json
```

---

## Step 0 — Obtain a Stage 1 artifact

- `--in <file>` → used directly.
- otherwise, if `-u` / `--seed` / `--openapi` / `--har` / `--postman` was given,
  Stage 1 is run in-process (`stages/stage1.py::run`), its artifact written to
  `<out>/stage1-vectors.json`, and that path used.
- neither → error, exit 2.

`Settings.load` runs exactly as in Stage 1 (env / `.env`, `EPT_AI_*`).

The artifact is read as JSON: `vectors[]`, `request_templates[]` are the two
pieces Stage 2 needs; `harvested_values` was already folded into each vector's
`baseline_candidates` during Stage 1.

---

## Step 1 — Select vectors

A vector is **picked** when all hold:

1. `relevance >= --min-relevance` (default **0.4**)
2. if `--location` was given, `vector.location` is in that comma list
3. if `--only <id>` was given (repeatable), `vector.id` matches
4. `vector.request_ref` is a valid index into `request_templates`
   (AI-inferred vectors have `request_ref = -1` and are skipped — they were
   never observed)

`ai-inferred` vectors are intentionally not probed; they are hypotheses for a
human to check.

The shared `HttpClient` is created once (`--rate` default 6/s, `--timeout` 15 s,
`--insecure`, `-H`, `-b`). `AIClient` is created; `ai_on` = `--no-ai` not set and
`AIConfig.enabled`.

---

## Step 2 — Build the request template

`probe/prepared.py::from_template(template, vector)` → a `Prepared` object:

- `method`, `url_base` (`scheme://host/path`, no query)
- `query{}`, `headers{}`, `cookies{}` copied from the template
- body: `body_kind` (`json` / `form` / `multipart` / `""`); for JSON the flat
  `body_fields` are **un-flattened** into a nested dict (`"a.b"` → `{a:{b:…}}`);
  for form/multipart they stay flat
- `multipart_field` = the file-part field name (from `multipart_filenames`)
- the injection target: `inj_location`, `inj_name`, `inj_nested`

`Prepared.build(value)` produces the concrete httpx kwargs with `value` placed in
exactly one spot. **How the value is injected matters** — the payload must reach
the server unchanged:

| `inj_location` | how `value` is placed | why |
|----------------|-----------------------|-----|
| `query` | the full URL is assembled as a string; every key/value is quoted with `safe="/%"` so `../` stays `../` and `%2e%2e%2f` stays intact. httpx does **not** re-encode a query string handed to it in the URL. `params=` is never used (it would turn `%2e` into `%252e`). | verbatim payload |
| `url-path-segment` | `_inject_path`: replace a `{name}` / `:name` / `*` token in the path; if there is no token, append `"/" + value` to the path. Path is quoted `safe="/%"`. | httpx **collapses `../` in a URL path**, so path-segment payloads use encoded separators only (see step 5) |
| `cookie` | `cookies[name] = value` | sent literally |
| `header` | `headers[name] = value` | sent literally |
| `json-body` | deep-copy the nested body, set the dotted `inj_nested` (or `inj_name`) to `value`, send as `json=` | literal string value |
| `form` | `data[name] = value` | literal |
| `multipart` | `files = { <file-field>: (value, b"probe-content-ept", "application/octet-stream") }` — `value` becomes the **filename** of the part; other fields go in `data=` | classic upload-filename traversal |

`Prepared.curl(value)` renders the same request as a
`curl -sk --path-as-is -X … '<url>'` one-liner for the report / repro.

---

## Step 3 — Establish the baseline

`probe/baseline.py::establish(client, prepared, candidates, repeats=3)`:

`candidates` = the vector's `baseline_candidates` (step 3.3 of Stage 1), with any
`--baseline 'name=value'` override prepended.

For each candidate value, in order:

1. record it in `tried`
2. send `prepared.build(candidate)` and capture a `Fingerprint`
3. **accept** it if the response "looks normal": transport OK **and** status ∈
   {200, 201, 203, 206, 301, 302, 307, 308}
4. on acceptance: re-send the same request `repeats-1` more times; compute the
   minimum body similarity across the repeats → `self_similarity`.
   `dynamic = self_similarity < 0.98` (the page changes between identical
   requests — timestamps, tokens, ads). This loosens later comparisons.
5. return `Baseline(accepted=True, value, fp, dynamic, self_similarity, tried)`

If **no** candidate produced a normal response, `Baseline.accepted = False` with
a note. Probing still runs (canary hits and write-side signals do not need a
baseline), but `differs_from_baseline` can never fire, so read-side findings
without a canary cap at `inconclusive`.

### The Fingerprint (`probe/fingerprint.py`)

`capture()` sends one request and records: `status`, `length` (bytes),
`body_sha1`, `content_type` (before `;`), `location` header, `elapsed_ms`,
redirect count, and `body_sample` (first 8 kB of decoded text). Transport
failure → `transport_ok = False` with the error.

`similarity(a, b)` = `difflib.SequenceMatcher` ratio over **normalised** bodies
(lower-cased, first 4 kB, with volatile tokens masked: long hex, ISO timestamps,
`csrf_token`-style values, collapsed whitespace).

---

## Step 4 — Negative control

`probe/baseline.py::negative_control(client, prepared, baseline_value)`:

`_mangle(baseline_value)` produces a well-formed but non-existent sibling, shape
preserved:

- empty → `nx-<rand>`
- absolute / URL-ish → `/nx-<rand>/nope-<rand>.dat`
- has an extension → `<stem>-nx<rand><ext>` (e.g. `report.txt` → `report-nx3f1a.txt`)
- otherwise → `<value>-nx<rand>`

Sent once; the `Fingerprint` is the "how the app answers a missing file"
reference. `<rand>` is `secrets.token_hex(3)`.

---

## Step 5 — Choose the payload set

### Read-side (`inj_location != "multipart"`)

`probe/payloads.py::generate(canary, depth_max, thorough, ext)`:

- **canary** (`--canary`): `unix` → target `etc/passwd`, regex `root:.*?:0:0:`
  (and `etc/hostname` when `--thorough`); `windows` → `windows/win.ini`, regex
  `\[fonts\]|\[extensions\]`; `both` → both families.
- **absolute payloads** (depth 0, no traversal): `/etc/passwd`, `%2f etc/passwd`,
  `//etc/passwd`, `/./etc/passwd`.
- **encoding families**, each emitted for every depth `1..depth_max`
  (`--depth-max`, default 6):

  | label | separator | note |
  |-------|-----------|------|
  | `raw` | `../` | plain (excluded for `url-path-segment` — httpx collapses it) |
  | `slash-enc` | `..%2f` | encoded slash |
  | `dot-slash-enc` | `%2e%2e%2f` | fully encoded |
  | `dot-enc` | `%2e%2e/` | encoded dots only |
  | `double-enc` | `%252e%252e%252f` | double-encoded |
  | `quad-dot` | `....//` | filter-collapse bypass |
  | `semicolon` | `..;/` | path-parameter split |
  | `backslash-enc` | `..%5c` | encoded backslash (Windows filters) |
  | `overlong-utf8` | `%c0%ae%c0%ae%c0%af` | IIS overlong UTF-8 |

- `leading-slash:d<n>` = `/` + `../`×n + target, per depth.
- `nullbyte:d<n>` = `../`×n + target + `%00`, per depth.
- **if the baseline value has an extension** (`ext`): `nullbyte-ext:d<n>` and
  `nullbyte-ext-enc:d<n>` = the traversal + `%00.<ext>`, per depth — for sinks
  that append an extension server-side.

**Ordering is encoding-major, depth-minor**: absolutes, then all `raw` depths,
then all `slash-enc` depths, … so the first *N* payloads sample every encoding
across the depth range rather than every encoding at depth 1. The set is then
filtered to payloads whose `kinds` include the vector's location and capped at
`--max-payloads` (default **90**). Read-payload sets are cached per
`(canary, ext)` within a run.

### Write-side (`inj_location == "multipart"`)

`probe/payloads.py::generate_write(marker, content, depth_max)`:

- a unique benign filename `ept-wr-<hex>.txt` and unique content
  `EPT-ROUNDTRIP-<hex>`
- **climb-only, never absolute, never a system path** — payloads are
  `<sep>×n + marker` for `sep` ∈ {`../`, `..%2f`, `%2e%2e%2f`, `....//`, `..\`},
  depths `1..min(depth_max, 8)`
- `kinds = ("multipart",)`, `canary_re` = the marker

This set can never overwrite `/etc/passwd` or anything outside the upload tree —
the worst case is a benign file one or more directories above the intended one,
which step 7 then tries to read back.

---

## Step 6 — Probe loop

For each payload `p` in the (capped, filtered) set:

1. `fp = capture(client, method, prepared.build(p.value))`
2. `diff = probe/differ.py::classify(fp, p, baseline, control, write_side=…)`
   — see [verdicts.md](verdicts.md). In short:
   - transport failure → `error`
   - **read-side** and `p.canary_re` matches the body → **`confirmed`**, 0.97
   - **write-side** and (the body reflects an escaped path / the marker with a
     separator, **or** a filesystem error the baseline did not raise) and the
     response is not identical to the control → **`likely`**, 0.55
   - body ≈ negative control (same status and similarity ≥ 0.97 or identical
     sha1) → **`not-vulnerable`**
   - differs from baseline (status, sha1 + low similarity, > 25 % length delta,
     or content-type flip) **and** looks like a file read (200/206, non-empty,
     unlike the control) → **`likely`**, 0.62 (+0.1 if a stack trace / FS error
     is in the body)
   - differs from baseline but ambiguous, or a WAF/5xx status → **`inconclusive`**, 0.3
   - otherwise → **`not-vulnerable`**
3. append a compact probe record (`payload`, `value`, `verdict`, `confidence`,
   `status`, `length`, `canary_hit`, `signals`)
4. keep the **best** result so far (strongest verdict; ties broken by confidence).
   Verdict strength: `confirmed > likely > inconclusive > error > not-vulnerable`.
5. **early exit**: the first payload that produces a read-side canary hit stops
   the loop (proof already obtained).

---

## Step 7 — Write-side round-trip confirmation

Only when `write_side` and the best verdict is `likely` and there is a winning
payload with a `marker`:

1. Try to `GET` the uploaded file back at guessed locations:
   `<origin>/<marker>`, `<origin><base_path>/<marker>`, `<origin>/uploads/<marker>`,
   `<origin>/static/<marker>`, `<origin>/files/<marker>`.
2. If any returns `< 400` **and** the body contains the unique
   `EPT-ROUNDTRIP-<hex>` content → the write escaped the intended directory:
   verdict → **`confirmed`**, confidence **0.95**, `round_trip_url` recorded.
3. If none match → the finding stays `likely` with a note that the file could
   not be located and needs out-of-band confirmation.

There is no external OOB channel yet, so a write that lands somewhere not served
over HTTP stays `likely`.

---

## Step 8 — Suffix-constrained note (read-side)

If the baseline value had an extension and the best verdict is `likely` /
`inconclusive` (not `confirmed`), a signal is added: the sink may append an
extension, so the `/etc/passwd` canary may be unreachable without null-byte
tricks (which modern PHP/Python reject). The vector is flagged as
traversal-shaped for a human to pursue with an extension-matching target.

---

## Step 9 — Reproduction gate

Only when the best verdict is `confirmed` / `likely` **and** it was not already
confirmed by a round-trip:

1. Re-send the winning payload **twice**.
2. Each response is re-classified; count how many come back `confirmed` /
   `likely`.
3. `reproduced = (both did)`.
4. If it did **not** reproduce both times: append `did NOT reproduce (2x)`,
   downgrade one level (`confirmed → likely`, `likely → inconclusive`), and
   halve the confidence.

---

## Step 10 — AI adjudication (optional)

Only when `ai_on`, the best verdict is `likely` / `inconclusive`, and a baseline
was accepted. `agent/verify.py::adjudicate` sends the model:

- the vector identity, the winning payload
- the **baseline** response (summary + up to ~1.5 kB of body)
- the **negative control** response
- the **payload** response

The system prompt asks: is this best explained by successful traversal / file
disclosure, versus normal behaviour, an error, or a WAF block? It returns
`{verdict, confidence, reason}`.

Merge rules:

- AI `not-vulnerable` with confidence ≥ 0.8 → finding becomes `not-vulnerable`,
  confidence 0, with the reason recorded
- AI `not-vulnerable` below 0.8 → confidence lowered to `min(current, ai)`
- AI `likely` / `confirmed` → confidence raised to `max(current, ai)` (the
  deterministic verdict is **not** upgraded by the AI)

Deterministic `confirmed` and `not-vulnerable` verdicts are never sent for
adjudication — the AI only breaks ties in the middle.

---

## Step 11 — Assemble the finding record

One object per probed vector (`stage2-findings.json → findings[]`):

```
vector_id, endpoint, method, location, field, relevance
verdict            confirmed | likely | inconclusive | not-vulnerable | error
confidence         0.0 – 0.97
reproduced         true | false | null
winning_payload    { name, value, note, status, length }   (null if not-vulnerable)
signals            [ human-readable reasons, in order ]
similarity         { vs_baseline, vs_control }
baseline           { accepted, value, dynamic, tried, note, fingerprint }
negative_control   { value, fingerprint }
ai_adjudication    { verdict, confidence, reason } | null
round_trip_url     "<url>" | null
repro_curl         "curl -sk --path-as-is ..."
probe_count, probes[ { payload, value, verdict, confidence, status, length, canary_hit, signals } ]
```

A vector with no applicable payloads yields an `error` finding
(`no payloads apply to location '<x>'`).

---

## Step 12 — Sort and write

Findings are sorted `confirmed → likely → inconclusive → error → not-vulnerable`,
then by descending confidence. `report/stage2_writer.py::write_json` writes
`<out>/stage2-findings.json`; unless `--json-only`, `print_summary` prints the
verdict counts and each non-clean finding with its winning payload, signals, AI
note, round-trip URL and `curl` repro.

The top-level object also carries `config` (the probing parameters used),
`counts` (per verdict), `duration_sec`, and `ai_errors`.

---

## Worked examples (local labs)

| Lab | Vector | What Stage 2 does | Verdict |
|-----|--------|-------------------|---------|
| `app.py` `?file=` | `query:file`, baseline `report.txt` | control `report-nxXXXX.txt` → 404; payload `absolute` `/etc/passwd` → 200, body matches `root:.*:0:0:` | **confirmed** 0.97 |
| `app3.py` static server | synthetic `url-path-segment:*`, baseline `index.html` | raw `../` excluded (httpx collapse); `slash-enc:d6` `..%2f…%2fetc%2fpasswd` → canary match | **confirmed** 0.97 |
| `app4.py` upload | `multipart:file` | `generate_write` marker; server 500s on the traversal filename → `likely`; round-trip GETs all 404 (file not web-served) | **likely** 0.55 |
| `app5.py` `POST /api/export` | `json-body:report` | payload sent as the literal JSON string `../../../etc/passwd` (no encoding needed) → canary match | **confirmed** 0.97 |
| `app5.py` cookie `theme` | `cookie:theme` | sink is `themes/<theme>.txt`; `/etc/passwd` never reachable; null-byte rejected → response ≈ control | **not-vulnerable** (+ suffix note on the path-segment sibling) |
