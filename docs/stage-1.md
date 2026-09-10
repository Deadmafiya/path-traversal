# Stage 1 — input-vector enumeration

**Command:** `exploit-path-traversal stage1`
**Entry point:** `exploit_path_traversal/stages/stage1.py` → `run(opts, settings, log)`
**Output:** `<out>/stage1-vectors.json`

Stage 1 builds a **source-to-sink dataflow inventory**: every attacker-influenced
value that could, alone or after transformation / lookup / combination, reach,
select, construct, modify, resolve or indirectly determine a filesystem path —
not only parameters named `file` or `path`. Each value becomes one scored
`InputVector` record.

The goal is coverage, not payloads. No traversal string is sent in Stage 1
(other than ordinary crawling).

---

## Pipeline overview

```
0. load configuration
1. import spec / capture files      (spec/)          -> RawRequest[]
2. crawl the live target            (crawl/)         -> RawRequest[]  (+ harvested ids)
3. extract + rule-score             (vectors/)       -> InputVector[]  (+ request_templates)
4. AI refinement pass (optional)    (agent/)         -> adjusted scores, inferred vectors, gaps
5. rank + compute A–L coverage      (vectors/coverage)
6. write stage1-vectors.json        (report/writer)
```

If neither a crawl surface nor a spec produced any `RawRequest`, Stage 1 stops
after step 2 with a note (`no request surface discovered`).

---

## Step 0 — Configuration

`Settings.load(env_file)` (`config.py`):

1. Read `./.env` (or `--env-file`) with a minimal `KEY=VALUE` parser (ignores
   blanks / `#` comments, strips quotes).
2. Overlay the process environment (process env wins over `.env`).
3. Resolve the AI config, first name found wins:
   - base URL: `EPT_AI_BASE_URL` → `OPENAI_BASE_URL` → `OPENAI_API_BASE`
   - model: `EPT_AI_MODEL` → `OPENAI_MODEL`
   - key: `EPT_AI_API_KEY` → `OPENAI_API_KEY`
   - tuning: `EPT_AI_TEMPERATURE` (0.0), `EPT_AI_MAX_TOKENS` (8192),
     `EPT_AI_TIMEOUT` (90 s), `EPT_AI_BATCH_SIZE` (25)
4. `AIConfig.enabled` is true only if base URL **and** model **and** key are all
   present. CLI flags override everything.

`Stage1Options` is filled from the CLI: `url`, `seeds[]`, `spec_files[]`,
`scope[]`, `depth`, `max_pages`, `rate`, `timeout`, `verify_tls`, `headers{}`,
`cookies{}`, `use_ai`, `app_hint`, `parse_js`.

---

## Step 1 — Import specs / captures

For each file in `--openapi` / `--har` / `--postman` (all repeatable),
`spec/__init__.py::load_any(path)`:

1. Read the file. Parse as JSON; if that fails and the extension is
   `.yaml` / `.yml` (or JSON parsing raised), parse as YAML (needs PyYAML;
   a clear error is raised if it is missing).
2. Detect the format from the parsed object:
   - has `openapi` or `swagger` key → **OpenAPI** (`spec/openapi.py`)
   - has `log.entries` → **HAR** (`spec/har.py`)
   - has `info` and (`item` or `requests`) → **Postman v2.x** (`spec/postman.py`)
3. Dispatch to that parser, which returns `list[RawRequest]`.

### OpenAPI (`spec/openapi.py::parse`)

- Base URL from `servers[0].url` (OpenAPI 3) or `schemes[0] + host + basePath`
  (Swagger 2); fallback `http://spec.local/`.
- `$ref` pointers are resolved (up to 10 hops, local `#/...` only).
- For every `paths.<path>.<method>` where method ∈
  get/post/put/delete/patch/head/options:
  - one `RawRequest(method, url=base+path, protocol="rest", source="openapi")`
  - path-level + operation-level `parameters`:
    - `in: path` → `path_params[name]`
    - `in: query` → `query[name]`
    - `in: header` → `headers[name]`
    - `in: cookie` → `cookies[name]`
    - `in: body` (Swagger 2) → flatten the schema into `body_fields` (dotted
      keys, recursion depth ≤ 6; arrays become `name[]`), `body_kind="json"`
    - `in: formData` → `body_kind="form"`; `type: file` →
      `multipart_filenames` + `body_kind="multipart"`
  - `requestBody.content`:
    - `application/json` → flattened schema into `body_fields`, `body_kind="json"`
    - `multipart/form-data` → non-binary props into `body_fields`; every
      `format: binary` prop name into `multipart_filenames`, `body_kind="multipart"`
    - `application/x-www-form-urlencoded` → `body_fields`, `body_kind="form"`
  - `example` / `default` values are carried as the field sample.

### HAR (`spec/har.py::parse`)

One `RawRequest` per `log.entries[].request`:

- `queryString[]` → `query`; `cookies[]` → `cookies`
- headers → `headers`, minus a noise list (`accept*`, `connection`,
  `content-length`, `content-type`, `cache-control`, `sec-*`, `authorization`,
  `cookie`, pseudo-headers)
- `postData`:
  - `params[]` with `fileName` → `body_kind="multipart"`; the param **name** is
    added to `multipart_filenames`, its observed filename stored in
    `body_fields[name]`
  - `params[]` without `fileName` → `body_fields`
  - `mimeType` json + `text` → parsed and flattened into `body_fields`
    (`body_kind="json"`)
  - `mimeType` form-urlencoded → `parse_qsl` into `body_fields` (`body_kind="form"`)

### Postman (`spec/postman.py::parse`)

Walks `item[]` recursively (folders have a nested `item`). Per request: method,
URL (raw or `protocol://host/path`), `url.query[]` → `query`, `:x` / `{x}` path
segments → `path_params`, `header[]` → `headers`, and `body` by mode:
`raw` (JSON) → flattened `body_fields`; `urlencoded` → `body_fields` (form);
`formdata` → `body_fields`, `type:file` entries → `multipart_filenames`.

A failed import is recorded as a note and does not abort the stage.

---

## Step 2 — Crawl the live target

Runs only if `-u` or `--seed` was given. `crawl/crawler.py::Crawler.run(seeds)`.

### 2.1 Setup

1. `_seed_reg` = registrable domain of the first seed (last two labels of the
   host). Used for scope when `--scope` is not given.
2. Queue seeded with `(seed_url, depth=0)` for every seed.
3. **Discovery files** — for the first seed's origin, fetch `/robots.txt` and
   `/sitemap.xml` (`_discover`):
   - robots: every `Allow:` / `Disallow:` / `Sitemap:` value that is not `/` is
     queued at depth 1.
   - sitemap: every `<loc>` URL (up to 200) is queued at depth 1.

### 2.2 BFS loop

While the queue is non-empty and `pages_fetched < --max-pages`, pop
`(url, depth)` and:

1. Strip the `#fragment`. Skip if already visited, `depth > --depth`, or
   out of scope.
   - **scope check** (`_in_scope`): host must equal / be a subdomain of a
     `--scope` entry; or, with no `--scope`, its registrable domain must equal
     `_seed_reg`.
2. Mark visited. `GET` the URL through the shared `HttpClient` (rate-limited,
   redirects followed). A transport failure is recorded and the URL skipped.
3. `pages_fetched += 1`.
4. **If the URL has a query string** → emit
   `RawRequest(GET, url_without_query, query=parsed, note="crawled URL with query string")`.
5. Read the `Content-Type`. Body text is kept only for
   `text/* | html | json | javascript`.
6. **Harvest identifiers** from the URL and (for JSON) the body — see 2.4.
7. Route by content type:
   - **JSON** → stop here (already harvested).
   - **JavaScript** → if `--no-js` was not set, run `js_parser.extract_requests`
     on the body and add the results.
   - **HTML** → parse with `html_parser.parse_html`:
     - every `<form>` → `_form_to_request`:
       - `GET` form → fields merged into the query
       - non-GET form → `body_kind` = `multipart` if the enctype is multipart
         **or** the form has `<input type=file>`; text fields → `body_fields`;
         file-input names → `multipart_filenames`
     - every `<a href>` in scope → queued at `depth+1`; the href is also run
       through the identifier harvester
     - if `--no-js` not set: every inline `<script>` body and every in-scope
       `<script src>` (fetched, first 20) → `js_parser.extract_requests`

### 2.3 JavaScript extraction (`crawl/js_parser.py`)

Regex-based, not a JS engine. Finds:

- `fetch("<url>", { method: "..." })` — method captured if present
- `axios.get|post|put|delete|patch("<url>")`
- any URL-ish string literal (`"//host/..."` or `"/path/..."`), method assumed `GET`

Each becomes a `RawRequest` (query parsed from the string; `:id` / `{id}`
segments recorded as `path_params`). Static asset extensions
(`.css .png .js .woff …`) are skipped. Results deduped by `method + path + query keys`.

### 2.4 Identifier harvesting (`_harvest_from_text`)

Feeds Stage 2's baseline-value guesses. From each crawled URL and each `<a href>`:

- `/(<collection>)/(<value>)` pairs where `<value>` looks like an id
  (`\d{1,12}`, a hex/uuid-ish token, or `name.ext`, or a `[\w-]{6,40}` slug) →
  stored under keys `<collection>` and `<collection-singular>id`.

From JSON response bodies (first 20 kB):

- `"<key>": <value>` where `<key>` ends in `id|name|slug|key|file|path` →
  stored under `<key>` (normalised).

Values that are `true`/`false`/`null` or don't match the id shape are dropped;
at most 12 values per key. Result: `CrawlResult.harvested: dict[str, list[str]]`.

### 2.5 Static-path synthetic vector (`_add_static_path_vector`)

After the loop: if **no** `RawRequest` collected has any query, body field, path
param or file field (i.e. nothing parameterised was found) and at least one page
was fetched, then the URL path itself is the input surface (static-file server /
path-mapped router). One synthetic
`RawRequest(GET, "<origin>/", path_params={"*": "<a seen path>"},
note="static path server — URL path maps to the filesystem")` is emitted per
origin.

`CrawlResult` returns: `requests[]`, `pages_fetched`, `urls_seen`,
`harvested{}`, `errors[]`, `notes[]`.

---

## Step 3 — Extract and rule-score

`vectors/extractor.py::from_raw(reqs, harvested)` → `(InputVector[], request_templates[])`.

### 3.1 Per `RawRequest` (indexed `idx`)

`request_templates` = `[asdict(r) for r in reqs]`; each vector records
`request_ref = idx` so Stage 2 can replay the exact request.

For each request, one `InputVector` is created per input location:

| Source on the RawRequest | InputVector.location | InputVector.name |
|--------------------------|----------------------|------------------|
| `:id` / `{id}` / `*` templated path segments | `url-path-segment` | the segment name (or `*`) |
| `path_params` | `url-path-segment` | key |
| `query` | `query` | key |
| `cookies` | `cookie` | key |
| `headers` (minus `cookie`, `authorization`, `content-length`, `accept`, `connection`; `host` kept) | `header` | key |
| `body_fields` **excluding** file-part fields | `json-body` / `form` / `multipart` per `body_kind` | leaf key; `nested_path` set for dotted keys |
| `multipart_filenames` (file-part field names) | `multipart` | the file-part field name; `controllability="second-order"`, `persistence="stored"` |

Every created vector goes through `add()`:

1. `scoring.classify(vec)` — see 3.2.
2. record its `example_value` under the normalised leaf name in `seen_values`
   (used to cross-populate baseline candidates).
3. dedupe key = `sha1(METHOD | normalised-endpoint | location | nested_path-or-name)[:16]`,
   where the endpoint has numeric ids → `{id}` and UUIDs → `{uuid}`.
   On collision the record with the **higher `rule_relevance`** is kept.

### 3.2 Rule-based relevance (`vectors/scoring.py::classify`)

Starts at **0.05** (any attacker-controlled string is non-zero) and adds:

| Signal | +score | Effect |
|--------|-------:|--------|
| endpoint path contains an fs-op verb (`download`, `upload`, `render`, `extract`, `rename`, `move`, `delete`, `template`, `log`, …) | 0.18 | sets `fs_operation` (write-ish verbs win over `read`) |
| leaf name ∈ strong path names (`file`, `path`, `filepath`, `filename`, `dir`, `template`, `include`, `page`, `src`, `dest`, …) | 0.55 | `path_role="constructs"` |
| leaf name ∈ source/destination names (`source`, `src`, `from`, `destination`, `dest`, `target`, `newpath`, …) | 0.45 | `path_role="constructs"` |
| leaf name ∈ resource-selection names (`download`, `export`, `report`, `image`, `attachment`, `theme`, `locale`, `version`, `backup`, …) | 0.38 | `path_role="selects"` |
| leaf name ∈ id-like names (`id`, `fileId`, `documentId`, `uuid`, `slug`, …) | 0.22 | `controllability="second-order"`, `path_role="indirect"` |
| leaf name ∈ derived names (`tenant`, `org`, `project`, `user`, `host`, `locale`, `theme`, …) | 0.20 | `controllability="derived"`, `path_role="indirect"` |
| name contains `file` / `path` / `dir` / `folder` / `doc` substring (and not already a strong match) | 0.15 | |
| location `url-path-segment` | 0.18 | |
| … and name is `*` / `path` / `filepath` / `splat` / contains `{` (catch-all) | 0.32 | |
| … and evidence mentions "static path" | 0.15 | |
| location `multipart` and name ∈ multipart filename fields / contains `filename` | 0.40 | `controllability="second-order"`, `persistence="stored"` |
| location `header`, name ∈ path headers (`X-Filename`, `X-Path`, `Content-Disposition`, `X-Accel-Redirect`, …) | 0.42 | |
| location `header`, name ∈ soft headers (`Host`, `Referer`, `X-Forwarded-*`, …) | 0.08 | |
| location `cookie`, name ∈ resource-selecting cookies (`template`, `theme`, `locale`, `file`, `view`, …) | 0.30 | |
| protocol `graphql` and name ∈ graphql path args | 0.30 | |
| protocol `websocket` / `grpc` | 0.10 | |
| `example_value` ends in an archive extension (`.zip .tar .jar …`) | 0.12 | |

Score is clamped to `[0, 1]` and stored in `rule_relevance`; the matched signal
strings are stored in `rule_signals`. The vector is then tagged with a coverage
dimension `A`–`L` (`_dimension_for`) and, if `fs_operation` was set, `sink` =
`filesystem <op>`. See [scoring.md](scoring.md) for the full lexicons and the
dimension mapping.

### 3.3 Baseline candidates (per vector, after dedupe)

`baseline_candidates` (a ranked list Stage 2 tries as its known-good value):

1. the vector's own observed `example_value` (unless it looks templated —
   contains `{}`, `:`, `%xx`, or is the literal `"string"` / `"example"`)
2. conventional defaults for the parameter's semantic class
   (`vectors/baseline.py::CONVENTIONAL` — `locale→en`, `theme→default`,
   `template→default`, `page→index`, `format→json`, `version→latest`, …);
   if the name implies a file, `sample.<ext>` or `index.html`
3. values seen elsewhere in this run for a same-named parameter (`seen_values`)
4. harvested identifier values (step 2.4) when the vector is id-like / derived /
   named `id`/`name`/`slug`/`key`

---

## Step 4 — AI refinement pass (optional)

Runs only if `--no-ai` was not set **and** `AIConfig.enabled`. Otherwise the
stage records `ai.enabled = false` with the reason and continues on rule scores
only.

`agent/classifier.py::refine(client, vectors, target, app_hint, batch_size)`:

1. Vectors are sent in batches of `EPT_AI_BATCH_SIZE` (25). Each batch: a slim
   JSON list (`id`, endpoint, method, location, name, nested_path, truncated
   example, source, `rule_relevance`, `rule_signals`).
2. System prompt (`agent/prompts.py::STAGE1_SYSTEM`) asks the model, for that
   batch, to:
   - re-score each vector's traversal-relevance `0.0–1.0` with a ≤ 12-word reason
     and optional `path_role` / `fs_operation`
   - propose up to 5 **inferred** vectors enumeration likely missed (derived,
     second-order, JWT claims, cache/temp/log filenames, internal-service
     fields, archive entries)
   - name up to 4 under-explored coverage dimensions
3. The response must be a compact JSON object; `agent/client.py::_extract_json`
   tolerates a ```` ```json ```` fence and salvages a **truncated** reply
   (closes open brackets, drops an incomplete trailing element).
4. Merge back:
   - `scored[].relevance` → `ai_relevance` (clamped); `reason` → `ai_reason`;
     `path_role` / `fs_operation` applied if valid
   - `inferred_vectors[]` → new `InputVector`s with `source="ai-inferred"`,
     then run through `scoring.classify`
   - `coverage_gaps[]` → merged into the report's gap list
5. A batch that errors or returns a non-object is recorded in `ai.errors` and
   skipped; the run continues.

`InputVector.relevance` = `ai_relevance` if the AI set one, else `rule_relevance`.

---

## Step 5 — Rank and compute coverage

1. Sort vectors by `(relevance, rule_relevance)` descending.
2. `vectors/coverage.py::matrix(vectors + inferred)` — count vectors per
   dimension `A`–`L`; each row is `covered` (≥ 1) or `gap` (0).
3. For every `gap` dimension not already flagged by the AI, add
   `{dimension, note: "no vectors found for: <label>"}`.

The A–L dimensions (research §22): A URL params · B HTTP body · C HTTP metadata
(cookies/headers) · D API protocols · E identity/state · F persistent /
second-order · G resource selection · H filesystem management · I archives /
links · J derived inputs · K infrastructure / internal flows · L file
infrastructure (cache/temp/log).

---

## Step 6 — Write the artifact

`report/writer.py::write_json` → `<out>/stage1-vectors.json`. Top-level keys:

```
tool, version, stage, stage_name, target, started, finished, duration_sec
counts               { vectors, ai_inferred, high_relevance }
counts_baseline      { with_candidate, without_candidate }
crawl                { seeds, pages_fetched, urls_seen, observations,
                       harvested_values, errors, notes }
imports              [ { file, format, requests } ]
ai                   { enabled, model?, batches?, inferred?, errors? | reason? }
coverage             { matrix: [ {dimension,label,vectors,status} ], gaps: [...] }
notes                [ ... ]
request_templates    [ RawRequest-as-dict, ... ]      <- indexed by vector.request_ref
harvested_values     { key: [values] }
vectors              [ InputVector-as-dict, ... ]      <- see data-model.md
ai_inferred_vectors  [ InputVector-as-dict, ... ]
```

Unless `--json-only`, `report/writer.py::print_summary` prints the header block,
crawl/import stats, the top-N vector table (`--top`, default 25), and the A–L
coverage matrix with gap notes.

---

## Worked example

```
$ exploit-path-traversal stage1 -u http://127.0.0.1:5000 --no-ai
  -> crawled 4 pages, 3 request observations
  -> enumerated 1 distinct input vectors (1 with a baseline candidate)
  warn AI pass skipped: disabled via --no-ai
```

- crawl fetched `/`, followed the `?file=` links, saw `/download?file=report.txt`
  → `RawRequest(GET /download, query={file: report.txt})`
- extractor made one vector: `location=query`, `name=file`,
  `example_value=report.txt`
- scoring: `0.05 + 0.18 (fs-op verb "download") + 0.55 (strong path name "file")
  = 0.78`, dimension `A`, `fs_operation=read`, `sink="filesystem read"`
- `baseline_candidates = ["report.txt", ...]` (observed value first)
- artifact: 1 vector, `request_templates[0]` is the full `/download` request
