# Data model

## `RawRequest` (`models.py`)

A request *shape* observed while crawling or parsed from a spec/capture. The
intermediate representation every importer and the crawler produce.

| Field | Type | Notes |
|-------|------|-------|
| `method` | str | `GET` … |
| `url` | str | full URL as observed |
| `query` | dict | name → sample |
| `headers` | dict | name → sample |
| `cookies` | dict | name → sample |
| `path_params` | dict | templated segment name → sample (`{id}`, `:id`, `*`) |
| `body_kind` | str | `json` \| `form` \| `multipart` \| `""` |
| `body_fields` | dict | dotted name → sample (JSON flattened; `name[]` for arrays) |
| `multipart_filenames` | list | **field names** of file parts (the injection point is that part's filename) |
| `protocol` | str | `rest` \| `graphql` \| `websocket` \| `grpc` \| `static` |
| `source` | str | `crawl` \| `openapi` \| `har` \| `postman` \| `seed` |
| `note` | str | provenance |

`request_templates[]` in the Stage 1 artifact is `[asdict(r) for r in reqs]`,
indexed by `InputVector.request_ref`.

## `InputVector` (`models.py`)

One attacker-influenced value = one source-to-sink dataflow record. The Stage 1
deliverable.

| Field | Meaning |
|-------|---------|
| `endpoint`, `method`, `protocol` | where the value lives |
| `location` | `url-path-segment` \| `query` \| `json-body` \| `form` \| `multipart` \| `header` \| `cookie` |
| `name`, `nested_path` | field name; dotted path for nested JSON (`document.path`) |
| `data_type`, `example_value` | observed type / sample |
| `controllability` | `direct` \| `derived` (templated into a path) \| `second-order` (persisted, reaches a sink later) |
| `persistence` | `none` \| `stored` \| `reflected` |
| `transformations` | decode / normalise / join / lookup steps expected before the sink |
| `path_role` | `selects` \| `constructs` \| `modifies` \| `resolves` \| `indirect` \| `none` |
| `fs_operation` | `read` \| `write` \| `rename` \| `move` \| `copy` \| `delete` \| `mkdir` \| `extract` \| `include` \| `unknown` |
| `sink` | e.g. `filesystem read` |
| `category`, `dimension` | coverage key `A`–`L` and its label |
| `source` | `crawl` \| `openapi` \| `har` \| `postman` \| `seed` \| `ai-inferred` |
| `evidence` | why this is a candidate |
| `rule_relevance`, `rule_signals` | deterministic score 0–1 and the signals that produced it |
| `ai_relevance`, `ai_reason`, `ai_notes` | AI refinement, if run |
| `request_ref` | index into `request_templates`; `-1` for `ai-inferred` |
| `baseline_candidates` | ranked known-good values for Stage 2 |
| `relevance` (computed) | `ai_relevance` if set, else `rule_relevance` |
| `id` (computed) | `sha1(method \| norm-endpoint \| location \| nested_path-or-name)[:16]` |

## `stage1-vectors.json`

```
tool, version, stage=1, stage_name="input-vector-enumeration"
target, started, finished, duration_sec
counts            { vectors, ai_inferred, high_relevance }        high = relevance >= 0.6
counts_baseline   { with_candidate, without_candidate }
crawl             { seeds, pages_fetched, urls_seen, observations, harvested_values, errors, notes }
imports           [ { file, format, requests } ]
ai                { enabled:true, model, batches, inferred, errors }
                | { enabled:false, reason }
coverage          { matrix:[ {dimension,label,vectors,status} ], gaps:[ {dimension,note} ] }
notes             [ ... ]
request_templates [ RawRequest-as-dict, ... ]
harvested_values  { key: [values] }
vectors           [ InputVector-as-dict, ... ]     sorted by relevance desc
ai_inferred_vectors [ InputVector-as-dict, ... ]
```

## `stage3-findings.json`

Extends the Stage 2 schema with tiered mechanism attribution:

```
tool, version, stage=3, stage_name="tiered-mechanism-attribution"
source_artifact, started, finished, duration_sec
config   { min_relevance, canary, depth_max, max_payloads, thorough, ai,
           platform, has_filter, has_extension_validation, has_prefix_check,
           has_canonicalization }
counts   { vectors_selected, confirmed, likely, inconclusive, not_vulnerable }
tier_stats { "<tier-id>": { count, bypass_categories[] } }
ai_errors [ "<vector id>: <message>" ]
findings [
  {
    ... (same fields as stage2-findings.json) ...
    tier               winning payload's tier id ("0", "0A", "1", ..., "29")
    tier_name          human-readable tier name
    mechanism          what defensive layer was bypassed
    bypass_category    representation | normalization | parser-differential | path-boundary
    attribution        { tier, tier_name, mechanism, bypass_category,
                         bypass_label, payload_class, validation_defeated,
                         transformation_responsible, confidence, notes[] }
    tiers_applicable   [ all tier ids that applied to this vector ]
    probes[].tier      per-probe tier attribution
  }
]
```

## `stage2-findings.json`

```
tool, version, stage=2, stage_name="baseline-differential-probing"
source_artifact, started, finished, duration_sec
config   { min_relevance, canary, depth_max, max_payloads, thorough, ai }
counts   { vectors_selected, confirmed, likely, inconclusive, not_vulnerable }
ai_errors [ "<vector id>: <message>" ]
findings [
  {
    vector_id, endpoint, method, location, field, relevance
    verdict            confirmed | likely | inconclusive | not-vulnerable | error
    confidence         0.0 – 0.97
    reproduced         true | false | null
    winning_payload    { name, value, note, status, length } | null
    signals            [ ... ]
    similarity         { vs_baseline, vs_control }
    baseline           { accepted, value, dynamic, tried:[...], note, fingerprint }
    negative_control   { value, fingerprint }
    ai_adjudication    { verdict, confidence, reason } | null
    round_trip_url     "<url>" | null
    repro_curl         "curl -sk --path-as-is ..."
    probe_count
    probes [ { payload, value, verdict, confidence, status, length, canary_hit, signals } ]
  }
]
```

`fingerprint` (the `.summary()` form): `{ status, length, content_type,
elapsed_ms, redirects, sha1, error }`.
