# Configuration

## Precedence

For every setting: **CLI flag > process environment > `.env` file**.
`.env` is read from the working directory, or from `--env-file <path>`.

## AI agent (optional)

The agent talks to any OpenAI-compatible `POST {base_url}/chat/completions`.
If base URL, model and key are not all present, all stages run on their
deterministic paths and print why the AI was skipped.

| Setting | Env (first found wins) | Default |
|---------|------------------------|---------|
| Base URL | `EPT_AI_BASE_URL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE` | — |
| Model | `EPT_AI_MODEL`, `OPENAI_MODEL` | — |
| API key | `EPT_AI_API_KEY`, `OPENAI_API_KEY` | — |
| Temperature | `EPT_AI_TEMPERATURE` | `0.0` |
| Max tokens | `EPT_AI_MAX_TOKENS` | `8192` |
| Request timeout (s) | `EPT_AI_TIMEOUT` | `90` |
| Stage 1 batch size | `EPT_AI_BATCH_SIZE` | `25` |

`.env.example` in the repo root is a template. The real `.env` is git-ignored.

Notes:
- The client sends `response_format: {type: "json_object"}`; if the endpoint
  rejects it (HTTP 400 mentioning `response_format`), it retries without.
- Truncated / fenced JSON replies are salvaged (`agent/client.py::_extract_json`):
  a lone ```` ```json ```` opener is stripped and unterminated brackets/strings
  are closed so complete array elements still parse.
- Slow models: raise `EPT_AI_TIMEOUT`; the tool degrades gracefully on timeout
  (records the batch error, keeps deterministic results).

## CLI reference

### `stage1`

| Group | Flag | Default | Meaning |
|-------|------|---------|---------|
| surface | `-u, --url` | — | base URL to crawl |
| | `--seed URL` | — | extra seed URL (repeatable) |
| | `--openapi FILE` | — | OpenAPI/Swagger JSON or YAML (repeatable) |
| | `--har FILE` | — | HAR capture (repeatable) |
| | `--postman FILE` | — | Postman v2.x collection (repeatable) |
| crawl | `--depth` | 2 | max crawl depth |
| | `--max-pages` | 200 | max pages fetched |
| | `--scope` | seed's registrable domain | comma host allowlist |
| | `--no-js` | off | skip JavaScript endpoint extraction |
| | `--rate` | 5 | max requests/sec |
| | `--timeout` | 15 | per-request timeout (s) |
| | `--insecure` | off | skip TLS verification |
| | `-H 'K: V'` | — | extra request header (repeatable) |
| | `-b 'k=v'` | — | request cookie (repeatable) |
| ai | `--no-ai` | off | deterministic scoring only |
| | `--app-hint` | "" | one line about the app, passed to the agent |
| | `--env-file` | `./.env` | path to the env file |
| output | `-o, --out` | `./ept-out` | output directory |
| | `--json-only` | off | write JSON, skip the terminal summary |
| | `--top` | 25 | rows in the terminal vector table |

### `stage2`

| Group | Flag | Default | Meaning |
|-------|------|---------|---------|
| input | `--in FILE` | — | `stage1-vectors.json` to probe |
| | `-u/--seed/--openapi/--har/--postman` | — | run Stage 1 first with these, then probe |
| | `--scope / --depth / --max-pages` | | passed to the Stage 1 crawl if it runs |
| selection | `--min-relevance` | 0.4 | only probe vectors at/above this score |
| | `--location` | all | comma list of locations to probe |
| | `--only ID` | — | probe just this vector id (repeatable) |
| | `--baseline 'name=value'` | — | force a known-good value for a field (repeatable) |
| probing | `--canary` | `unix` | `unix` (`/etc/passwd`), `windows`, or `both` |
| | `--depth-max` | 6 | max `../` depth |
| | `--max-payloads` | 90 | payload cap per vector |
| | `--thorough` | off | extra canary targets + payloads |
| | `--rate` | 6 | max requests/sec |
| | `--timeout` | 15 | per-request timeout (s) |
| | `--insecure` | off | skip TLS verification |
| | `-H / -b` | — | extra header / cookie (repeatable) |
| | `--no-ai` | off | skip AI adjudication |
| | `--app-hint / --env-file` | | as in `stage1` |
| output | `-o, --out` | `./ept-out` | output directory |
| | `--json-only` | off | write JSON, skip the terminal summary |

### `stage3`

| Group | Flag | Default | Meaning |
|-------|------|---------|---------|
| input | `--in FILE` | — | `stage1-vectors.json` to probe |
| | `-u/--seed/--openapi/--har/--postman` | — | run Stage 1 first with these, then probe |
| | `--scope / --depth / --max-pages` | | passed to the Stage 1 crawl if it runs |
| selection | `--min-relevance` | 0.4 | only probe vectors at/above this score |
| | `--location` | all | comma list of locations to probe |
| | `--only ID` | — | probe just this vector id (repeatable) |
| | `--baseline 'name=value'` | — | force a known-good value for a field (repeatable) |
| probing | `--canary` | `unix` | `unix` (`/etc/passwd`), `windows`, or `both` |
| | `--depth-max` | 6 | max `../` depth |
| | `--max-payloads` | 120 | payload cap per vector |
| | `--thorough` | off | extra canary targets + payloads |
| | `--rate` | 6 | max requests/sec |
| | `--timeout` | 15 | per-request timeout (s) |
| | `--insecure` | off | skip TLS verification |
| | `-H / -b` | — | extra header / cookie (repeatable) |
| | `--no-ai` | off | skip AI adjudication |
| | `--app-hint / --env-file` | | as in `stage1` |
| target | `--platform` | auto | `unix` or `windows` (enables platform tiers) |
| | `--filter` | off | a WAF/custom filter is suspected |
| | `--extension-validation` | off | app validates extensions (tier 7) |
| | `--prefix-check` | off | app does startsWith(base) checks (tier 6) |
| | `--canonicalization` | off | app canonicalizes paths (tier 18) |
| | `--multi-service` | off | proxy/CDN/WAF in front (tiers 10–11) |
| | `--legacy` | off | legacy stack (tier 9) |
| | `--ntfs` | off | NTFS behavior (tier 15) |
| | `--links` | off | symlink/hardlink resolution (tier 17) |
| | `--unc` | off | UNC paths (tier 13) |
| | `--windows-filename` | off | Windows filename quirks (tier 14) |
| | `--compound` | off | compound transformations (tier 19) |
| | `--multi-language` | off | multi-language boundaries (tier 20) |
| | `--protocol-variants` | off | protocol-specific variants (tier 21) |
| | `--second-order` | off | stored traversal (tier 22) |
| | `--derived-value` | off | derived-value traversal (tier 23) |
| | `--collision` | off | normalization equivalence (tier 24) |
| | `--case` | off | case sensitivity (tier 25) |
| | `--basename-dirname` | off | basename/dirname discrepancies (tier 26) |
| | `--absolute-join` | off | absolute-path replacement during join (tier 27) |
| | `--parser-syntax` | off | special parser syntaxes (tier 28) |
| | `--waf-mutation` | off | WAF/filter mutation (tier 29) |
| output | `-o, --out` | `./ept-out` | output directory |
| | `--json-only` | off | write JSON, skip the terminal summary |

### `report`

| Flag | Default | Meaning |
|------|---------|---------|
| `--in FILE` | — (required) | `stage2-findings.json` |
| `--stage1 FILE` | sibling `stage1-vectors.json` | for the coverage table |
| `-o, --out` | `./ept-out` | writes `report.md` here |

## Terminal output style

`output.py` uses bold and dim only, no colour spam, no decorative symbols.
It honours `NO_COLOR` and disables styling when stdout is not a TTY.
