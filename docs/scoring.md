# Scoring & coverage model

`vectors/scoring.py::classify(vec)` fills, in place: `fs_operation`, `path_role`,
`controllability`, `persistence`, `rule_relevance`, `rule_signals`, `category`
(A–L), `dimension`, `sink`.

## Relevance score

Baseline **0.05** (any attacker-controlled string is non-zero — traversal
survives in places that do not look path-like). Additive signals, clamped to
`[0, 1]`:

### Endpoint

- an fs-op verb anywhere in the endpoint path → **+0.18**, sets `fs_operation`.
  Verbs (`lexicon.FS_OP_PATH_HINTS`): `download`, `getfile`, `raw`, `blob`,
  `attachment`, `media`, `asset`, `static`, `content`, `document`, `preview`,
  `view`, `render`, `read`, `include`, `import`, `load`, `export`, `upload`,
  `save`, `write`, `generate`, `create`, `rename`, `move`, `copy`, `delete`,
  `remove`, `rm`, `mkdir`, `extract`, `unzip`, `decompress`, `restore`,
  `backup`, `template`, `themes`, `repository`, `repo`, `tree`, `browse`,
  `log`, `logs`, `debug`. A write-ish verb (`extract`/`rename`/`move`/`copy`/
  `delete`/`mkdir`/`write`/`include`) wins over `read`.

### Field name (leaf name, lower-cased, alphanumerics only)

| Class (`lexicon.py`) | +score | Side effects |
|----------------------|-------:|--------------|
| `STRONG_PATH_NAMES` — `file`, `path`, `filepath`, `filename`, `dir`, `directory`, `folder`, `document`, `template`, `include`, `page`, `view`, `resource`, `asset`, `src`, `source`, `target`, `dest`, `output`, `input`, `newpath`, … | **0.55** | `path_role="constructs"` |
| `SOURCE_DEST_NAMES` — `source`, `src`, `from`, `input`, `origin`, `destination`, `dest`, `to`, `target`, `output`, `newpath`, `newname` | **0.45** | `path_role="constructs"` |
| `RESOURCE_SELECTION_NAMES` — `download`, `attachment`, `export`, `report`, `preview`, `render`, `image`, `img`, `media`, `backup`, `restore`, `version`, `revision`, `branch`, `theme`, `locale`, `lang`, `module`, `plugin`, `config`, `profile`, … | **0.38** | `path_role="selects"` |
| `ID_LIKE_NAMES` — `id`, `fileId`, `documentId`, `assetId`, `attachmentId`, `templateId`, `projectId`, `repositoryId`, `tenantId`, `uuid`, `guid`, `key`, `hash`, `slug`, `name`, `title`, `ref` | **0.22** | `controllability="second-order"`, `path_role="indirect"` |
| `DERIVED_NAMES` — `tenant`, `org`, `account`, `project`, `workspace`, `repository`, `namespace`, `bucket`, `user`, `username`, `owner`, `host`, `subdomain`, `domain`, `locale`, `lang`, `region`, `theme`, `brand`, `channel`, `environment`, `env`, `stage` | **0.20** | `controllability="derived"`, `path_role="indirect"` |
| name merely *contains* `file`/`path`/`dir`/`folder`/`doc` (and not already strong) | **0.15** | |

### Location

| Location | +score | Extra |
|----------|-------:|-------|
| `url-path-segment` | **0.18** | |
| … name is `*`/`path`/`filepath`/`splat` or contains `{` (catch-all/wildcard) | **+0.32** | |
| … `evidence` mentions "static path" (synthetic static-server vector) | **+0.15** | |
| `multipart`, name ∈ multipart filename fields or contains `filename` | **0.40** | `controllability="second-order"`, `persistence="stored"` |
| `header`, name ∈ `PATH_HEADER_NAMES` (`X-Filename`, `X-File`, `X-Path`, `X-File-Path`, `X-Resource`, `X-Template`, `Content-Disposition`, `X-Forwarded-Path`, `X-Original-URL`, `X-Rewrite-URL`, `X-Accel-Redirect`) | **0.42** | |
| `header`, name ∈ `SOFT_HEADER_NAMES` (`Host`, `Referer`, `Origin`, `User-Agent`, `Accept-Language`, `X-Forwarded-*`, `X-Real-IP`, `Forwarded`) | **0.08** | only relevant if the app derives a path from it |
| `cookie`, name ∈ `PATH_COOKIE_NAMES` (`template`, `theme`, `skin`, `locale`, `lang`, `file`, `document`, `view`, `resource`, `layout`, `config`, `profile`) | **0.30** | |

### Protocol / value

- `graphql` and name ∈ `GRAPHQL_PATH_ARGS` (`path`, `relativePath`, `newPath`,
  `filename`, `file`, `source`, `destination`, `dir`, `directory`) → **+0.30**
- `websocket` / `grpc` field → **+0.10**
- `example_value` ends in an archive extension (`.zip .tar .tgz .gz .7z .rar
  .jar .war .ear .bz2 .xz`) → **+0.12**

`InputVector.relevance` = `ai_relevance` if the AI set one, else
`rule_relevance`. Stage 2 probes vectors with `relevance >= --min-relevance`
(default 0.4).

## A–L coverage dimensions

`_dimension_for(vec)` maps each vector to exactly one dimension; the report shows
per-dimension counts and flags any dimension with zero vectors as a **gap**.

| Dim | Area | Mapped when… |
|-----|------|--------------|
| A | URL path segments / query / route-wildcard params | query or path-segment (default) |
| B | HTTP body: JSON / form-urlencoded / multipart / XML / YAML | `json-body` or `form` |
| C | HTTP metadata: cookies, custom headers, filename metadata | `cookie` or `header` |
| D | API protocols: REST / GraphQL / WebSocket / gRPC | protocol is graphql / websocket / grpc |
| E | Identity/state: JWT claims, session, user/tenant identifiers | name ∈ `jwt`, `sub`, `tenant`, `tenantid`, `user`, `userid`, `username`, `org` |
| F | Persistent / second-order: DB values, imports, stored/uploaded names | `multipart`, or `controllability="second-order"` |
| G | Resource selection: download/preview/template/include/image/report/locale/backup | name ∈ resource-selection names |
| H | Filesystem management: read/write/upload/rename/move/copy/delete/mkdir/extract | `fs_operation` ∈ rename/move/copy/delete/mkdir/write/extract |
| I | Archives / filesystem links: zip/tar entries, symlinks, extraction dest | `fs_operation="extract"` or archive-extension value |
| J | Derived inputs: host/subdomain, tenant, username, project, repo, locale, theme, ids | `controllability="derived"` |
| K | Infrastructure / internal flows: reverse proxies, rewrites, internal APIs, workers | (AI-only; rules rarely populate it → usually a gap note) |
| L | File infrastructure: caches, temp files, logs, generated artifacts, CLI bridges | (AI-only; usually a gap note) |
