# Verdicts

`probe/differ.py::classify(fp, payload, baseline, control, write_side)` → `Diff`
with `verdict`, `confidence`, `canary_hit`, `signals[]`, `sim_baseline`,
`sim_control`.

Verdict strength (for keeping the "best" result and for report ordering):

```
confirmed (4) > likely (3) > inconclusive (2) > error (1) > not-vulnerable (0)
```

## Decision order

The first matching rule wins.

### 0. Transport failure
`fp.transport_ok == False` → **`error`**, confidence 0, signal `transport: <err>`.

### 1. Read-side canary hit
`not write_side` and `payload.canary_re` matches the body →
**`confirmed`**, **0.97**, `canary_hit=True`, signal
`canary signature matched (<family>)`. (A reflected upload filename is *not*
treated as a canary — see rule 2.)

### 2. Write-side signal
`write_side` and the response is **not** byte-identical to the negative control
and **either**:
- the body reflects an escaped save path (`../`, `..\`, `..%2f`, or the marker
  next to a path separator), **or**
- a filesystem error / stack trace is in the body, **or** the baseline status
  was `< 400` and the payload status is `>= 400`

→ **`likely`**, **0.55**, signal describing which. Step 7 (round-trip) may then
upgrade this to `confirmed` @ 0.95.

### 3. Matches the negative control
`fp.status == control.status` and (`sim_control >= 0.97` or identical
`body_sha1`) → **`not-vulnerable`**, 0, signal
`response == negative control (missing-file behavior)`.

### 4. Likely (read-side differential)
Requires **`differs_from_baseline`** AND **`read_shaped`** (and not rule 3):

- `differs_from_baseline` — a baseline was accepted **and** any of:
  - status differs from baseline, or
  - different `body_sha1` **and** `sim_baseline` below `0.9` (dynamic baseline)
    / `0.97` (stable), or
  - `|length - baseline.length|` > `max(64, 25% of baseline.length)`, or
  - content-type changed
- `read_shaped` — status `200`/`206`, non-empty body, and (no control, or
  `sim_control < 0.9` with a different status, or `length - control.length > 64`)

→ **`likely`**, **0.62** (+0.1 if a stack trace / FS error is in the body),
signal quoting both similarities.

### 5. Inconclusive
`differs_from_baseline`, or status ∈ {403, 406, 429, 500, 502}, or any signal was
already recorded → **`inconclusive`**, **0.3**. Sub-signals: `possible WAF/filter
(403/406/429)`, `server error (500/502) — may indicate a broken path`, or
`differs from baseline but ambiguous`.

### 6. Not vulnerable
Otherwise → **`not-vulnerable`**, 0, signal
`indistinguishable from baseline (sim <x>)`.

## After the probe loop (stage2.py)

| Step | Effect on the finding |
|------|-----------------------|
| **early exit** | first read-side `canary_hit` stops probing that vector |
| **round-trip** (write-side `likely`) | marker content retrieved → `confirmed` @ 0.95, `round_trip_url` set; else a "could not locate" signal |
| **suffix note** (read-side, baseline value has an extension, verdict `likely`/`inconclusive`) | signal: sink may append an extension; canary may be unreachable without null-byte tricks |
| **reproduction gate** (`confirmed`/`likely`, not round-trip-confirmed) | re-send winning payload 2×; if not both `confirmed`/`likely` → downgrade one level, halve confidence, signal `did NOT reproduce (2x)` |
| **AI adjudication** (`likely`/`inconclusive`, baseline accepted, `--no-ai` off) | AI `not-vulnerable` ≥0.8 → finding becomes `not-vulnerable`; AI `not-vulnerable` <0.8 → confidence lowered; AI `likely`/`confirmed` → confidence raised (verdict not upgraded) |

Deterministic `confirmed` and `not-vulnerable` are never sent to the AI.

## Confidence values at a glance

| Situation | confidence |
|-----------|-----------:|
| canary signature matched | 0.97 |
| write-side round-trip recovered the file | 0.95 |
| read-side likely + stack trace | 0.72 |
| read-side likely | 0.62 |
| write-side likely (reflected / errored) | 0.55 |
| inconclusive | 0.30 |
| not-vulnerable / error | 0.00 |
| reproduction failed | ×0.5 and downgraded |
