# Stage 3 — tiered mechanism-attribution probing

**Command:** `exploit-path-traversal stage3`
**Entry point:** `exploit_path_traversal/stages/stage3.py` → `run(opts, settings, log)`
**Input:** `stage1-vectors.json` (via `--in`, or produced on the fly from a target surface)
**Output:** `<out>/stage3-findings.json`

Stage 3 does **not** execute one giant, undifferentiated traversal wordlist.
Instead it organizes test inputs into **tiers based on the mechanism they are
intended to defeat**, so every finding can be attributed to *which parser /
filter / validation layer was bypassed* — not merely "a payload worked".

The central rule:

> **Increase complexity only when the preceding layer is understood.**

---

## The tier model

For every discovered input vector, Stage 3 progresses from the simplest
representation toward increasingly complex encoding, normalization,
parser-differential, platform-specific, and validation-bypass cases:

```
Tier 0    literal path semantics
Tier 0A   absolute-path behavior
Tier 1    single percent encoding
Tier 2    double / repeated encoding
Tier 3    mixed encoding
Tier 4    normalization / path-mangling
Tier 5    canonicalization-order differences
Tier 6    base-path / prefix-validation bypass
Tier 7    extension / suffix / NUL / truncation
Tier 8    Unicode representation / normalization
Tier 9    legacy overlong UTF-8
Tier 10   parser / proxy / framework discrepancies
Tier 11   HTTP path normalization discrepancies
Tier 12   Windows-specific path semantics
Tier 13   UNC / network-path semantics
Tier 14   Windows filename normalization quirks
Tier 15   alternate filename / filesystem namespace behavior
Tier 16   archive extraction traversal
Tier 17   symlink / hardlink resolution
Tier 18   canonicalization / boundary-check weaknesses
Tier 19   compound multi-technique transformations
Tier 20   multi-parser / multi-language boundary cases
Tier 21   protocol-specific representation changes
Tier 22   second-order / stored traversal
Tier 23   derived-value traversal
Tier 24   normalization equivalence / collision
Tier 25   case / filesystem sensitivity
Tier 26   basename / dirname / extension parser discrepancies
Tier 27   absolute-path replacement after path joining
Tier 28   special parser syntaxes
Tier 29   WAF / filter-specific mutation
```

Not every tier applies to every target. Tiers are selected based on the
observed application, framework, operating system, and response behavior.

---

## Tier selection

`tiers/selector.py::build_profile()` builds a condition set from the vector's
characteristics and the operator's target hints. `select_tiers()` returns the
ordered list of applicable tiers.

### Always-applicable tiers

Tiers 0, 0A, 1, 2, 3, 4, 5, and 8 have no conditions and are always probed.

### Condition-gated tiers

| Tier | Condition | CLI flag |
|------|-----------|----------|
| 6 | `prefix-check` | `--prefix-check` |
| 7 | `extension-validation` | `--extension-validation` |
| 9 | `legacy` | `--legacy` |
| 10 | `multi-service` | `--multi-service` |
| 11 | `path-segment` | auto (URL path-segment vectors) |
| 12 | `platform:windows` | `--platform windows` |
| 13 | `platform:windows` + `unc` | `--platform windows --unc` |
| 14 | `platform:windows` + `windows-filename` | `--platform windows --windows-filename` |
| 15 | `platform:windows` + `ntfs` | `--platform windows --ntfs` |
| 16 | `archive` | auto (fs_operation=extract) |
| 17 | `links` | `--links` |
| 18 | `canonicalization` | `--canonicalization` |
| 19 | `compound` | `--compound` |
| 20 | `multi-language` | `--multi-language` |
| 21 | `protocol-variants` | `--protocol-variants` |
| 22 | `second-order` | auto (controllability=second-order) |
| 23 | `derived-value` | auto (controllability=derived) |
| 24 | `collision` | `--collision` |
| 25 | `case` | `--case` |
| 26 | `basename-dirname` | `--basename-dirname` |
| 27 | `absolute-join` | `--absolute-join` |
| 28 | `parser-syntax` | `--parser-syntax` |
| 29 | `waf-mutation` | `--waf-mutation` |

---

## Payload generation model

`tiers/generator.py::generate_tiered()` produces payloads systematically from
the model:

```
BASE PATH
+ TRAVERSAL REPRESENTATION
+ ENCODING TRANSFORMATION
+ NORMALIZATION TRANSFORMATION
+ PLATFORM SEMANTICS
+ VALIDATION-BYPASS TRANSFORMATION
```

Each `TieredPayload` carries:

- `tier_id` — which tier it belongs to
- `mechanism` — what defensive layer it targets
- `bypass_category` — `representation` | `normalization` | `parser-differential` | `path-boundary`
- `name`, `value`, `canary_key`, `canary_re`, `depth`, `note`, `kinds`

Payloads are ordered **tier-major** so the first N payloads sample every
applicable tier before deeper variants of any single tier.

### Write-side payloads

`generate_tiered_write()` produces **safe by construction** upload-filename
payloads: climb-only, never absolute, never a system path. Each is tagged with
its tier for mechanism attribution.

---

## Mechanism attribution

`tiers/attribution.py::attribute_finding()` classifies *why* a payload
succeeded. The critical distinction separates four concepts:

| Category | Meaning |
|----------|---------|
| **REPRESENTATION BYPASS** | The filter fails to recognize the traversal representation (encoding, Unicode, etc.) |
| **NORMALIZATION BYPASS** | Validation and filesystem resolution normalize differently |
| **PARSER DIFFERENTIAL** | Different layers interpret the same request differently |
| **PATH-BOUNDARY LOGIC FAILURE** | The application resolves a path outside the intended root despite apparently successful validation |

Every finding records:

```
tier
payload class
input vector
transport
OS
framework
observed response
baseline difference
transformation responsible
validation defeated
canonicalization behavior
filesystem behavior
confidence
```

---

## Pipeline overview

```
0. obtain a stage 1 artifact           (run stage 1 first if only -u/specs given)
1. select vectors to probe             (min-relevance, location, id filters)
   for each selected vector:
     2. build the request template      (probe/prepared.from_template)
     3. establish the baseline          (probe/baseline.establish)
     4. build the negative control      (probe/baseline.negative_control)
     5. build the tier profile          (tiers/selector.build_profile)
     6. select applicable tiers         (tiers/selector.select_tiers)
     7. generate tiered payloads        (tiers/generator.generate_tiered)
     8. probe loop                      (probe/fingerprint.capture + probe/differ.classify)
        -> best verdict for this vector
     9. write-side round-trip           (only for multipart "likely")
    10. reproduction gate               (re-send the winning payload 2x)
    11. AI adjudication (optional)      (agent/verify.adjudicate)
    12. mechanism attribution           (tiers/attribution.attribute_finding)
    13. assemble the finding record
14. sort findings, write stage3-findings.json
```

---

## Usage

```bash
# probe an existing stage 1 artifact
exploit-path-traversal stage3 --in ./ept-out/stage1-vectors.json

# run stage 1 then probe, in one go
exploit-path-traversal stage3 -u https://target.example.com

# Windows target with extension validation and prefix checks
exploit-path-traversal stage3 --in ./ept-out/stage1-vectors.json \
    --platform windows --extension-validation --prefix-check

# WAF in front, legacy stack, compound transformations
exploit-path-traversal stage3 --in ./ept-out/stage1-vectors.json \
    --filter --legacy --compound --waf-mutation
```

### Key options

| Flag | Meaning |
|------|---------|
| `--in FILE` | `stage1-vectors.json` to probe (else give `-u`/`--openapi`/… to run stage 1 first) |
| `--min-relevance` | only probe vectors at/above this score (default 0.4) |
| `--location` | comma-separated locations to probe |
| `--only ID` | probe just one vector id (repeatable) |
| `--baseline 'name=value'` | force a known-good value for a field (repeatable) |
| `--canary` | `unix` (default), `windows`, or `both` |
| `--depth-max` | max `../` depth (default 6) |
| `--max-payloads` | payload cap per vector (default 120) |
| `--thorough` | more canary targets + payloads |
| `--platform` | `unix` or `windows` (enables platform-specific tiers) |
| `--filter` | a WAF/custom filter is suspected |
| `--extension-validation` | app validates file extensions (enables tier 7) |
| `--prefix-check` | app does startsWith(base) checks (enables tier 6) |
| `--canonicalization` | app canonicalizes paths (enables tier 18) |
| `--multi-service` | proxy/CDN/WAF in front (enables tiers 10–11) |
| `--legacy` | legacy stack (enables tier 9) |
| `--ntfs` | NTFS behavior (enables tier 15) |
| `--links` | symlink/hardlink resolution (enables tier 17) |
| `--unc` | UNC paths (enables tier 13) |
| `--windows-filename` | Windows filename quirks (enables tier 14) |
| `--compound` | compound transformations (enables tier 19) |
| `--multi-language` | multi-language boundaries (enables tier 20) |
| `--protocol-variants` | protocol-specific variants (enables tier 21) |
| `--second-order` | stored traversal (enables tier 22) |
| `--derived-value` | derived-value traversal (enables tier 23) |
| `--collision` | normalization equivalence (enables tier 24) |
| `--case` | case sensitivity (enables tier 25) |
| `--basename-dirname` | basename/dirname discrepancies (enables tier 26) |
| `--absolute-join` | absolute-path replacement during join (enables tier 27) |
| `--parser-syntax` | special parser syntaxes (enables tier 28) |
| `--waf-mutation` | WAF/filter mutation (enables tier 29) |
| `--no-ai` | skip AI adjudication |
| `--rate` / `--timeout` / `--insecure` / `-H` / `-b` | HTTP controls |

---

## Output

`stage3-findings.json` extends the Stage 2 schema with:

```
tier_stats        { "<tier-id>": { count, bypass_categories[] } }
findings[].tier               winning payload's tier id
findings[].tier_name          human-readable tier name
findings[].mechanism          what defensive layer was bypassed
findings[].bypass_category    representation | normalization | parser-differential | path-boundary
findings[].attribution        { tier, tier_name, mechanism, bypass_category,
                                bypass_label, payload_class, validation_defeated,
                                transformation_responsible, confidence, notes[] }
findings[].tiers_applicable   all tiers that applied to this vector
findings[].probes[].tier      per-probe tier attribution
```

The terminal summary shows verdict counts, tier stats, and each non-clean
finding with its bypass label, mechanism, validation defeated, and
transformation responsible.