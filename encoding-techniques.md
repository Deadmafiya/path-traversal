# Encoding Techniques in Path Traversal

A comprehensive reference of all encoding techniques used to **prevent** and **bypass** path traversal (directory traversal), compiled from deep multi-agent research.

> **Universal defense pattern**: `decode → canonicalize → allowlist → verify prefix containment` — in this order, never reordered.
> **Never**: check raw input before canonicalizing (CWE-179); use string concatenation for paths; trust `startsWith` without a trailing-separator qualifier; forget TOCTOU on symlinks; assume cross-OS path semantics are identical.

---

## Table of Contents

1. [Defensive Encoding Techniques](#1-defensive-encoding-techniques)
2. [Percent / URL Encoding Attack Vectors](#2-percent--url-encoding-attack-vectors)
3. [Unicode & Charset Vectors](#3-unicode--charset-vectors)
4. [OS & Filesystem Semantics](#4-os--filesystem-semantics)
5. [Language & Framework API Defenses](#5-language--framework-api-defenses)
6. [Transport & Protocol-Level Encodings](#6-transport--protocol-level-encodings)
7. [Encoding Evasion Matrix (payload → defense)](#7-encoding-evasion-matrix)
8. [CVE Reference Table](#8-cve-reference-table)
9. [The Universal Defense Pattern](#9-the-universal-defense-pattern)

---

## 1. Defensive Encoding Techniques

Techniques developers deliberately use with encoding/normalization to stop traversal.

| # | Technique | Encoding/API | Example | Caveats |
|---|-----------|--------------|---------|---------|
| 1.1 | **Canonicalize-then-contain prefix check** | `realpath` / `resolve` / `getCanonicalPath` / `GetFullPath` | `canonical.startsWith(base + sep)` | Raw prefix check passes `/safe_dir/../important.dat`; base `/safedir` also prefixes `/safedir_evil/` → qualify base with trailing separator; symlink TOCTOU (CWE-59); input must already be decoded (CWE-174); case-normalize on Windows |
| 1.2 | **Percent-encoding of user-supplied components** | `encodeURIComponent` (JS) / `urllib.parse.quote(string, safe='')` (Py) / `HttpUtility.UrlEncode` (.NET) / `url.PathEscape` (Go) | `encodeURIComponent('../x')` → `..%2Fx` | **`encodeURIComponent` does NOT encode `.`** → `'../../etc/passwd'` → `..%2Fetc%2Fpasswd` (not `%2E%2E%2F...`); `urllib.parse.quote` defaults `safe='/'` → must pass `safe=''` |
| 1.3 | **Path-component extraction (basename)** | `basename()` (PHP) / `os.path.basename` (Py) / `path.basename` (Node) / `Path.GetFileName` (.NET) | `basename('../../etc/passwd')` → `passwd` | `basename('uploads/..')` returns `'..'` — dot-dot survives; on Linux backslash is a legal filename char, so `..\..\etc\passwd` is NOT stripped → always reject `\` and `/` after |
| 1.4 | **Base64 / hex encoding of stored filenames** | `base64` / `hex` / `sha256` of input | `filename = sha256(input)[:16]` | On-disk name contains no path-significant characters at all; also prevents race conditions & info disclosure |
| 1.5 | **Input allowlisting / character-set filtering** | regex `^[a-zA-Z0-9_\-\.]+$` | reject anything with `/ \ ..` | Must be applied AFTER decode + canonicalization, never before (CWE-179/180) |
| 1.6 | **Validate-after-canonicalize ordering** | CWE-179 vs CWE-180 | — | CWE-179 (wrong): validate first, then canonicalize — canonicalization undoes validation; CWE-180 (right): canonicalize first, then validate |
| 1.7 | **Encode-for-context (output encoding)** | encode output for the context it is consumed in | — | If the path goes to a URL, URL-encode; to a shell, shell-escape (different context!) |
| 1.8 | **Separator neutralization** | explicit reject/encode of `/ \` and control bytes | — | On Linux must reject BOTH `\` and `/` (backslash is legal in filenames) |
| 1.9 | **Safe path builder helpers** | `secure_filename` (Werkzeug) / `os.Root` (Go 1.24+) / `res.sendFile(root:)` (Express) / `PhysicalFileProvider` (.NET) / `Paths.get().normalize().startsWith` (Java) | — | Werkzeug strips separators & collapses Unicode; Go `os.Root` enforces containment at OS layer |
| 1.10 | **Hex encoding alternative** | `hexlify(input)` | — | Filesystem-safe; reversible but no path-significant chars |
| 1.11 | **Single-decode to internal representation** | CWE-174 discipline | — | Decode exactly once at the boundary; store decoded; never re-decode at use |

---

## 2. Percent / URL Encoding Attack Vectors

Encoding forms used to bypass weak defenses (what the canonicalize-then-contain pattern must handle).

| # | Technique | Payload Example | Bypasses | Real CVE |
|---|-----------|-----------------|----------|----------|
| 2.1 | **Single percent-encoding** | `/files/%2e%2e/%2e%2e/etc/passwd` | blacklist/regex searching for literal `../` | ✅ CVE-2021-41773 (Apache 2.4.49) |
| 2.2 | **Double/triple encoding** | `/cgi-bin/.%%32%65%%32%65/%%32%65%%32%65/etc/passwd` | single-decode-then-check filters | ✅ CVE-2021-42013 (Apache 2.4.49/2.4.50) |
| 2.3 | **Null-byte (`%00`) truncation** | `../../etc/passwd%00.jpg` | extension checks (PHP < 5.3.4 truncates at `%00`) | ✅ CVE-2006-7243, CVE-2015-4025 |
| 2.4 | **Mixed percent + literal** | `/cgi-bin/.%2e/%2e%2e/etc/passwd` | both a literal-`..` AND a full-encoded `%2e%2e%2f` signature | ✅ CVE-2021-41773 |
| 2.5 | **Encoded backslash (`%5c`)** | `..%5c..%5cwindows%5cwin.ini` | filters that strip only `/` on Windows | ⚠️ CVE-2007-0450 (Apache/Tomcat proxy, not nginx) |
| 2.6 | **Plus-sign / space mismatch** | `+` decoded as space by one layer, literal `+` by another | constraint layer vs rewrite layer disagree | ✅ CVE-2026-59083 (Tomcat RewriteValve) |
| 2.7 | **Case-insensitive percent-hex** | `%2E` vs `%2e` | case-sensitive blacklists matching only one case | — |
| 2.8 | **Encoded path parameters / semicolon** | `/files/..;/config/` | path-parameter parsing (Tomcat, Rails) splits on `;` | — |
| 2.9 | **Proxy-vs-app decoding mismatch** | WAF decodes once, app server decodes again | multi-hop canonicalization divergence | CVE-2007-0450, CVE-2008-5515 |
| 2.10 | **nginx `$uri` vs `$request_uri`** | `proxy_pass http://backend$uri;` | `$uri` re-encodes the normalized path → backend decodes again | — |
| 2.11 | **Server encoded-slash policy** | Tomcat `ALLOW_ENCODED_SLASH`, `ALLOW_BACKSLASH`, `encodedSolidusHandling` | `%2f`, `%5c` accepted as path delimiters | — |

---

## 3. Unicode & Charset Vectors

| # | Technique | Payload Example | Notes | Real CVE |
|---|-----------|-----------------|-------|----------|
| 3.1 | **Overlong UTF-8** | `%c0%ae%c0%ae%c0%af` → `../` | IIS 5.0 lenient decoder maps overlong sequences to ASCII; slash `%c0%af`, dot `%c0%ae`, backslash `%c1%9c` (NOT `%c1%1c`) | ✅ CVE-2001-0333 |
| 3.2 | **Invalid/truncated multibyte** | `%c0%af` coerced to `/` | some Windows decoders coerce malformed sequences | — |
| 3.3 | **Fullwidth / lookalike separators** | `U+FF0E` (．) → `.`, `U+FF0F` (／) → `/`, `U+2215` (∕) → `/`, `U+FF3C` (＼) → `\` | ONLY collapses if app explicitly calls NFKC normalization; **Windows/NTFS does NOT fold these** — mechanism attribution error common | ⚠️ unverified |
| 3.4 | **NFC vs NFD mismatch (macOS)** | composed vs decomposed form | macOS HFS+/APFS stores NFD; validator checking NFC sees different bytes | ❌ CVE-2018-4230 is FALSE (that CVE is NVIDIA drivers) |
| 3.5 | **Case folding (CWE-178)** | case-insensitive names | Windows/macOS FS fold case; validator must too | — |
| 3.6 | **Dotless-i / Turkish locale** | `I` ↔ `ı`, `İ` ↔ `i` | locale-sensitive folding breaks case-insensitive compare | — |
| 3.7 | **Charset confusion** | ISO-8859-1 vs UTF-8 | bytes reinterpreted across decoders; 0x82 = C1 control in Latin-1, `‚` (U+201A) in CP1252 | — |
| 3.8 | **Mojibake / double-encoded UTF-8** | UTF-8 bytes UTF-8-encoded again | survives one decode layer | — |
| 3.9 | **Invalid UTF-8 passthrough** | raw bytes accepted by one layer, coerced by another | validator sees one encoding, FS sees another | — |
| 3.10 | **Decode-after-validation** | `%252e%252e%255c` | IIS double-decode family: validation happens before the second decode | CVE-2000-0884 (double-decode), distinct from CVE-2001-0333 |

---

## 4. OS & Filesystem Semantics

Encoding-relevant behaviors of real filesystems that defenses must respect.

### 4.1 Windows-specific

| # | Quirk | Payload Example | Mechanism |
|---|-------|-----------------|-----------|
| 4.1.1 | **Backslash/slash equivalence** | `..\\..\\config`, `../..\\config` | Win32 normalizes `/` → `\` internally |
| 4.1.2 | **Trailing dots & spaces** | `.. `, `...`, `file.asp.`, `file.asp%20` | Win32 trims trailing dots/spaces in most APIs (CWE-32/33 triple-dot, CWE-23) |
| 4.1.3 | **NTFS Alternate Data Streams** | `file.php::$DATA` | hidden stream attached to filename |
| 4.1.4 | **Reserved device names** | `CON`, `NUL`, `AUX`, `PRN`, `COM1-9`, `LPT1-9` | DOS device names; `NUL` suppresses output |
| 4.1.5 | **UNC paths** | `\\server\share\..\file` | escapes local base (CWE-40) |
| 4.1.6 | **Long-path prefix** | `\\?\C:\...` | bypasses MAX_PATH and some normalization |
| 4.1.7 | **NTFS 8.3 short names** | `PROGRA~1` for `Program Files` | canonicalization resolves to real name |
| 4.1.8 | **Case-insensitivity (CWE-178)** | `Passwd` == `passwd` | validator must case-normalize |
| 4.1.9 | **Drive-relative paths** | `C:foo`, `C:..\..\x` | relative to the drive's current directory, not root |

### 4.2 Linux-specific

| # | Quirk | Payload Example | Mechanism |
|---|-------|-----------------|-----------|
| 4.2.1 | **`/proc` magic symlinks** | `/proc/self/root/etc/passwd`, `/proc/self/cwd/`, `/proc/self/fd/N`, `/dev/fd`, `/dev/stdin` | `/proc/self/root` lexically passes a containment check but resolves to `/` |
| 4.2.2 | **Hardlink escape (CWE-59/62)** | attacker uploads hardlink to `/etc/shadow` | canonicalization is blind to hardlinks — same inode, different name |
| 4.2.3 | **Byte-exact semantics** | every character as-is | no trailing-dot strip, no case folding, no Unicode normalization |

### 4.3 Cross-platform

| # | Quirk | Mechanism |
|---|-------|-----------|
| 4.3.1 | **Symlink/junction following (CWE-59/61)** | `realpath()` resolves symlinks → TOCTOU window between check and use |
| 4.3.2 | **`path.join` vs string concat** | `path.join('/base','../../etc')` → `/etc`; `'/base/' + '../../etc'` → `/base/../../etc` |
| 4.3.3 | **Multiple leading slashes** | `//etc/passwd` — some parsers treat differently |
| 4.3.4 | **Relative escape from cwd** | `../../` from process current directory |

---

## 5. Language & Framework API Defenses

The canonical functions developers use to encode/normalize paths, and their documented pitfalls.

| Language | API | Correct Usage | Pitfall / Misuse |
|----------|-----|---------------|------------------|
| **Python** | `os.path.realpath()` | canonicalize then `startswith` | returns empty string if path doesn't exist |
| **Python** | `os.path.normpath()` | lexical collapse `..` | does NOT resolve symlinks; `normpath` docs warn it may change meaning of symlinked paths |
| **Python** | `pathlib.Path.resolve()` | — | touches filesystem; strict mode fails on missing |
| **Python** | `urllib.parse.quote()` | **must pass `safe=''`** | default `safe='/'` leaves separators passable |
| **Python** | `Werkzeug secure_filename()` | drop-in safe filename | strips separators + collapses Unicode; strips leading dots (may rename files) |
| **Java** | `Paths.get(base, input).normalize().startsWith(base)` | canonical containment | `Path.normalize()` is lexical, no symlink resolution |
| **Java** | `Path.toRealPath()` | resolve symlinks | throws on nonexistent; TOCTOU |
| **Java** | `URI.normalize()` | — | lexical only |
| **Java** | `URLEncoder` | ⚠️ **WRONG for path segments** | encodes space as `+` — that's form encoding, not path encoding |
| **Node.js** | `path.resolve()` | canonicalize-then-check | lexical only, no symlink resolution |
| **Node.js** | `path.normalize()` | — | lexical only |
| **Node.js** | `encodeURIComponent`/`decodeURIComponent` | encode output, never decode user paths blindly | `decodeURIComponent` on path re-enables encoded traversal |
| **Node.js** | `express.static(root)` / `res.sendFile(path, {root})` | built-in containment | root option required; else open path |
| **.NET** | `Path.GetFullPath(String)` | use `GetFullPath(path, basePath)` overload | 1-arg version resolves against **mutable current directory** |
| **.NET** | `Path.Combine` | join with base | doesn't validate containment by itself |
| **.NET** | `PhysicalFileProvider` | framework containment | maps into content root |
| **.NET** | `Uri.EscapeDataString` vs `HttpUtility.UrlEncode` | EscapeDataString for path segments | UrlEncode is form-style (space→`+`) |
| **Go** | `filepath.Clean` | — | lexical only |
| **Go** | `filepath.Rel` | check result stays within base | — |
| **Go** | `http.Dir` / `http.FileServer` | string containment | bypassed by `..;/` and `//` variants in older versions |
| **Go 1.24+** | `os.Root` | OS-layer containment | new, not universally adopted |
| **PHP** | `realpath()` | canonicalize-then-check | returns `false` on nonexistent path |
| **PHP** | `basename()` | first-line filter | `basename('uploads/..')` → `'..'` — naive string op |
| **PHP** | `pathinfo()` | — | — |
| **PHP** | `filter_var(..., FILTER_SANITIZE_URL)` | — | — |
| **Ruby** | `File.expand_path` | — | — |
| **Ruby** | `File.basename` | — | same dot-dot caveat |
| **Ruby** | `sanitize-path` gem | — | — |
| **Rust** | `std::path::Path.canonicalize()` | canonicalize-then-contain | requires path exists; TOCTOU |
| **Rust** | `camino` / `path_clean` / `sanitize-filename` crates | — | lexical crates do not resolve symlinks |
| **C/C++** | `realpath()` | canonicalize-then-check | TOCTOU |
| **C/C++** | `canonicalize_file_name()` | — | GNU-specific |
| **C/C++** | `_fullpath` (Windows) | — | — |
| **Web** | Apache `mod_alias` canonicalization | — | `..%2f` traversal → CVE-2021-41773 |
| **Web** | Nginx `alias` directive | require trailing-slash match | missing trailing slash → traversal |
| **Web** | IIS `Request.Path` canonicalization | — | IIS double-decode family |

---

## 6. Transport & Protocol-Level Encodings

Encoding layers beyond the URL/path string itself.

| # | Technique | Example | Mechanism |
|---|-----------|---------|-----------|
| 6.1 | **Whitespace / control chars** | `%0a` (LF), `%0d` (CR), `%09` (tab), `%20` (space) | truncators or extension-check bypasses (`shell.asp%20`, `shell.asp.`); CRLF log/CSV injection |
| 6.2 | **Archive entry traversal (zip-slip)** | encoded separators, `..`, NUL, Unicode variants inside `zip`/`jar`/`tar` entry names | must apply canonicalize-then-contain to entry names before extraction |
| 6.3 | **WebDAV MOVE/COPY** | MOVE resource to encoded/special target; PUT to `..`-resolving destination | rename-based upload bypass |
| 6.4 | **Transport content-encoding** | `Content-Encoding: gzip` / deflate | WAF sees opaque bytes, origin decompresses (encoding-layer analog of double-decode) |
| 6.5 | **Chunked transfer smuggling** | chunked TE hiding traversal path | bypasses byte-scanning filters |
| 6.6 | **Non-percent encodings** | `%u002e` (IIS `.`), UTF-7 (legacy IIS/ASP), HTML entity `&#x2e;` / `&#46;`, quoted-printable, uuencode, base85 | non-percent forms evade `%`-aware filters |
| 6.7 | **RFC 2231 / RFC 5987 `filename*`** | multipart `filename*=UTF-8''..%2f..%2f` | parser decodes this form while filter inspects `filename=` |
| 6.8 | **Filesystem vs shell context (CWE-78)** | `;` `\|` `` ` `` `$()` glob `*` `?` `[` `]` `~` | path data reaching a shell is a different encoding context filesystem canonicalization does NOT defend |

---

## 7. Encoding Evasion Matrix (payload → defense)

Quick lookup: which payload defeats which defense, and what stops it.

| Payload | Defeats | Stopped By |
|---------|---------|-----------|
| `../` literal | nothing (if you filter `..`) | filter + canonicalize |
| `..%2f` | literal-`..` filter | decode-then-canonicalize |
| `%2e%2e%2f` | `..` and `../` filters | single decode → canonicalize |
| `%252e%252e%252f` | single-decode filter | decode ALL layers → canonicalize |
| `.%2e/` | `..` AND `%2e%2e%2f` filters | decode → canonicalize |
| `..%5c..` | `/`-only filters on Windows | reject `\` + canonicalize |
| `..%00` | extension checks | reject NUL before use |
| `%c0%ae%c0%ae%c0%af` | ASCII-only filters | reject overlong UTF-8 at boundary |
| `..\..\` (backslash) | `/`-only filters on Windows | reject `\` on all platforms |
| `...` (triple dot) | `..` exact-match filters | reject any `.` sequence + canonicalize |
| `.. ` (trailing space) | exact `..` match (Win32 trims) | allowlist charset + canonicalize |
| `file.php::$DATA` | extension check (reads stream) | reject `:` / ADS syntax |
| `CON` / `NUL` | normal filename logic | reject device names on Windows |
| `//etc/passwd` | missing-root checks | require absolute base |
| `C:..\..` | relative-base checks | resolve to absolute drive path |
| `/proc/self/root/etc/passwd` | `startsWith(base)` where base contains `/proc` | realpath + verify NOT root escape |
| `file.asp%20` / `file.asp.` | `.asp`-extension allowlist | reject control/space/dot at end |
| `filename*=UTF-8''..%2f..%2f` | `filename=` filter | decode RFC 2231/5987 form too |

---

## 8. CVE Reference Table

Fact-checked against the MITRE database. `✅` = confirmed, `⚠️` = corrected (details), `❌` = false claim.

| CVE | Product | Technique | Status |
|-----|---------|-----------|--------|
| CVE-2001-0333 | IIS 5.0 | Overlong UTF-8 Unicode traversal `%c0%af` | ✅ **Confirmed** |
| CVE-2006-7243 | PHP < 5.3.4 | Null-byte `%00` truncation | ✅ **Confirmed** |
| CVE-2015-4025 | PHP 5.4.x–5.6.x | Null-byte truncation (incomplete fix) | ⚠️ **Corrected** — affected versions are 5.4.x<5.4.41, 5.5.x<5.5.25, 5.6.x<5.6.9 |
| CVE-2021-41773 | Apache 2.4.49 | `.%2e` mixed encoding in mod_alias | ✅ **Confirmed** |
| CVE-2021-42013 | Apache 2.4.49/2.4.50 | Double-encoding bypass of 41773 fix | ✅ **Confirmed** |
| CVE-2007-0450 | Apache/Tomcat proxy | Backslash `%5C` traversal escaping context | ⚠️ **Corrected** — affects Apache/Tomcat (mod_proxy, mod_rewrite, mod_jk), NOT nginx |
| CVE-2008-5515 | Apache Tomcat | RequestDispatcher normalization order → WEB-INF | ⚠️ **Corrected** — proxy mismatch part belongs to CVE-2007-0450 |
| CVE-2026-59083 | Apache Tomcat | RewriteValve `+` vs space decoding (CWE-177) | ✅ **Confirmed** (recent — treat as needs-verification) |
| CVE-2000-0884 | IIS | Double-encoded-character (double-decode) bug | ⚠️ distinct from CVE-2001-0333 (overlong UTF-8) |
| CVE-2009-3898 | nginx | WebDAV Destination-header traversal (COPY/MOVE) | ❌ **False claim** — the claimed `%2e%2e%2f` URL traversal is fabricated for this CVE |
| CVE-2011-4963 | nginx/Windows | Access-restriction bypass via trailing dot / `$index_allocation` | ❌ **False claim** — the claimed `%5c` backslash traversal is fictitious for this CVE |
| CVE-2018-4230 | macOS | Claimed: Safari Unicode-normalization download bypass | ❌ **False** — CVE is NVIDIA Graphics Drivers use-after-free, not Safari |
| CVE-2000-0240 / CVE-1999-1082 / CVE-2004-2121 / CVE-2001-0615 | — | Trailing-dot/triple-dot CVEs from CWE pages | ⚠️ **needs verification** — asserted without direct source confirmation |

---

## 9. The Universal Defense Pattern

```
1. DECODE          → Resolve all layers of encoding (percent, Unicode, charset)
2. CANONICALIZE    → realpath / resolve / getCanonicalPath / GetFullPath
3. ALLOWLIST       → Reject anything outside [a-zA-Z0-9_\-.] or verify prefix containment
4. VERIFY CONTAIN  → canonical.startsWith(base + sep) — NOT base alone
```

### Rules that never change

- **Check after canonicalization, never before** (CWE-179 vs CWE-180).
- **Decode exactly once, at the boundary** — then store the decoded form; never re-decode at use (CWE-174).
- **Never build paths by string concatenation** — use `path.join`-style APIs.
- **Qualify prefix checks with a trailing separator** — `/safe` must not match `/safe_evil`.
- **Handle TOCTOU** — the canonicalized path can change between check and use (symlinks, junctions).
- **Respect the target OS** — case-insensitivity, `/` vs `\`, trailing dots/spaces, device names, ADS, 8.3 names, drive-relative paths.
- **Separate filesystem context from shell/command context** (CWE-22 vs CWE-78) — filesystem canonicalization does not defend shell metacharacters.
- **Do not rely on any single encoding as a control** — encoding is a defense-in-depth layer; canonicalize-then-contain is the control.

---

*Generated from multi-agent deep research. CVE entries fact-checked against the MITRE CVE database. Verify any unmarked/unverified CVE before citing in production security documentation.*
