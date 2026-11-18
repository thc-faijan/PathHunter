#!/usr/bin/env python3
"""
PathHunter v4.0
Authorized path-traversal assessment helper.

Features:
- Custom payload wordlists
- Query-parameter discovery
- Optional HTML form parameter discovery (discovery only; GET query parameters are tested)
- Response status/length/hash comparison
- Conservative Linux/Windows file-disclosure indicators
- Optional URL-encoding variants
- Threaded requests with per-thread sessions
- Custom headers, cookies, proxy and timeout
- TXT, JSON and CSV output

Use only on systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

BANNER = """
PathHunter v4.0 | Path Traversal Tester
"""

# These are content clues, not proof by themselves.
INDICATORS = {
    "linux_passwd": [
        re.compile(r"(?m)^root:[^:\r\n]*:0:0:"),
        re.compile(r"(?m)^(daemon|bin|www-data):[^:\r\n]*:\d+:\d+:"),
    ],
    "linux_shell": [
        re.compile(r"(?m)^root:.*:/bin/(?:bash|sh)\s*$"),
        re.compile(r"(?m)^www-data:.*:/usr/sbin/nologin\s*$"),
    ],
    "windows_ini": [
        re.compile(r"(?im)^\[extensions\]\s*$"),
        re.compile(r"(?im)^\[fonts\]\s*$"),
        re.compile(r"(?im)^\[mci extensions\]\s*$"),
    ],
}

_thread_local = threading.local()
_print_lock = threading.Lock()


@dataclass
class Finding:
    parameter: str
    payload: str
    tested_url: str
    status_code: int | None
    response_length: int | None
    baseline_status: int | None
    baseline_length: int | None
    length_delta: int | None
    indicators: list[str]
    classification: str
    note: str


def make_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    session.headers.update(args.headers)
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})
    adapter = HTTPAdapter(pool_connections=args.threads, pool_maxsize=args.threads)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def session_for_thread(args: argparse.Namespace) -> requests.Session:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = make_session(args)
    return _thread_local.session


def parse_headers(items: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items or []:
        if ":" not in item:
            raise ValueError(f"Invalid header {item!r}; expected 'Name: value'")
        name, value = item.split(":", 1)
        if not name.strip():
            raise ValueError("Header name cannot be empty")
        headers[name.strip()] = value.strip()
    return headers


def load_wordlist(path: str) -> list[str]:
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {file_path}")
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        # Preserve payload characters exactly apart from surrounding whitespace.
        items = [line.strip() for line in handle
                 if line.strip() and not line.lstrip().startswith("#")]
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(items))


def build_test_url(url: str, parameter: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, value in query:
        if key == parameter:
            if not replaced:
                updated.append((key, payload))
                replaced = True
        else:
            updated.append((key, value))
    if not replaced:
        updated.append((parameter, payload))

    # Keep valid %XX sequences from encoding-variant payloads intact.
    encoded = urllib.parse.urlencode(updated, doseq=True, safe="%")
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, encoded, parts.fragment)
    )


def discover_parameters(url: str, response: requests.Response,
                        include_forms: bool) -> list[str]:
    parts = urllib.parse.urlsplit(url)
    params = [key for key, _ in urllib.parse.parse_qsl(
        parts.query, keep_blank_values=True
    )]

    if include_forms:
        soup = BeautifulSoup(response.text, "html.parser")
        for form in soup.find_all("form"):
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")
                if name:
                    params.append(name)

    return list(dict.fromkeys(params))


def make_variants(payload: str, enabled: bool) -> list[str]:
    if not enabled:
        return [payload]
    # Keep the original and add common transport-encoding variants.
    once = urllib.parse.quote(payload, safe="")
    twice = urllib.parse.quote(once, safe="")
    variants = [payload, once, twice]
    return list(dict.fromkeys(variants))


def response_indicators(body: str) -> list[str]:
    matched: list[str] = []
    for category, patterns in INDICATORS.items():
        if any(pattern.search(body) for pattern in patterns):
            matched.append(category)
    return matched


def response_fingerprint(response: requests.Response) -> str:
    return hashlib.sha256(response.content).hexdigest()


def classify_response(response: requests.Response, baseline: requests.Response,
                      indicators: list[str]) -> tuple[str, str]:
    if indicators:
        return (
            "indicator_match",
            "Response contains a known file-content indicator; manually verify context."
        )

    changed = (
        response.status_code != baseline.status_code
        or len(response.content) != len(baseline.content)
        or response_fingerprint(response) != response_fingerprint(baseline)
    )
    if changed:
        return (
            "response_changed",
            "Response differs from baseline; this is not proof of path traversal."
        )

    return ("no_obvious_signal", "No configured indicator or notable response change.")


def fetch_baseline(url: str, args: argparse.Namespace) -> requests.Response:
    session = session_for_thread(args)
    return session.get(
        url,
        timeout=args.timeout,
        allow_redirects=True,
        verify=not args.insecure,
    )


def test_one(url: str, parameter: str, payload: str,
             baseline: requests.Response, args: argparse.Namespace) -> Finding:
    tested_url = build_test_url(url, parameter, payload)
    try:
        response = session_for_thread(args).get(
            tested_url,
            timeout=args.timeout,
            allow_redirects=True,
            verify=not args.insecure,
        )
        indicators = response_indicators(response.text)
        classification, note = classify_response(response, baseline, indicators)
        return Finding(
            parameter=parameter,
            payload=payload,
            tested_url=tested_url,
            status_code=response.status_code,
            response_length=len(response.content),
            baseline_status=baseline.status_code,
            baseline_length=len(baseline.content),
            length_delta=len(response.content) - len(baseline.content),
            indicators=indicators,
            classification=classification,
            note=note,
        )
    except requests.RequestException as exc:
        return Finding(
            parameter=parameter,
            payload=payload,
            tested_url=tested_url,
            status_code=None,
            response_length=None,
            baseline_status=baseline.status_code,
            baseline_length=len(baseline.content),
            length_delta=None,
            indicators=[],
            classification="request_error",
            note=str(exc),
        )


def write_reports(findings: list[Finding], args: argparse.Namespace,
                  metadata: dict[str, Any]) -> None:
    # Reports contain only successful indicator matches. Network errors,
    # ordinary responses and response-only differences are excluded.
    successful = [
        item for item in findings
        if item.classification == "indicator_match"
        and item.status_code is not None
        and 200 <= item.status_code < 300
        and item.indicators
    ]

    metadata = {
        **metadata,
        "successful_payload_count": len(successful),
        "report_filter": "2xx responses with configured file-disclosure indicators",
    }

    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as handle:
        handle.write("PathHunter v4.0 - Successful Payloads\\n")
        handle.write(f"Target: {metadata['target']}\\n")
        handle.write(f"Successful matches: {len(successful)}\\n")
        handle.write("=" * 64 + "\\n")

        if not successful:
            handle.write("No successful indicator matches found.\\n")
        else:
            for item in successful:
                handle.write(
                    f"[SUCCESSFUL INDICATOR MATCH]\\n"
                    f"Parameter: {item.parameter}\\n"
                    f"Payload: {item.payload}\\n"
                    f"HTTP Status: {item.status_code}\\n"
                    f"Indicators: {', '.join(item.indicators)}\\n"
                    f"Response Length: {item.response_length}\\n"
                    f"Test URL: {item.tested_url}\\n"
                    f"{'-' * 64}\\n"
                )

    if args.json:
        json_path = Path(args.json).expanduser()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(
                {"metadata": metadata, "results": [asdict(x) for x in successful]},
                indent=2
            ),
            encoding="utf-8",
        )

    if args.csv:
        csv_path = Path(args.csv).expanduser()
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = list(Finding.__dataclass_fields__)
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for item in successful:
                row = asdict(item)
                row["indicators"] = ";".join(row["indicators"])
                writer.writerow(row)


def interactive_args() -> list[str]:
    print(BANNER)
    url = input("[?] Target URL: ").strip()
    parameter = input("[?] Parameter (blank = discover query parameters): ").strip()
    wordlist = input("[?] Wordlist path: ").strip()
    output = input("[?] Output file [output.txt]: ").strip() or "output.txt"
    threads = input("[?] Threads [10]: ").strip() or "10"

    result = ["-u", url, "-w", wordlist, "-o", output, "-t", threads]
    if parameter:
        result += ["-p", parameter]
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PathHunter v4.0 - Path Traversal Testing Toolkit"
    )
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-p", "--param", help="Parameter to test; omit to discover query parameters")
    parser.add_argument("-w", "--wordlist", help="Custom payload wordlist")
    parser.add_argument("-o", "--output", default="output.txt", help="TXT output path")
    parser.add_argument("--json", help="Optional JSON report path")
    parser.add_argument("--csv", help="Optional CSV report path")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Workers (1-20)")
    parser.add_argument("--timeout", type=float, default=10, help="Per-request timeout")
    parser.add_argument("-H", "--header", action="append", help="Custom header; repeatable")
    parser.add_argument("--cookie", action="append", help="Cookie as name=value; repeatable")
    parser.add_argument("--proxy", help="Proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--encode-variants", action="store_true",
                        help="Also test URL-encoded and double-encoded payload variants")
    parser.add_argument("--discover-forms", action="store_true",
                        help="Include HTML form field names in parameter discovery (discovery only)")
    parser.add_argument("--delay", type=float, default=0,
                        help="Delay in seconds between task submissions")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification")
    return parser


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        argv = interactive_args()

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.url or not args.wordlist:
        parser.error("-u/--url and -w/--wordlist are required")
    if not args.url.startswith(("http://", "https://")):
        parser.error("URL must begin with http:// or https://")
    if not 1 <= args.threads <= 20:
        parser.error("Threads must be between 1 and 20")
    if args.timeout <= 0 or args.delay < 0:
        parser.error("Timeout must be positive and delay cannot be negative")

    try:
        args.headers = parse_headers(args.header)
        if args.cookie:
            cookie_header = "; ".join(args.cookie)
            args.headers["Cookie"] = cookie_header
        payloads = load_wordlist(args.wordlist)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    if not payloads:
        parser.error("Wordlist is empty")

    print(BANNER.strip())
    print(f"[*] Wordlist: {len(payloads)} unique payloads")

    try:
        baseline = fetch_baseline(args.url, args)
    except requests.RequestException as exc:
        print(f"[!] Baseline request failed: {exc}")
        return 2

    parameters = [args.param] if args.param else discover_parameters(
        args.url, baseline, args.discover_forms
    )
    if not parameters:
        print("[!] No query parameters discovered. Supply one with -p.")
        return 1

    print(f"[*] Target: {args.url}")
    print(f"[*] Parameters: {', '.join(parameters)}")
    print(f"[*] Payload variants: {args.threads} workers")
    print("[*] Scanning...")

    jobs: list[tuple[str, str]] = []
    for parameter in parameters:
        for payload in payloads:
            for variant in make_variants(payload, args.encode_variants):
                jobs.append((parameter, variant))

    metadata = {
        "tool": "PathHunter",
        "version": "4.0",
        "target": args.url,
        "parameters": parameters,
        "payload_count": len(payloads),
        "task_count": len(jobs),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_status": baseline.status_code,
        "baseline_length": len(baseline.content),
    }

    results: list[Finding] = []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = []
        for parameter, payload in jobs:
            futures.append(pool.submit(
                test_one, args.url, parameter, payload, baseline, args
            ))
            if args.delay:
                time.sleep(args.delay)

        for index, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if index % 25 == 0 or index == len(futures):
                print(
                    f"\r[*] Progress: {index}/{len(futures)}",
                    end="", flush=True
                )

    elapsed = time.monotonic() - started
    results.sort(key=lambda x: (x.parameter, x.payload))
    metadata["finished_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["duration_seconds"] = round(elapsed, 2)

    write_reports(results, args, metadata)

    indicator_count = sum(r.classification == "indicator_match" for r in results)
    changed_count = sum(r.classification == "response_changed" for r in results)
    error_count = sum(r.classification == "request_error" for r in results)

    print("\n\nScan complete")
    print(f"  Tested:     {len(results)}")
    print(f"  Indicators: {indicator_count}")
    print(f"  Changed:    {changed_count}")
    print(f"  Errors:     {error_count}")
    print(f"  Duration:   {elapsed:.2f}s")
    print(f"  Report:     {Path(args.output).resolve()}")
    if args.json:
        print(f"  JSON:       {Path(args.json).expanduser().resolve()}")
    if args.csv:
        print(f"  CSV:        {Path(args.csv).expanduser().resolve()}")
    print("\nNote: Review findings manually; response changes alone are not proof.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        raise SystemExit(130)
