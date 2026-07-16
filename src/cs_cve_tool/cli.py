from __future__ import annotations

import argparse
import csv
import html
import itertools
import json
import os
import queue
import re
import sys
import threading
import time
from collections import Counter
from datetime import date
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import dotenv_values, load_dotenv, set_key

from .client import FalconCredentials, FalconSpotlightClient

CVSS_AV_PATTERN = re.compile(r"(?:^|/)AV:([NALP])(?:/|$)")
CVSS_AC_PATTERN = re.compile(r"(?:^|/)AC:([LH])(?:/|$)")

AV_LABELS = {
    "N": "Network",
    "A": "Adjacent Network",
    "L": "Local",
    "P": "Physical",
}

AC_LABELS = {
    "L": "Low",
    "H": "High",
}

DEFAULT_BASE_URL = "https://api.eu-1.crowdstrike.com"
TOOL_VERSION = "0.0.1a"
BUILD_DATE = date.today().strftime("%d.%m.%Y")
ENV_PATH = Path(".env")


@dataclass
class InteractiveSelection:
    min_score: Optional[float]
    attack_vector: Optional[str]
    attack_complexity: Optional[str]

ATTACK_VECTOR_ALIASES = {
    "n": "Network",
    "network": "Network",
    "a": "Adjacent Network",
    "adjacent": "Adjacent Network",
    "adjacent network": "Adjacent Network",
    "adjacent_network": "Adjacent Network",
    "adjacent-network": "Adjacent Network",
    "l": "Local",
    "local": "Local",
    "p": "Physical",
    "physical": "Physical",
}

ATTACK_COMPLEXITY_ALIASES = {
    "l": "Low",
    "low": "Low",
    "h": "High",
    "high": "High",
}


@dataclass
class NormalizedVuln:
    cve_id: str
    host: str
    aid: str
    score: Optional[float]
    severity: Optional[str]
    attack_vector: Optional[str]
    attack_complexity: Optional[str]
    vector_raw: Optional[str]


def parse_cvss_metrics(vector: Optional[str]) -> Dict[str, Optional[str]]:
    if not vector:
        return {"attack_vector": None, "attack_complexity": None}

    av_match = CVSS_AV_PATTERN.search(vector)
    ac_match = CVSS_AC_PATTERN.search(vector)

    av_code = av_match.group(1) if av_match else None
    ac_code = ac_match.group(1) if ac_match else None

    return {
        "attack_vector": AV_LABELS.get(av_code) if av_code else None,
        "attack_complexity": AC_LABELS.get(ac_code) if ac_code else None,
    }


def _normalize_attack_vector(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    key = str(value).strip().lower()
    return ATTACK_VECTOR_ALIASES.get(key)


def _normalize_attack_complexity(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    key = str(value).strip().lower()
    return ATTACK_COMPLEXITY_ALIASES.get(key)


def _coalesce_non_empty(*values: Any) -> Optional[str]:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def build_filter(args: argparse.Namespace, include_min_score: bool = True) -> str:
    filters: List[str] = []

    if args.cve:
        filters.append(f"cve.id:'{args.cve.upper()}'")
    if args.status:
        filters.append(f"status:'{args.status}'")
    if include_min_score and args.min_score is not None:
        filters.append(f"cve.base_score:>={args.min_score}")

    return "+".join(filters) if filters else ""


def to_normalized(resource: Dict[str, Any]) -> NormalizedVuln:
    cve = resource.get("cve", {}) if isinstance(resource.get("cve"), dict) else {}
    host_info = resource.get("host_info", {}) if isinstance(resource.get("host_info"), dict) else {}

    vector = cve.get("vector") or cve.get("vector_string") or cve.get("cvss_vector")
    parsed = parse_cvss_metrics(vector)

    # Prefer explicit CVSS fields when present, then fall back to parsing the CVSS vector.
    attack_vector = _normalize_attack_vector(
        _coalesce_non_empty(
            cve.get("attack_vector"),
            cve.get("cvss_attack_vector"),
            resource.get("attack_vector"),
            resource.get("cvss_attack_vector"),
        )
    ) or parsed["attack_vector"]

    attack_complexity = _normalize_attack_complexity(
        _coalesce_non_empty(
            cve.get("attack_complexity"),
            cve.get("cvss_attack_complexity"),
            resource.get("attack_complexity"),
            resource.get("cvss_attack_complexity"),
        )
    ) or parsed["attack_complexity"]

    aid = resource.get("aid") or host_info.get("aid") or ""
    host = host_info.get("hostname") or resource.get("hostname") or ""

    return NormalizedVuln(
        cve_id=str(cve.get("id") or resource.get("cve_id") or "UNKNOWN"),
        host=str(host),
        aid=str(aid),
        score=_safe_float(cve.get("base_score")),
        severity=cve.get("severity"),
        attack_vector=attack_vector,
        attack_complexity=attack_complexity,
        vector_raw=vector,
    )


def _safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def apply_local_filters(items: List[NormalizedVuln], attack_vector: Optional[str], attack_complexity: Optional[str]) -> List[NormalizedVuln]:
    filtered = items

    if attack_vector:
        av_norm = _normalize_attack_vector(attack_vector)
        if av_norm:
            filtered = [v for v in filtered if v.attack_vector == av_norm]

    if attack_complexity:
        ac_norm = _normalize_attack_complexity(attack_complexity)
        if ac_norm:
            filtered = [v for v in filtered if v.attack_complexity == ac_norm]

    return filtered


def filter_by_min_score(items: List[NormalizedVuln], min_score: Optional[float]) -> List[NormalizedVuln]:
    if min_score is None:
        return items
    return [item for item in items if item.score is not None and item.score >= min_score]


def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
        return

    if os.getenv("TERM"):
        os.system("clear")


def print_greeting() -> None:
    print("CrowdStrike Spotlight Filter")
    print("This is not an official tool.")
    print(f"Version: {TOOL_VERSION}")
    print(f"Build date: {BUILD_DATE}")
    print()


def _prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        raw = input(f"{prompt} {suffix}: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _prompt_yes_no_timeout(prompt: str, default: bool = False, timeout_seconds: int = 5) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    full_prompt = f"{prompt} {suffix}: "

    if not sys.stdin.isatty():
        return default

    result: queue.Queue[Optional[str]] = queue.Queue()

    def _reader() -> None:
        try:
            result.put(input(full_prompt).strip().lower())
        except EOFError:
            result.put(None)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()
    reader_thread.join(timeout_seconds)

    if reader_thread.is_alive():
        print()
        print(f"No response received in {timeout_seconds}s. Defaulting to {'Yes' if default else 'No'}.")
        return default

    raw = result.get_nowait()
    if not raw:
        return default
    if raw in {"y", "yes"}:
        return True
    if raw in {"n", "no"}:
        return False

    print("Invalid response. Defaulting to No.")
    return default


def _prompt_non_empty(prompt: str, default: Optional[str] = None, secret: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        text = getpass(f"{prompt}{suffix}: ") if secret else input(f"{prompt}{suffix}: ")
        text = text.strip()
        if not text and default:
            return default
        if text:
            return text
        print("This field is required.")


def _save_credentials_to_env(client_id: str, client_secret: str, base_url: str) -> None:
    set_key(str(ENV_PATH), "FALCON_CLIENT_ID", client_id)
    set_key(str(ENV_PATH), "FALCON_CLIENT_SECRET", client_secret)
    set_key(str(ENV_PATH), "FALCON_BASE_URL", base_url)


def _collect_credentials_with_prompt(base_url_from_args: Optional[str], force_update: bool = False) -> FalconCredentials:
    load_dotenv(dotenv_path=str(ENV_PATH))
    env_file_values = dotenv_values(str(ENV_PATH)) if ENV_PATH.exists() else {}

    file_client_id = str(env_file_values.get("FALCON_CLIENT_ID") or "").strip()
    file_client_secret = str(env_file_values.get("FALCON_CLIENT_SECRET") or "").strip()
    file_base_url = str(env_file_values.get("FALCON_BASE_URL") or "").strip()

    has_file_creds = bool(file_client_id and file_client_secret)
    should_update = force_update

    if has_file_creds and not force_update and sys.stdin.isatty():
        should_update = _prompt_yes_no_timeout(
            "Credentials found in .env. Do you want to update them?",
            default=False,
            timeout_seconds=5,
        )

    if has_file_creds and not should_update:
        return FalconCredentials(
            client_id=file_client_id,
            client_secret=file_client_secret,
            base_url=base_url_from_args or file_base_url or DEFAULT_BASE_URL,
        )

    if not sys.stdin.isatty():
        raise RuntimeError("Missing or invalid credentials and interactive input is not available.")

    print("Please provide CrowdStrike API credentials.")
    client_id = _prompt_non_empty("FALCON_CLIENT_ID", default=file_client_id or None)
    client_secret = _prompt_non_empty("FALCON_CLIENT_SECRET", default=file_client_secret or None, secret=True)
    base_url_default = base_url_from_args or file_base_url or DEFAULT_BASE_URL
    base_url = _prompt_non_empty("FALCON_BASE_URL", default=base_url_default)

    _save_credentials_to_env(client_id, client_secret, base_url)
    print("Credentials saved to .env")

    return FalconCredentials(client_id=client_id, client_secret=client_secret, base_url=base_url)


def load_credentials(base_url_from_args: Optional[str]) -> FalconCredentials:
    force_update = False
    while True:
        creds = _collect_credentials_with_prompt(base_url_from_args=base_url_from_args, force_update=force_update)
        validator = FalconSpotlightClient(creds)
        valid, message = validator.validate_credentials()
        if valid:
            print("Credentials validated successfully.")
            print()
            return creds

        print(f"Credential validation failed: {message}")
        if not sys.stdin.isatty():
            raise RuntimeError("Credentials validation failed and interactive retry is not available.")

        print("Please enter credentials again.")
        force_update = True


def _prompt_choice(prompt: str, options: List[str]) -> str:
    while True:
        print(prompt)
        for idx, option in enumerate(options, start=1):
            print(f"  {idx}. {option}")

        sys.stdout.write("Select an option by number: ")
        sys.stdout.flush()
        raw = input().strip()
        if not raw.isdigit():
            print("Invalid choice. Please enter a number.")
            continue

        selected = int(raw)
        if 1 <= selected <= len(options):
            return options[selected - 1]

        print("Choice out of range. Try again.")


def _count_by_min_score(items: List[NormalizedVuln], threshold: float) -> int:
    return len([item for item in items if item.score is not None and item.score >= threshold])


def _prompt_cvss_score_filter(items: List[NormalizedVuln]) -> tuple[List[NormalizedVuln], Optional[float]]:
    critical_count = _count_by_min_score(items, 9.0)
    high_count = _count_by_min_score(items, 7.0)
    medium_count = _count_by_min_score(items, 4.0)
    low_count = _count_by_min_score(items, 0.1)

    options = [
        f"CVSS >= 9.0 (Critical) ({critical_count})",
        f"CVSS >= 7.0 (High+) ({high_count})",
        f"CVSS >= 4.0 (Medium+) ({medium_count})",
        f"CVSS >= 0.1 (Low+) ({low_count})",
        "Custom minimum...",
        f"All ({len(items)})",
    ]

    selected = _prompt_choice("\nSelect CVSS score", options)
    if selected.startswith("All"):
        return items, None

    if selected == "Custom minimum...":
        while True:
            raw = input("Enter custom minimum CVSS score (0.0 - 10.0): ").strip()
            try:
                value = float(raw)
            except ValueError:
                print("Invalid number. Try again.")
                continue

            if 0.0 <= value <= 10.0:
                filtered = [item for item in items if item.score is not None and item.score >= value]
                return filtered, value

            print("Score must be between 0.0 and 10.0.")

    threshold_text = selected.split("(", 1)[0].strip()
    if ">= 9.0" in threshold_text:
        return [item for item in items if item.score is not None and item.score >= 9.0], 9.0
    if ">= 7.0" in threshold_text:
        return [item for item in items if item.score is not None and item.score >= 7.0], 7.0
    if ">= 4.0" in threshold_text:
        return [item for item in items if item.score is not None and item.score >= 4.0], 4.0

    return [item for item in items if item.score is not None and item.score >= 0.1], 0.1


def _prompt_category_filter(step_label: str, items: List[NormalizedVuln], field_name: str) -> Optional[str]:
    counts: Counter[str] = Counter()
    for item in items:
        raw_value = getattr(item, field_name)
        counts[_value_or_unknown(raw_value)] += 1

    if not counts:
        return None

    sorted_values = [name for name, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    options = [f"{value} ({counts[value]})" for value in sorted_values]
    options.append(f"All ({len(items)})")
    selected = _prompt_choice(step_label, options)

    if selected.startswith("All"):
        return None

    return selected.rsplit("(", 1)[0].strip()


def run_interactive_selection(items: List[NormalizedVuln]) -> tuple[List[NormalizedVuln], InteractiveSelection]:
    print(f"\nFetched {len(items)} vulnerability records.\n")

    score_filtered, selected_min_score = _prompt_cvss_score_filter(items)

    selected_vector = _prompt_category_filter(
        "\nSelect attack vector",
        score_filtered,
        "attack_vector",
    )
    vector_filtered = [
        item for item in score_filtered
        if selected_vector is None or _value_or_unknown(item.attack_vector) == selected_vector
    ]
    print(f"Records after attack vector filter: {len(vector_filtered)}")

    selected_complexity = _prompt_category_filter(
        "\nSelect attack complexity",
        vector_filtered,
        "attack_complexity",
    )
    final_filtered = [
        item for item in vector_filtered
        if selected_complexity is None or _value_or_unknown(item.attack_complexity) == selected_complexity
    ]
    print(f"Records after attack complexity filter: {len(final_filtered)}")

    return final_filtered, InteractiveSelection(
        min_score=selected_min_score,
        attack_vector=selected_vector,
        attack_complexity=selected_complexity,
    )


def print_equivalent_command(selection: InteractiveSelection, limit: Optional[int]) -> None:
    command_parts = ["spotlight_filter"]
    if selection.min_score is not None:
        command_parts.extend(["--min-score", f"{selection.min_score:g}"])
    if selection.attack_vector is not None and selection.attack_vector != "Unknown":
        command_parts.extend(["--attack-vector", f'"{selection.attack_vector}"'])
    if selection.attack_complexity is not None and selection.attack_complexity != "Unknown":
        command_parts.extend(["--attack-complexity", selection.attack_complexity])
    if limit is not None:
        command_parts.extend(["--limit", str(limit)])

    print()
    print("Equivalent command:")
    print(" ".join(command_parts))


def print_results_header() -> None:
    print()
    print("Here are the results:")
    print()


class Spinner:
    def __init__(self, message: str) -> None:
        self.message = message
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "Spinner":
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, exc_tb) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r" + " " * (len(self.message) + 6) + "\r")
        sys.stdout.flush()

    def _spin(self) -> None:
        for symbol in itertools.cycle("|/-\\"):
            if not self._running:
                break
            sys.stdout.write(f"\r{self.message} {symbol}")
            sys.stdout.flush()
            time.sleep(0.1)


def print_table(items: List[NormalizedVuln]) -> None:
    if not items:
        print("No vulnerabilities found for the provided filters.")
        return

    headers = ["CVE", "Host", "Score", "Attack Vector", "Attack Complexity"]
    rows = [
        [
            v.cve_id,
            v.host or "-",
            f"{v.score:.1f}" if v.score is not None else "-",
            v.attack_vector or "-",
            v.attack_complexity or "-",
        ]
        for v in items
    ]

    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(str(cell)))

    def fmt_row(row_values: List[str]) -> str:
        return " | ".join(str(value).ljust(widths[idx]) for idx, value in enumerate(row_values))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(fmt_row([str(c) for c in row]))


def print_json(items: List[NormalizedVuln]) -> None:
    payload = [
        {
            "cve": v.cve_id,
            "host": v.host,
            "aid": v.aid,
            "score": v.score,
            "severity": v.severity,
            "attack_vector": v.attack_vector,
            "attack_complexity": v.attack_complexity,
            "cvss_vector": v.vector_raw,
        }
        for v in items
    ]
    print(json.dumps(payload, indent=2))


def _value_or_unknown(value: Optional[str]) -> str:
    return value if value else "Unknown"


def _cvss_score_bucket(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical (9.0-10.0)"
    if score >= 7.0:
        return "High (7.0-8.9)"
    if score >= 4.0:
        return "Medium (4.0-6.9)"
    if score > 0:
        return "Low (0.1-3.9)"
    return "None (0.0)"


def summarize_cvss_buckets(items: List[NormalizedVuln]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in items:
        counts[_cvss_score_bucket(item.score)] += 1
    return counts


def summarize_categories(items: List[NormalizedVuln]) -> Dict[str, Counter[str]]:
    summary: Dict[str, Counter[str]] = {
        "attack_vector": Counter(),
        "attack_complexity": Counter(),
    }

    for item in items:
        summary["attack_vector"][_value_or_unknown(item.attack_vector)] += 1
        summary["attack_complexity"][_value_or_unknown(item.attack_complexity)] += 1

    return summary


def print_summary(items: List[NormalizedVuln]) -> None:
    if not items:
        return

    summary = summarize_categories(items)
    score_summary = summarize_cvss_buckets(items)

    print()
    print("Observed category counts")
    print("Attack Vector:")
    for label, count in sorted(summary["attack_vector"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  - {label}: {count}")

    print("Attack Complexity:")
    for label, count in sorted(summary["attack_complexity"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  - {label}: {count}")

    print("CVSS Score Buckets:")
    for label, count in sorted(score_summary.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  - {label}: {count}")


def export_csv(items: List[NormalizedVuln], output_path: str, include_summary_row: bool = False) -> None:
    summary = summarize_categories(items)
    score_summary = summarize_cvss_buckets(items)
    distinct_vectors = len(summary["attack_vector"])
    distinct_complexities = len(summary["attack_complexity"])

    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "cve",
            "host",
            "aid",
            "score",
            "severity",
            "cvss_score_bucket",
            "attack_vector",
            "attack_complexity",
            "cvss_vector",
        ])

        if include_summary_row:
            writer.writerow([
                "__SUMMARY__",
                f"total_rows={len(items)}",
                "",
                "",
                "",
                "",
                "",
                f"distinct_vectors={distinct_vectors}",
                f"distinct_complexities={distinct_complexities}",
                "; ".join([f"{k}:{v}" for k, v in sorted(score_summary.items(), key=lambda kv: (-kv[1], kv[0]))]),
            ])

        for item in items:
            writer.writerow([
                item.cve_id,
                item.host,
                item.aid,
                item.score,
                item.severity,
                _cvss_score_bucket(item.score),
                item.attack_vector,
                item.attack_complexity,
                item.vector_raw,
            ])


def export_html(items: List[NormalizedVuln], output_path: str) -> None:
    summary = summarize_categories(items)
    score_summary = summarize_cvss_buckets(items)

    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(item.cve_id)}</td>"
        f"<td>{html.escape(item.host or '')}</td>"
        f"<td>{html.escape(f'{item.score:.1f}' if item.score is not None else '-')}</td>"
        f"<td>{html.escape(_cvss_score_bucket(item.score))}</td>"
        f"<td>{html.escape(item.attack_vector or 'Unknown')}</td>"
        f"<td>{html.escape(item.attack_complexity or 'Unknown')}</td>"
        "</tr>"
        for item in items
    )

    av_items = "\n".join(
        f"<li>{html.escape(label)}: {count}</li>"
        for label, count in sorted(summary["attack_vector"].items(), key=lambda kv: (-kv[1], kv[0]))
    )
    ac_items = "\n".join(
        f"<li>{html.escape(label)}: {count}</li>"
        for label, count in sorted(summary["attack_complexity"].items(), key=lambda kv: (-kv[1], kv[0]))
    )
    score_items = "\n".join(
        f"<li>{html.escape(label)}: {count}</li>"
        for label, count in sorted(score_summary.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    html_doc = f"""<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>CrowdStrike Spotlight Filter Report</title>
    <style>
        :root {{
            --bg: #f7f6f3;
            --panel: #ffffff;
            --text: #1b2630;
            --accent: #0d6e6e;
            --line: #d9e1e4;
        }}
        body {{
            margin: 0;
            padding: 24px;
            background: linear-gradient(140deg, #eef4f6, var(--bg));
            color: var(--text);
            font-family: Georgia, \"Times New Roman\", serif;
        }}
        .wrap {{ max-width: 1200px; margin: 0 auto; }}
        .card {{
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 16px;
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.06);
        }}
        h1, h2 {{ margin: 0 0 12px; }}
        h1 {{ color: var(--accent); }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th, td {{ border-bottom: 1px solid var(--line); text-align: left; padding: 8px; }}
        th {{ background: #f0f5f6; }}
    </style>
</head>
<body>
    <div class=\"wrap\">
        <div class=\"card\">
            <h1>CrowdStrike Spotlight Filter Report</h1>
            <p>This is not an official CrowdStrike tool.</p>
            <p>Version: {TOOL_VERSION} | Build date: {BUILD_DATE}</p>
            <p>Total rows: {len(items)}</p>
        </div>
        <div class=\"card\">
            <h2>Observed CVSS Score Buckets</h2>
            <ul>{score_items or '<li>No data</li>'}</ul>
            <h2>Observed Attack Vector Counts</h2>
            <ul>{av_items or '<li>No data</li>'}</ul>
            <h2>Observed Attack Complexity Counts</h2>
            <ul>{ac_items or '<li>No data</li>'}</ul>
        </div>
        <div class=\"card\">
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>Host</th>
                        <th>Score</th>
                        <th>CVSS Bucket</th>
                        <th>Attack Vector</th>
                        <th>Attack Complexity</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_doc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spotlight_filter",
        description="Query CrowdStrike Spotlight vulnerabilities and investigate CVE attack vectors/complexity.",
    )

    parser.add_argument("--cve", help="Filter by CVE ID, e.g. CVE-2025-12345")
    parser.add_argument("--status", help="Spotlight status filter, e.g. open, closed")
    parser.add_argument("--min-score", type=float, help="Minimum CVSS base score")
    parser.add_argument(
        "--attack-vector",
        choices=["Network", "Adjacent", "Adjacent Network", "Local", "Physical", "N", "A", "L", "P"],
        help="Filter by CVSS attack vector (client-side).",
    )
    parser.add_argument(
        "--attack-complexity",
        choices=["Low", "High", "L", "H"],
        help="Filter by CVSS attack complexity (client-side).",
    )
    parser.add_argument("--limit", type=int, default=100, help="Maximum records to return")
    parser.add_argument("--sort", default="updated_timestamp.desc", help="Falcon sort expression")
    parser.add_argument("--base-url", default=None, help="Falcon API base URL (default: EU-1)")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of table")
    parser.add_argument("--interactive", action="store_true", help="Fetch data first, then interactively select CVSS score, attack vector, and attack complexity")
    parser.add_argument("--show-summary", action="store_true", help="Show observed attack vector and complexity category counts")
    parser.add_argument("--csv-out", help="Write results to CSV file")
    parser.add_argument("--csv-summary-row", action="store_true", help="Include a compact summary row at top of CSV output")
    parser.add_argument("--html-out", help="Write results to HTML file")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    clear_screen()
    print_greeting()

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        creds = load_credentials(args.base_url)
        client = FalconSpotlightClient(creds)

        filter_expression = build_filter(args, include_min_score=not args.interactive)
        query_limit = None if args.interactive else max(1, args.limit)
        with Spinner("Fetching data"):
            raw_rows = client.query_vulnerabilities(filter_expression=filter_expression, limit=query_limit, sort=args.sort)
        normalized = [to_normalized(item) for item in raw_rows]

        if args.interactive:
            filtered, selection = run_interactive_selection(normalized)
            print_equivalent_command(selection, None)
        else:
            scored = filter_by_min_score(normalized, args.min_score)
            filtered = apply_local_filters(scored, args.attack_vector, args.attack_complexity)

        if args.json:
            print_json(filtered)
        else:
            print_results_header()
            print_table(filtered)

        if args.show_summary:
            print_summary(filtered)

        if args.csv_out:
            export_csv(filtered, args.csv_out, include_summary_row=args.csv_summary_row)
            print(f"CSV exported to {args.csv_out}")

        if args.html_out:
            export_html(filtered, args.html_out)
            print(f"HTML exported to {args.html_out}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
