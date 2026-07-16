from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

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
    status: str
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
        status=str(resource.get("status") or "unknown"),
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


def _prompt_choice(prompt: str, options: List[str]) -> str:
    while True:
        print(prompt)
        for idx, option in enumerate(options, start=1):
            print(f"  {idx}. {option}")

        raw = input("Select an option by number: ").strip()
        if not raw.isdigit():
            print("Invalid choice. Please enter a number.")
            continue

        selected = int(raw)
        if 1 <= selected <= len(options):
            return options[selected - 1]

        print("Choice out of range. Try again.")


def _prompt_score_filter() -> Optional[float]:
    options = [
        "Any score",
        "CVSS >= 9.0 (Critical)",
        "CVSS >= 7.0 (High+)",
        "CVSS >= 4.0 (Medium+)",
        "Custom minimum",
    ]
    selected = _prompt_choice("\nStep 1/3: Select CVSS score filter", options)

    if selected == "Any score":
        return None
    if selected == "CVSS >= 9.0 (Critical)":
        return 9.0
    if selected == "CVSS >= 7.0 (High+)":
        return 7.0
    if selected == "CVSS >= 4.0 (Medium+)":
        return 4.0

    while True:
        raw = input("Enter custom minimum CVSS score (0.0 - 10.0): ").strip()
        try:
            value = float(raw)
        except ValueError:
            print("Invalid number. Try again.")
            continue

        if 0.0 <= value <= 10.0:
            return value

        print("Score must be between 0.0 and 10.0.")


def _prompt_category_filter(step_label: str, items: List[NormalizedVuln], field_name: str) -> Optional[str]:
    counts: Counter[str] = Counter()
    for item in items:
        raw_value = getattr(item, field_name)
        counts[_value_or_unknown(raw_value)] += 1

    if not counts:
        return None

    sorted_values = [name for name, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    options = [f"Any ({len(items)})"] + [f"{value} ({counts[value]})" for value in sorted_values]
    selected = _prompt_choice(step_label, options)

    if selected.startswith("Any"):
        return None

    return selected.rsplit("(", 1)[0].strip()


def run_interactive_selection(items: List[NormalizedVuln]) -> List[NormalizedVuln]:
    print(f"\nFetched {len(items)} vulnerability records.\n")

    min_score = _prompt_score_filter()
    score_filtered = filter_by_min_score(items, min_score)
    print(f"Records after score filter: {len(score_filtered)}")

    selected_vector = _prompt_category_filter(
        "\nStep 2/3: Select attack vector",
        score_filtered,
        "attack_vector",
    )
    vector_filtered = [
        item for item in score_filtered
        if selected_vector is None or _value_or_unknown(item.attack_vector) == selected_vector
    ]
    print(f"Records after attack vector filter: {len(vector_filtered)}")

    selected_complexity = _prompt_category_filter(
        "\nStep 3/3: Select attack complexity",
        vector_filtered,
        "attack_complexity",
    )
    final_filtered = [
        item for item in vector_filtered
        if selected_complexity is None or _value_or_unknown(item.attack_complexity) == selected_complexity
    ]
    print(f"Records after attack complexity filter: {len(final_filtered)}")

    return final_filtered


def print_table(items: List[NormalizedVuln]) -> None:
    if not items:
        print("No vulnerabilities found for the provided filters.")
        return

    headers = ["CVE", "Host", "Status", "Score", "Attack Vector", "Attack Complexity"]
    rows = [
        [
            v.cve_id,
            v.host or "-",
            v.status,
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
            "status": v.status,
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

    print()
    print("Observed category counts")
    print("Attack Vector:")
    for label, count in sorted(summary["attack_vector"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  - {label}: {count}")

    print("Attack Complexity:")
    for label, count in sorted(summary["attack_complexity"].items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  - {label}: {count}")


def export_csv(items: List[NormalizedVuln], output_path: str, include_summary_row: bool = False) -> None:
    summary = summarize_categories(items)
    distinct_vectors = len(summary["attack_vector"])
    distinct_complexities = len(summary["attack_complexity"])

    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "cve",
            "host",
            "aid",
            "status",
            "score",
            "severity",
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
                f"distinct_vectors={distinct_vectors}",
                f"distinct_complexities={distinct_complexities}",
                "",
            ])

        for item in items:
            writer.writerow([
                item.cve_id,
                item.host,
                item.aid,
                item.status,
                item.score,
                item.severity,
                item.attack_vector,
                item.attack_complexity,
                item.vector_raw,
            ])


def export_html(items: List[NormalizedVuln], output_path: str) -> None:
    summary = summarize_categories(items)

    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(item.cve_id)}</td>"
        f"<td>{html.escape(item.host or '')}</td>"
        f"<td>{html.escape(item.status)}</td>"
        f"<td>{html.escape(f'{item.score:.1f}' if item.score is not None else '-')}</td>"
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

    html_doc = f"""<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Falcon CVE Report</title>
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
            <h1>Falcon CVE Report</h1>
            <p>Total rows: {len(items)}</p>
        </div>
        <div class=\"card\">
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
                        <th>Status</th>
                        <th>Score</th>
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
        prog="falcon-cve",
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


def load_credentials(base_url_from_args: Optional[str]) -> FalconCredentials:
    load_dotenv()

    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    base_url = base_url_from_args or os.getenv("FALCON_BASE_URL") or DEFAULT_BASE_URL

    if not client_id or not client_secret:
        raise RuntimeError(
            "Missing credentials. Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in env or .env file."
        )

    return FalconCredentials(client_id=client_id, client_secret=client_secret, base_url=base_url)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        creds = load_credentials(args.base_url)
        client = FalconSpotlightClient(creds)

        filter_expression = build_filter(args, include_min_score=not args.interactive)
        query_limit = None if args.interactive else max(1, args.limit)
        raw_rows = client.query_vulnerabilities(filter_expression=filter_expression, limit=query_limit, sort=args.sort)
        normalized = [to_normalized(item) for item in raw_rows]

        if args.interactive:
            filtered = run_interactive_selection(normalized)
        else:
            scored = filter_by_min_score(normalized, args.min_score)
            filtered = apply_local_filters(scored, args.attack_vector, args.attack_complexity)

        if args.json:
            print_json(filtered)
        else:
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
