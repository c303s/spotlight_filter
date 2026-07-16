# Falcon CVE Investigation Tool

Python CLI built on FalconPy to query CrowdStrike Spotlight vulnerabilities and investigate CVE attack vectors and attack complexity.

## What it does

- Authenticates to CrowdStrike Falcon using API client credentials.
- Queries Spotlight vulnerabilities with Falcon-side filters (CVE, status, min score).
- Parses CVSS vector data to classify:
  - Attack Vector: Network, Adjacent Network, Local, Physical
  - Attack Complexity: Low, High
- Applies client-side filtering for attack vector and attack complexity.
- Shows observed category counts for attack vector and attack complexity.
- Outputs table/JSON and can export CSV and HTML reports.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Provide credentials in environment variables or a `.env` file.

### Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
```

Then edit `.env` with your real values.

## Usage

### Basic query

```bash
falcon-cve --limit 50
```

### Search a specific CVE

```bash
falcon-cve --cve CVE-2025-12345 --limit 100
```

### Hunt remote, low-complexity vulnerabilities

```bash
falcon-cve --attack-vector Network --attack-complexity Low --min-score 7.0 --limit 200
```

You can also use short aliases in filters:
- Attack vector: `N`, `A`, `L`, `P`
- Attack complexity: `L`, `H`

### Show observed category counts

```bash
falcon-cve --show-summary --limit 200
```

### Interactive selection flow

Fetches data up front, then prompts in this order:
1. CVSS score
2. Attack vector
3. Attack complexity

```bash
falcon-cve --interactive
```

### JSON output

```bash
falcon-cve --status open --json
```

### Export CSV and HTML

```bash
falcon-cve --status open --show-summary --csv-out report.csv --html-out report.html
```

### Add compact summary row to CSV

```bash
falcon-cve --status open --csv-out report.csv --csv-summary-row
```

### Optional base URL override (EU-1 is default)

```bash
falcon-cve --base-url https://api.eu-1.crowdstrike.com
```

## Notes

- The tool supports different FalconPy Spotlight method names for compatibility across versions.
- Attack vector and attack complexity are derived from CVSS vector strings when present.
- If `FALCON_BASE_URL` is not set, the tool uses `https://api.eu-1.crowdstrike.com`.
- When no Falcon-side filter is supplied, the tool defaults to `status:'open'` to satisfy Spotlight query requirements.
- If Falcon-side filtering syntax for your tenant differs, adjust `build_filter` in `src/cs_cve_tool/cli.py`.

## Install troubleshooting

- If you see "No matching distribution found for falconpy", use the official package name:
  - `crowdstrike-falconpy`
- This project is already configured with the correct dependency name in `pyproject.toml` and `requirements.txt`.

## Share On GitHub

For step-by-step publishing and release automation, see `PUBLISHING.md`.

This repository includes a GitHub Actions workflow at `.github/workflows/release.yml`.
When you push a tag like `v0.1.0`, it automatically builds package artifacts and creates a GitHub Release.

This repository also includes `.github/workflows/pypi-publish.yml`.
After PyPI trusted publishing is configured once, each tag push (for example `v0.1.0`) also publishes to PyPI.

## Easy Install For Other People

### Fastest start (one command after PyPI release)

```bash
pipx install falcon-cve-tool
```

### Install pipx if needed (no Brew)

Install with `pipx` directly from Python and then run:

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
exec "$SHELL" -l
```

Then install the tool:

```bash
pipx install falcon-cve-tool
falcon-cve --help
```

### Minimal fallback (plain pip)

```bash
python3 -m pip install --user falcon-cve-tool
```

If `falcon-cve` is not found in your shell after pip install, run it with:

```bash
python3 -m cs_cve_tool.cli --help
```
