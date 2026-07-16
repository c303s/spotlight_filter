# CrowdStrike Spotlight Filter

Python CLI built on FalconPy to query CrowdStrike Spotlight vulnerabilities and investigate CVE attack vectors and attack complexity.

## What it does

- Authenticates to CrowdStrike Falcon using API client credentials.
- Queries Spotlight vulnerabilities with Falcon-side filters (CVE, status, min score).
- Parses CVSS vector data to classify:
  - Attack Vector: Network, Adjacent Network, Local, Physical
  - Attack Complexity: Low, High
- Clears the terminal on startup and displays a banner with version/build date.
- Guides credential onboarding from `.env` and validates credentials before querying.
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

The `spotlight_filter` command is created when you run `pip install -e .` (or `pip install .`) in the active environment.

### Run from local source (this repository)

```bash
source .venv/bin/activate
pip install -e .
spotlight_filter --interactive
```

If command lookup fails in your shell, run with module form from this repo:

```bash
source .venv/bin/activate
PYTHONPATH=src python -m cs_cve_tool.cli --interactive
```

If credentials are missing, the tool asks for them and saves them into `.env`.
If credentials already exist, the tool asks whether to update them (default: No).
It validates credentials before continuing.

## Windows Quick Start

1. Install Python 3.10+ from python.org (check "Add Python to PATH").
2. Open PowerShell.
3. Install pipx and the tool:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
# Close and reopen PowerShell after ensurepath
pipx install spotlight-filter
```

4. Run the tool:

```powershell
spotlight_filter --interactive
```

If command discovery is delayed on PATH, run:

```powershell
$env:PYTHONPATH="src"
py -m cs_cve_tool.cli --interactive
```

## Usage

### Basic query

```bash
spotlight_filter --limit 50
```

### Search a specific CVE

```bash
spotlight_filter --cve CVE-2025-12345 --limit 100
```

### Hunt remote, low-complexity vulnerabilities

```bash
spotlight_filter --attack-vector Network --attack-complexity Low --min-score 7.0 --limit 200
```

You can also use short aliases in filters:
- Attack vector: `N`, `A`, `L`, `P`
- Attack complexity: `L`, `H`

### Show observed category counts

```bash
spotlight_filter --show-summary --limit 200
```

### Interactive selection flow

Fetches data up front, then prompts in this order:
1. CVSS score
2. Attack vector
3. Attack complexity

```bash
spotlight_filter --interactive
```

### JSON output

```bash
spotlight_filter --status open --json
```

### Export CSV and HTML

```bash
spotlight_filter --status open --show-summary --csv-out report.csv --html-out report.html
```

### Add compact summary row to CSV

```bash
spotlight_filter --status open --csv-out report.csv --csv-summary-row
```

### Optional base URL override (EU-1 is default)

```bash
spotlight_filter --base-url https://api.eu-1.crowdstrike.com
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

## Easy Install For Other People

### Fastest start (one command after PyPI release)

```bash
pipx install spotlight-filter
```

### Install pipx if needed

Install with `pipx` directly from Python and then run:

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
exec "$SHELL" -l
```

Then install the tool:

```bash
pipx install spotlight-filter
spotlight_filter --help
```

### Minimal fallback (plain pip)

```bash
python3 -m pip install --user spotlight-filter
```

If `spotlight_filter` is not found in your shell after pip install, run it with:

```bash
python3 -m spotlight_filter --help
```
