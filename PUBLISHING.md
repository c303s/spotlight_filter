# Publishing And Distribution Guide

This project is ready for GitHub releases and PyPI publishing.

## 1) Create the GitHub repository

1. Create a new repository on GitHub (for example: `falcon-cve-tool`).
2. Push your local project:

```bash
git init
git add .
git commit -m "Initial release"
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USER>/<YOUR_REPO>.git
git push -u origin main
```

## 2) Configure PyPI trusted publishing (one-time setup)

Before the first PyPI publish, configure a trusted publisher on PyPI.

1. Create the package on PyPI (or reserve the name) if needed.
2. In PyPI project settings, add a Trusted Publisher with:
	- Owner: `<YOUR_GITHUB_USER_OR_ORG>`
	- Repository: `<YOUR_REPO>`
	- Workflow name: `pypi-publish.yml`
	- Environment name: `pypi`
3. Save.

This repository already contains `.github/workflows/pypi-publish.yml` using OpenID Connect (no API token needed).

If `falcon-cve-tool` is already taken on PyPI, change `project.name` in `pyproject.toml` before the first release.

## 3) Create a release tag

Every push of a tag like `v0.1.0` triggers both:
- `.github/workflows/release.yml` to create a GitHub Release
- `.github/workflows/pypi-publish.yml` to publish the package to PyPI

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflows build:
- Source distribution (`.tar.gz`)
- Wheel (`.whl`)
- `sha256sums.txt`

And publish them (GitHub Release + PyPI).

## 4) Easy install methods for other users

### Option A: One command from PyPI

```bash
pipx install falcon-cve-tool
```

### Option B: Install pipx first (if needed, no Brew)

Install pipx and ensure PATH is set (no Brew required):

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
exec "$SHELL" -l
```

Install your tool from PyPI:

```bash
pipx install falcon-cve-tool
```

Then run:

```bash
falcon-cve --help
```

### Option C: Plain pip from PyPI

```bash
python3 -m pip install --user falcon-cve-tool
```

If the `falcon-cve` command is not available on PATH, run:

```bash
python3 -m cs_cve_tool.cli --help
```

## 5) Credential setup for end users

Users must define:
- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- Optional: `FALCON_BASE_URL` (default in this project is EU-1)

Example:

```bash
export FALCON_CLIENT_ID="..."
export FALCON_CLIENT_SECRET="..."
export FALCON_BASE_URL="https://api.eu-1.crowdstrike.com"
```

## 6) Subsequent releases

1. Update version in `pyproject.toml`.
2. Commit changes.
3. Tag and push:

```bash
git tag v0.1.1
git push origin v0.1.1
```
