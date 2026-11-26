# XSSAM — XSS Reconnaissance & Validation Automation

XSSAM is an **authorized-testing-only** tool for discovering likely reflected XSS, generating proof-of-concept requests, optionally confirming execution in headless Chromium, and producing JSON, TXT, and HTML reports.

> Only scan systems you own or have explicit written permission to test. The CLI requires `--authorized` for every scan.

## What works

- Bounded asynchronous crawler with same-origin scope enforcement, depth/URL/request limits, and rate limiting.
- Parameter discovery from query strings, dynamic path segments, fragments, and GET/POST forms.
- Canary-based HTML, attribute, and JavaScript context classification.
- Context-specific payloads with a unique per-scan marker.
- Playwright validation that confirms only marker-specific execution; findings are otherwise `POTENTIAL`.
- Optional, experimental DOM sink probing through URL fragments when `--dom --browser` is used.
- JSON, TXT, and escaped HTML reports with POC URLs, request methods, bodies, and screenshot paths.
- Graceful fallback when Chromium is not installed: the scan still runs and reports unconfirmed findings.

### Current limitations

- Stored XSS is **not implemented**: `--stored` is accepted for compatibility, but deliberately ignored because POST-based stored checks can modify server state.
- DOM checks are a heuristic fragment probe, not a full taint-analysis engine.
- `POTENTIAL` means raw reflection was observed; it is **not proof of exploitability**. Use `--browser` and manual review.

## Installation on Kali Linux / Debian

Kali may enforce PEP 668 (`externally-managed-environment`). Use a virtual environment instead of installing into the system Python:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/clipsncore911/XSSAM.git
cd XSSAM
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Browser confirmation is optional. To enable it, install Chromium once:

```bash
python -m playwright install chromium
# If system libraries are missing on Kali:
sudo python -m playwright install-deps chromium
```

If you do not want a browser, no Chromium installation is needed; simply use `--no-browser` (the default).

For development/test dependencies:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## Quick local demo

Start the intentionally vulnerable local app in one terminal:

```bash
source .venv/bin/activate
python tests/vulnerable_app/app.py
```

Scan it from another terminal:

```bash
source .venv/bin/activate
python -m xssam -u 'http://127.0.0.1:5000/search?q=hello' \
  --authorized --no-crawl --no-browser --delay 0 \
  --output demo-output
```

Open `demo-output/report.html`, or inspect `report.json` and `report.txt`. To confirm execution with a browser:

```bash
python -m xssam -u 'http://127.0.0.1:5000/search?q=hello' \
  --authorized --no-crawl --browser --headless \
  --delay 0 --output demo-output
```

Confirmed findings are marked `CONFIRMED`; screenshots are stored under the output directory's `screenshots/` folder.

## Usage

```bash
xssam -u https://example.com/search?q=test --authorized
python -m xssam -u https://example.com/ --authorized --depth 2 --threads 5
python -m xssam -u https://example.com/ --authorized --browser --dom --headless
```

Important options:

| Option | Description |
|---|---|
| `-u, --url` | Absolute `http://` or `https://` target URL |
| `--authorized` | Required acknowledgement of authorization |
| `--scope a.com,b.com` | Extend the allowlist; the target origin is always included |
| `--scope-file FILE` | One domain/URL per line; `#` comments are allowed |
| `--depth`, `--max-urls`, `--max-requests` | Crawl and request budgets (`0` requests means unlimited) |
| `--threads`, `--delay`, `--timeout` | Concurrency, minimum inter-request delay, and HTTP timeout |
| `--cookies`, `--header`, `--headers`, `--user-agent` | Session customization; repeat `--header` for multiple headers |
| `--crawl/--no-crawl` | Crawl links/forms or test only the supplied URL |
| `--scan/--no-scan`, `--reflected/--no-reflected` | Master and reflected-XSS switches |
| `--browser/--no-browser`, `--headless/--no-headless` | Playwright validation switches |
| `--dom/--no-dom` | Experimental fragment-based DOM sink probe (requires `--browser`) |
| `-o, --output` | Report directory (default: `output/`) |
| `--json/--no-json`, `--html/--no-html`, `--txt/--no-txt` | Select report formats |
| `--config FILE` | Custom YAML config; `XSSAM_CONFIG` also works |
| `--verbose`, `--quiet` | Debug details or minimal output |

Run `python -m xssam --help` for the full list.

## Scope and configuration

By default, crawling is restricted to the exact target host and effective port. `example.com` does not implicitly authorize `evil-example.com`, subdomains, or another port. Set `scope.subdomain_scope: true` or use `--scope` / `--scope-file` to widen it deliberately.

`config/default.yaml` is the editable config when running from the repository. A packaged copy is used when XSSAM is installed and launched from another directory, so templates, payload YAML, and defaults no longer depend on the current working directory.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `error: externally-managed-environment` | Create and activate `.venv`, then `pip install -e .` |
| `Multiple top-level packages discovered in a flat-layout` | Update to this revision; `pyproject.toml` now selects only `xssam*` packages |
| `ModuleNotFoundError: No module named ...` | Activate `.venv` and reinstall with `pip install -e .` |
| `Executable doesn't exist ... chromium` | Run `python -m playwright install chromium`, or add `--no-browser` |
| Playwright cannot start as root / missing libraries | Run `sudo python -m playwright install-deps chromium`, or use `--no-browser` |
| No `CONFIRMED` findings | Browser validation is disabled by default; use `--browser` and verify manually |
| Reports are empty | Check `--verbose`, target reachability, request budget, and `--scope` |

## Responsible use

XSSAM is intended for authorized security testing only. Unauthorized scanning is illegal and unethical. The authors assume no liability for misuse.
