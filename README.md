# XSSAM — XSS Reconnaissance & Validation Automation

XSSAM is a professional-grade security tool designed for authorized bug-bounty researchers and penetration testers. It automates the entire lifecycle of XSS discovery, from initial reconnaissance and parameter extraction to context-aware payload injection and headless browser validation.

## 🚀 Features

- **Robust Async Crawler**: Recursively discovers endpoints, JS files, and forms while respecting scope and depth limits.
- **Comprehensive Parameter Engine**: Extracts parameters from Query strings, Path segments, Form bodies, HTTP Headers, and Cookies.
- **Intelligent Context Analysis**: Uses a canary-based approach to determine if a reflection occurs in HTML, Attribute, or JavaScript contexts, selecting the most effective payloads.
- **Exhaustive Payload Corpus**: Organized by context to ensure high coverage and reduced noise.
- **Browser-Based Validation**: Integrates **Playwright** to confirm actual script execution (via dialogs, console logs, or DOM mutations), eliminating false positives.
- **Professional Reporting**: Generates detailed HTML, JSON, and TXT reports including proof-of-concept URLs and evidence screenshots.

## 🛠️ Installation

### Prerequisites
- Python 3.11+
- Playwright browsers

### Setup
```bash
git clone https://github.com/your-username/XSSAM.git
cd XSSAM
pip install -r requirements.txt
playwright install chromium
```

## 💻 Usage

### Basic Scan
```bash
python -m xssam -u https://example.com --authorized
```

### Advanced Scan
```bash
python -m xssam -u https://example.com --authorized --depth 5 --threads 20 --dom --headless
```

### Options
| Option | Description |
|---|---|
| `-u, --url` | Target URL to test |
| `--authorized` | Confirm target is authorized (Required) |
| `--depth` | Maximum crawl depth |
| `--threads` | Concurrency limit |
| `--dom` | Enable DOM XSS testing |
| `--output` | Custom output directory |

## 🛡️ Responsible Use
XSSAM is intended for **authorized security testing only**. Unauthorized scanning of websites is illegal and unethical. The developers of XSSAM assume no liability for misuse of this tool.

## 🏗️ Architecture
XSSAM follows a modular pipeline:
`Target` $\rightarrow$ `Crawler` $\rightarrow$ `Parameter Extractor` $\rightarrow$ `Context Analyzer` $\rightarrow$ `XSS Scanner` $\rightarrow$ `Playwright Validator` $\rightarrow$ `Reporter`
