import argparse
import sys
from xssam.banner import print_banner
from xssam.config import settings
from xssam.core.engine import XSSAMEngine

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="XSSAM - XSS Reconnaissance & Validation Automation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Target and Scope
    parser.add_argument("-u", "--url", required=True, help="Target URL to test")
    parser.add_argument("--authorized", action="store_true", help="Confirm target is authorized for testing")
    parser.add_argument("--scope", help="Domain allowlist (comma-separated)")
    parser.add_argument("--scope-file", help="Path to scope file")

    # Crawler Settings
    parser.add_argument("--depth", type=int, help="Maximum crawl depth")
    parser.add_argument("--max-urls", type=int, help="Maximum URLs to crawl")
    parser.add_argument("--threads", type=int, help="Number of concurrent threads")
    parser.add_argument("--delay", type=float, help="Request delay in seconds")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")

    # Session/Headers
    parser.add_argument("--cookies", help="Custom cookies (cookie1=val1;cookie2=val2)")
    parser.add_argument("--headers", help="Custom headers (Header1:Val1,Header2:Val2)")
    parser.add_argument("--user-agent", help="Custom User-Agent string")

    # Scan Modes
    parser.add_argument("--crawl", action="store_true", default=True, help="Perform website crawling")
    parser.add_argument("--scan", action="store_true", default=True, help="Perform XSS scanning")
    parser.add_argument("--reflected", action="store_true", default=True, help="Test for reflected XSS")
    parser.add_argument("--stored", action="store_true", help="Test for stored XSS")
    parser.add_argument("--dom", action="store_true", help="Test for DOM XSS")
    parser.add_argument("--headless", action="store_true", default=True, help="Run browser in headless mode")

    # Output Settings
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--html", action="store_true", default=True, help="Generate HTML report")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Enable quiet mode")

    parser.add_argument("--version", action="version", version="XSSAM 0.1.0")

    args = parser.parse_args()

    if not args.authorized:
        print("\n[!] ERROR: You must use the --authorized flag to confirm this target is within scope.")
        sys.exit(1)

    # Update settings from CLI args
    if args.depth: settings.crawler.max_depth = args.depth
    if args.max_urls: settings.crawler.max_urls = args.max_urls
    if args.threads: settings.performance.threads = args.threads
    if args.delay: settings.performance.delay = args.delay
    if args.timeout: settings.performance.timeout = args.timeout
    if args.headless: settings.browser.headless = args.headless

    # Initialize Engine
    engine = XSSAMEngine(args)

    try:
        engine.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Generating partial report...")
        engine.generate_reports()
        sys.exit(0)

if __name__ == "__main__":
    main()
