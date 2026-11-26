from __future__ import annotations

import argparse
import sys
import traceback
from collections.abc import Sequence
from urllib.parse import urlsplit

from pydantic import ValidationError

from xssam import __version__
from xssam.banner import print_banner
from xssam.config import load_config
from xssam.crawler.url_normalizer import normalize_url
from xssam.logging import ScanLogger


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def positive_int(value: str) -> int:
    parsed = non_negative_int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def positive_float(value: str) -> float:
    parsed = non_negative_float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def target_url(value: str) -> str:
    candidate = value.strip()
    if not normalize_url(candidate):
        raise argparse.ArgumentTypeError(
            "must be an absolute http:// or https:// URL with a valid host"
        )
    try:
        # Accessing .port raises ValueError for malformed port values.
        _port = urlsplit(candidate).port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("contains an invalid port") from exc
    return candidate


def _preparse_config(argv: Sequence[str]) -> str | None:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--config")
    known, _ = parser.parse_known_args(argv)
    return known.config


def build_parser(settings, config_path: str | None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xssam",
        description="XSSAM - XSS Reconnaissance & Validation Automation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target = parser.add_argument_group("Target and scope")
    target.add_argument(
        "-u", "--url", required=True, type=target_url, help="Target URL to test"
    )
    target.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you are authorized to test this target (required)",
    )
    target.add_argument(
        "--scope", help="Additional in-scope domains, comma-separated"
    )
    target.add_argument(
        "--scope-file", help="File containing one domain or URL per line"
    )

    crawl = parser.add_argument_group("Crawler and performance")
    crawl.add_argument(
        "--depth",
        type=non_negative_int,
        default=settings.crawler.max_depth,
        help="Maximum crawl depth",
    )
    crawl.add_argument(
        "--max-urls",
        type=positive_int,
        default=settings.crawler.max_urls,
        help="Maximum URLs to visit",
    )
    crawl.add_argument(
        "--max-requests",
        type=non_negative_int,
        default=settings.crawler.max_requests,
        help="Maximum HTTP requests; 0 means unlimited",
    )
    crawl.add_argument(
        "--threads",
        type=positive_int,
        default=settings.performance.threads,
        help="Concurrent request limit",
    )
    crawl.add_argument(
        "--delay",
        type=non_negative_float,
        default=settings.performance.delay,
        help="Minimum delay between request starts, in seconds",
    )
    crawl.add_argument(
        "--timeout",
        type=positive_float,
        default=settings.performance.timeout,
        help="HTTP timeout in seconds",
    )

    session = parser.add_argument_group("Session")
    session.add_argument("--cookies", help="Cookies: name=value;name2=value2")
    session.add_argument(
        "--headers", help="Legacy comma-separated headers: Name:Value,Name2:Value2"
    )
    session.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra header; repeat for multiple headers (commas are preserved)",
    )
    session.add_argument("--user-agent", help="Custom User-Agent")

    modes = parser.add_argument_group("Scan modes")
    modes.add_argument(
        "--crawl",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Crawl links and forms (--no-crawl scans only the target URL)",
    )
    modes.add_argument(
        "--scan",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run the XSS scanner",
    )
    modes.add_argument(
        "--reflected",
        action=argparse.BooleanOptionalAction,
        default=settings.scanner.reflected,
        help="Test reflected parameters",
    )
    modes.add_argument(
        "--stored",
        action=argparse.BooleanOptionalAction,
        default=settings.scanner.stored,
        help="Reserved compatibility flag; stored checks are not implemented",
    )
    modes.add_argument(
        "--dom",
        action=argparse.BooleanOptionalAction,
        default=settings.scanner.dom,
        help="Probe obvious DOM sinks using URL fragments (requires --browser)",
    )
    modes.add_argument(
        "--browser",
        action=argparse.BooleanOptionalAction,
        default=settings.browser.enabled,
        help="Confirm findings with Playwright Chromium",
    )
    modes.add_argument(
        "--headless",
        action=argparse.BooleanOptionalAction,
        default=settings.browser.headless,
        help="Run Chromium headlessly",
    )

    output = parser.add_argument_group("Output")
    output.add_argument(
        "-o", "--output", default=None, help="Output directory (default: output)"
    )
    output.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=settings.reporting.json_report,
        help="Generate report.json",
    )
    output.add_argument(
        "--html",
        action=argparse.BooleanOptionalAction,
        default=settings.reporting.html,
        help="Generate report.html",
    )
    output.add_argument(
        "--txt",
        action=argparse.BooleanOptionalAction,
        default=settings.reporting.txt,
        help="Generate report.txt",
    )
    output.add_argument("--config", default=config_path, help="YAML configuration file")
    verbosity = output.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="Show debug details")
    verbosity.add_argument("--quiet", action="store_true", help="Suppress progress output")

    parser.add_argument("--version", action="version", version=f"XSSAM {__version__}")
    return parser


def apply_settings(args: argparse.Namespace, settings, logger: ScanLogger) -> None:
    try:
        settings.crawler.max_depth = 0 if not args.crawl else args.depth
        settings.crawler.max_urls = 1 if not args.crawl else args.max_urls
        settings.crawler.max_requests = args.max_requests
        settings.performance.threads = args.threads
        settings.performance.delay = args.delay
        settings.performance.timeout = args.timeout

        if args.scope is not None:
            settings.scope.allowed_domains = [
                item.strip() for item in args.scope.split(",") if item.strip()
            ]
        if args.scope_file is not None:
            settings.scope.scope_file = args.scope_file

        # ``--scan`` is the master switch; feature flags refine it.
        settings.scanner.reflected = args.scan and args.reflected
        settings.scanner.stored = args.scan and args.stored
        settings.scanner.dom = args.scan and args.dom
        settings.browser.enabled = args.scan and args.browser
        settings.browser.headless = args.headless

        settings.reporting.json_report = args.json
        settings.reporting.html = args.html
        settings.reporting.txt = args.txt
    except ValidationError as exc:
        raise ValueError(f"Invalid command-line setting:\n{exc}") from exc

    if args.stored:
        logger.warning(
            "Stored XSS scanning is not implemented because it can change server "
            "state. --stored is accepted for compatibility but ignored."
        )
    if args.dom and not settings.browser.enabled:
        logger.warning(
            "DOM sink probing requires browser validation; pass --browser to enable it."
        )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    config_path = _preparse_config(arguments)
    try:
        settings = load_config(config_path)
    except (OSError, ValueError) as exc:
        print(f"[!] Configuration error: {exc}", file=sys.stderr)
        return 2

    parser = build_parser(settings, config_path)
    args = parser.parse_args(arguments)
    logger = ScanLogger(verbose=args.verbose, quiet=args.quiet)

    if not args.authorized:
        logger.error(
            "\n[!] ERROR: --authorized is required. Only test systems you own "
            "or have explicit written permission to assess."
        )
        return 2

    try:
        apply_settings(args, settings, logger)
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    if not args.quiet:
        print_banner(logger.console)

    # Imported after argument parsing so --help/--version stay lightweight.
    from xssam.core.engine import XSSAMEngine

    try:
        engine = XSSAMEngine(args, settings, logger)
    except (OSError, ValueError) as exc:
        logger.error(f"Could not initialize scan: {exc}")
        return 2

    try:
        engine.run()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted; generating a partial report...")
        try:
            engine.generate_reports()
        except Exception as exc:
            logger.error(f"Could not generate partial report: {exc}")
        return 130
    except Exception as exc:
        logger.error(f"Scan failed: {exc}")
        if args.verbose:
            logger.error(traceback.format_exc())
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
