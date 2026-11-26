from __future__ import annotations

from rich.console import Console
from rich.markup import escape


class ScanLogger:
    """Small, markup-safe wrapper around Rich's console."""

    def __init__(
        self,
        console: Console | None = None,
        *,
        verbose: bool = False,
        quiet: bool = False,
    ) -> None:
        self.console = console or Console()
        self.verbose = verbose
        self.quiet = quiet

    def _write(self, message: object, style: str | None = None, *, force: bool = False) -> None:
        if self.quiet and not force:
            return
        text = escape(str(message))
        if style:
            self.console.print(text, style=style)
        else:
            self.console.print(text)

    def info(self, message: object) -> None:
        self._write(message)

    def success(self, message: object) -> None:
        self._write(message, "bold green")

    def warning(self, message: object) -> None:
        self._write(message, "bold yellow", force=True)

    def error(self, message: object) -> None:
        self._write(message, "bold red", force=True)

    def debug(self, message: object) -> None:
        if self.verbose and not self.quiet:
            self._write(message, "dim")
