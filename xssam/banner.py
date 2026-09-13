from rich.console import Console
from rich.panel import Panel
from rich.text import Text

def print_banner():
    console = Console()
    banner_text = Text()

    ascii_art = r"""
██╗  ██╗███████╗███████╗ █████╗ ███╗   ███╗
╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗ ████║
 ╚███╔╝ ███████╗███████╗███████║██╔████╔██║
 ██╔██╗ ╚════██║╚════██║██╔══██║██║╚██╔╝██║
██╔╝ ██╗███████║███████║██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
    """

    banner_text.append(ascii_art, style="bold cyan")
    banner_text.append("\n                     XSSAM\n                  made by SAUMYA\n", style="bold white")

    console.print(Panel(banner_text, border_style="cyan", expand=False))
