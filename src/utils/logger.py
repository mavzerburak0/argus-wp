"""
Logging and output utilities for WordPress vulnerability scanner.
"""
import sys
import logging
from typing import Optional
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support."""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def __init__(self, fmt: str, use_color: bool = True):
        """
        Initialize formatter.

        Args:
            fmt: Log format string
            use_color: Enable colored output
        """
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record):
        """Format log record with color."""
        if self.use_color:
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(
    name: str = "argus-wp",
    level: int = logging.INFO,
    use_color: bool = True,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up logger with console and optional file output.

    Args:
        name: Logger name
        level: Logging level
        use_color: Enable colored output
        log_file: Optional log file path

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    console_format = '%(message)s'
    console_formatter = ColoredFormatter(console_format, use_color=use_color)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        file_formatter = logging.Formatter(file_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


class Output:
    """
    Output helper for formatted messages.
    """

    def __init__(self, use_color: bool = True, verbose: bool = False):
        """
        Initialize output helper.

        Args:
            use_color: Enable colored output
            verbose: Enable verbose output
        """
        self.use_color = use_color
        self.verbose = verbose

    def _colorize(self, text: str, color: str) -> str:
        """
        Colorize text if color is enabled.

        Args:
            text: Text to colorize
            color: Color code

        Returns:
            Colored text
        """
        if self.use_color:
            return f"{color}{text}{Style.RESET_ALL}"
        return text

    def success(self, message: str, indent: int = 0):
        """Print success message."""
        prefix = "  " * indent
        print(self._colorize(f"{prefix}[+] {message}", Fore.GREEN))

    def info(self, message: str, indent: int = 0):
        """Print info message."""
        prefix = "  " * indent
        print(self._colorize(f"{prefix}[*] {message}", Fore.BLUE))

    def warning(self, message: str, indent: int = 0):
        """Print warning message."""
        prefix = "  " * indent
        print(self._colorize(f"{prefix}[!] {message}", Fore.YELLOW))

    def error(self, message: str, indent: int = 0):
        """Print error message."""
        prefix = "  " * indent
        print(self._colorize(f"{prefix}[-] {message}", Fore.RED))

    def critical(self, message: str, indent: int = 0):
        """Print critical message."""
        prefix = "  " * indent
        print(self._colorize(f"{prefix}[!!!] {message}", Fore.RED + Style.BRIGHT))

    def vuln(self, message: str, severity: str = "medium", indent: int = 0):
        """
        Print vulnerability message.

        Args:
            message: Vulnerability message
            severity: Vulnerability severity (low, medium, high, critical)
            indent: Indentation level
        """
        prefix = "  " * indent
        severity_colors = {
            'low': Fore.YELLOW,
            'medium': Fore.YELLOW + Style.BRIGHT,
            'high': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT
        }
        color = severity_colors.get(severity.lower(), Fore.YELLOW)
        print(self._colorize(f"{prefix}[VULN] {message}", color))

    def debug(self, message: str):
        """Print debug message (only in verbose mode)."""
        if self.verbose:
            print(self._colorize(f"[DEBUG] {message}", Fore.CYAN))

    def banner(self):
        """Print application banner."""
        banner = f"""
{self._colorize('╔══════════════════════════════════════════════════════════════╗', Fore.CYAN)}
{self._colorize('║                                                              ║', Fore.CYAN)}
{self._colorize('║                   Argus-WP Scanner v1.0                      ║', Fore.CYAN + Style.BRIGHT)}
{self._colorize('║          WordPress Vulnerability Scanner & Auditor          ║', Fore.CYAN)}
{self._colorize('║                                                              ║', Fore.CYAN)}
{self._colorize('╚══════════════════════════════════════════════════════════════╝', Fore.CYAN)}
        """
        print(banner)

    def section(self, title: str):
        """
        Print section header.

        Args:
            title: Section title
        """
        line = "=" * 60
        print(f"\n{self._colorize(line, Fore.CYAN)}")
        print(self._colorize(f"{title}", Fore.CYAN + Style.BRIGHT))
        print(self._colorize(line, Fore.CYAN))

    def subsection(self, title: str):
        """
        Print subsection header.

        Args:
            title: Subsection title
        """
        print(f"\n{self._colorize(f'--- {title} ---', Fore.BLUE)}")

    def item(self, key: str, value: str, indent: int = 0):
        """
        Print key-value item.

        Args:
            key: Item key
            value: Item value
            indent: Indentation level
        """
        spaces = "  " * indent
        print(f"{spaces}{self._colorize(key + ':', Fore.WHITE)} {value}")

    def list_item(self, message: str, indent: int = 0):
        """
        Print list item.

        Args:
            message: Item message
            indent: Indentation level
        """
        spaces = "  " * indent
        print(f"{spaces}{self._colorize('•', Fore.BLUE)} {message}")

    def table_row(self, columns: list, widths: list):
        """
        Print table row.

        Args:
            columns: Column values
            widths: Column widths
        """
        row = ""
        for col, width in zip(columns, widths):
            row += str(col).ljust(width) + "  "
        print(row)

    def progress(self, message: str):
        """
        Print progress message.

        Args:
            message: Progress message
        """
        print(self._colorize(f"[~] {message}", Fore.MAGENTA), end='\r')

    def newline(self):
        """Print newline."""
        print()
