#!/usr/bin/env python3
"""
PDF Password Cracker Tool
=========================
A Python-based tool to recover passwords from encrypted PDF files.
Uses multiple attack strategies like dictionary, brute-force, hybrid, and rule-based attacks.

Author: phantom16
Date: January 2026

Requirements:
    pip install pikepdf rich
"""

__version__ = "1.0.0"
__author__ = "phantom16"

# --- Standard library imports ---
import sys
import os
import time
import json
import signal
import logging
import argparse
import threading
from itertools import product
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Third-party imports ---
import pikepdf

# Try importing rich for better terminal output
# If not installed, the tool will still work with plain text output
try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ===========================
# Configuration / Constants
# ===========================

# ASCII art banner displayed when the tool runs
BANNER = r"""
  ____  ____  _____    ____                _
 |  _ \|  _ \|  ___|  / ___|_ __ __ _  ___| | _____ _ __
 | |_) | | | | |_    | |   | '__/ _` |/ __| |/ / _ \ '__|
 |  __/| |_| |  _|   | |___| | | (_| | (__|   <  __/ |
 |_|   |____/|_|      \____|_|  \__,_|\___|_|\_\___|_|
"""

# Default characters used in brute-force mode
DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"

# How many passwords to submit to the thread pool at once
# This prevents loading millions of passwords into memory
BATCH_SIZE = 1000

# Format for log messages
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


# ===========================
# Logging Setup
# ===========================

logger = logging.getLogger("pdfcracker")


def setup_logging(verbose=False, log_file=None):
    """
    Configure logging for the application.
    - verbose: if True, show debug-level messages
    - log_file: optional file path to save logs
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Console output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt="%H:%M:%S"))
    logger.addHandler(console_handler)

    # File output (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(file_handler)


# ===========================
# Display Helpers
# ===========================

# Create a Rich console object if the library is available
console = Console() if RICH_AVAILABLE else None


def display(msg, style=""):
    """Print a message using Rich if available, otherwise plain print."""
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


def show_banner():
    """Display the tool's ASCII banner at startup."""
    if console:
        console.print(Panel(Text(BANNER, style="bold cyan"), subtitle=f"v{__version__}"))
    else:
        print(BANNER)
        print(f"  v{__version__}\n")


# ===========================
# Progress Bar Helper
# ===========================

def create_progress_bar(total=None):
    """
    Create a Rich progress bar to show cracking progress.
    Returns None if Rich is not installed.
    """
    if not RICH_AVAILABLE:
        return None

    columns = [
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
    ]
    if total:
        columns.append(MofNCompleteColumn())
    columns += [
        TextColumn("[green]{task.fields[speed]}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ]
    return Progress(*columns, console=console, transient=False)


# ===========================
# Wordlist Utility Functions
# ===========================

def count_lines(filepath):
    """Count lines in a file without loading it entirely into memory."""
    count = 0
    with open(filepath, "rb") as f:
        for _ in f:
            count += 1
    return count


def read_wordlist(filepath):
    """
    Generator that reads a wordlist file line by line.
    This avoids loading the entire file into memory which is important
    for large wordlists like rockyou.txt (14+ million passwords).
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word:
                yield word


# ===========================
# Main PDFCracker Class
# ===========================

class PDFCracker:
    """
    Main class that handles PDF password cracking.

    It supports 4 attack modes:
    1. Dictionary - tries passwords from a wordlist file
    2. Brute-force - tries all possible character combinations
    3. Hybrid - combines prefixes/suffixes with dictionary words
    4. Rules - applies common password mutations to dictionary words

    Uses multithreading to test multiple passwords in parallel.
    """

    def __init__(self, pdf_path, threads=8, output=None):
        """
        Initialize the cracker with the target PDF.

        Args:
            pdf_path: path to the encrypted PDF file
            threads: number of worker threads for parallel testing
            output: optional path for the decrypted output PDF
        """
        self.pdf_path = pdf_path
        self.threads = threads
        self.output = output

        # Track cracking state
        self.found_password = None
        self.stop_event = threading.Event()  # used to signal all threads to stop
        self.tested = 0                      # counter for passwords tested
        self._lock = threading.Lock()        # thread-safe counter updates
        self.start_time = 0.0
        self.end_time = 0.0

        # Check if the PDF file exists
        if not os.path.isfile(pdf_path):
            logger.error("PDF not found: %s", pdf_path)
            sys.exit(1)

        # Check if the PDF is actually encrypted
        size_mb = os.path.getsize(pdf_path) / (1024 * 1024)
        try:
            pikepdf.Pdf.open(pdf_path).close()
            display(f"[*] PDF is not encrypted ({size_mb:.1f} MB). Nothing to crack.", style="yellow")
            sys.exit(0)
        except pikepdf.PasswordError:
            # This is what we want - the PDF is encrypted
            logger.info("PDF is encrypted (%s, %.1f MB). Ready to crack.", pdf_path, size_mb)
        except Exception as exc:
            logger.error("Cannot open PDF: %s", exc)
            sys.exit(1)

    def try_password(self, password):
        """
        Test a single password against the PDF.
        Returns True if the password is correct, False otherwise.
        """
        # Check if another thread already found the password
        if self.stop_event.is_set():
            return False
        try:
            pdf = pikepdf.Pdf.open(self.pdf_path, password=password)
            pdf.close()
            return True
        except pikepdf.PasswordError:
            return False
        except Exception as exc:
            logger.debug("Unexpected error testing '%s': %s", password, exc)
            return False

    # ----- Core engine that runs passwords in parallel -----

    def run_attack(self, passwords, total, description):
        """
        Run passwords through the thread pool in batches.

        This is the core engine used by all attack modes. It:
        - Submits passwords in batches (to limit memory usage)
        - Shows a progress bar with speed and ETA
        - Stops all threads immediately when password is found
        """
        progress = create_progress_bar(total)

        if progress:
            progress.start()
            task_id = progress.add_task(description, total=total, speed="0 pwd/s")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                batch = []

                for pwd in passwords:
                    if self.stop_event.is_set():
                        break

                    # Submit password to thread pool
                    future = pool.submit(self.try_password, pwd)
                    future._pwd = pwd  # store the password on the future for later retrieval
                    batch.append(future)

                    # Process batch when it's full
                    if len(batch) >= BATCH_SIZE:
                        if self._process_batch(batch, progress, task_id if progress else None):
                            return True
                        batch = []

                # Process any remaining passwords
                if batch and not self.stop_event.is_set():
                    if self._process_batch(batch, progress, task_id if progress else None):
                        return True

        except KeyboardInterrupt:
            self.stop_event.set()
            display("\n[!] Interrupted by user.", style="bold red")
        finally:
            if progress:
                progress.stop()

        return False

    def _process_batch(self, futures, progress, task_id):
        """
        Wait for a batch of futures to complete and check results.
        Returns True if the password was found.
        """
        for f in as_completed(futures):
            if self.stop_event.is_set():
                return False

            result = f.result()

            # Update the counter (thread-safe)
            with self._lock:
                self.tested += 1
                count = self.tested

            # Update progress bar
            if progress and task_id is not None:
                elapsed = time.time() - self.start_time
                speed = count / elapsed if elapsed > 0 else 0
                progress.update(task_id, advance=1, speed=f"{speed:,.0f} pwd/s")

            # Fallback: print progress every 10,000 passwords if Rich is not available
            if not progress and count % 10000 == 0:
                elapsed = time.time() - self.start_time
                speed = count / elapsed if elapsed > 0 else 0
                print(f"\r  Tested: {count:,}  Speed: {speed:,.0f} pwd/s", end="", flush=True)

            # Check if this password was correct
            if result:
                self.found_password = f._pwd
                self.stop_event.set()
                return True

        return False

    # ----- Attack Mode Implementations -----

    def dictionary_attack(self, wordlist):
        """
        Dictionary Attack: tries each password from a wordlist file.
        This is the most common and usually fastest attack mode.
        """
        total = count_lines(wordlist)
        logger.info("Dictionary attack - %s (%s words)", wordlist, f"{total:,}")
        return self.run_attack(read_wordlist(wordlist), total, "Dictionary")

    def brute_force_attack(self, charset, min_len, max_len):
        """
        Brute-Force Attack: tries every possible combination of characters.
        This guarantees finding the password but can be very slow for long passwords.

        For example, with lowercase + digits (36 chars) and max length 4:
        Total combinations = 36^1 + 36^2 + 36^3 + 36^4 = 1,727,604
        """
        total = sum(len(charset) ** i for i in range(min_len, max_len + 1))
        logger.info("Brute-force - charset[%d] len[%d-%d] (%s combos)",
                     len(charset), min_len, max_len, f"{total:,}")

        def generate():
            for length in range(min_len, max_len + 1):
                for combo in product(charset, repeat=length):
                    if self.stop_event.is_set():
                        return
                    yield "".join(combo)

        return self.run_attack(generate(), total, "Brute-force")

    def hybrid_attack(self, wordlist, prefixes, suffixes):
        """
        Hybrid Attack: combines dictionary words with prefixes and suffixes.
        For example: "admin" + "password" + "123" = "adminpassword123"

        This is useful because many people create passwords by combining
        a common word with numbers or symbols.
        """
        base_count = count_lines(wordlist)
        total = base_count * (len(prefixes) + 1) * (len(suffixes) + 1)
        logger.info("Hybrid attack - %s combos", f"{total:,}")

        def generate():
            for word in read_wordlist(wordlist):
                for pre in [""] + prefixes:
                    for suf in [""] + suffixes:
                        if self.stop_event.is_set():
                            return
                        yield pre + word + suf

        return self.run_attack(generate(), total, "Hybrid")

    def rules_attack(self, wordlist):
        """
        Rules-Based Attack: applies common password mutations to dictionary words.

        People often modify real words to create passwords, like:
        - "password" -> "PASSWORD" (uppercase)
        - "password" -> "password123" (append numbers)
        - "password" -> "p@ssw0rd" (leet speak)

        This attack tries these common patterns automatically.
        """
        # Define mutation rules as lambda functions
        rules = [
            lambda x: x,                    # original word
            lambda x: x.upper(),            # UPPERCASE
            lambda x: x.lower(),            # lowercase
            lambda x: x.capitalize(),       # Capitalize
            lambda x: x.title(),            # Title Case
            lambda x: x[::-1],              # reversed
            lambda x: x + "123",            # append 123
            lambda x: x + "1234",           # append 1234
            lambda x: x + "!",              # append !
            lambda x: x + "@",              # append @
            lambda x: x + "2024",           # append year
            lambda x: x + "2025",           # append year
            lambda x: x.replace("a", "@").replace("e", "3").replace("o", "0"),  # leet speak
            lambda x: x[0].upper() + x[1:] if len(x) > 1 else x.upper(),       # first letter caps
            lambda x: x + x[-1] * 2 if x else x,  # repeat last char
        ]

        base_count = count_lines(wordlist)
        total = base_count * len(rules)
        logger.info("Rules attack - %d rules x %s words = %s combos",
                     len(rules), f"{base_count:,}", f"{total:,}")

        def generate():
            for word in read_wordlist(wordlist):
                for rule in rules:
                    if self.stop_event.is_set():
                        return
                    try:
                        yield rule(word)
                    except Exception:
                        continue

        return self.run_attack(generate(), total, "Rules")

    # ----- Main crack method -----

    def crack(self, mode="dict", wordlist=None, charset=DEFAULT_CHARSET,
              min_len=1, max_len=4, prefixes=None, suffixes=None):
        """
        Main method to start the cracking process.
        Selects the appropriate attack mode and runs it.
        """
        self.start_time = time.time()
        show_banner()

        # Display target info
        display(f"[*] Target   : {self.pdf_path}", style="bold")
        display(f"[*] Mode     : {mode.upper()}", style="bold")
        display(f"[*] Threads  : {self.threads}", style="bold")
        display("")

        success = False

        if mode == "dict":
            success = self.dictionary_attack(wordlist or "rockyou.txt")
        elif mode == "brute":
            success = self.brute_force_attack(charset, min_len, max_len)
        elif mode == "hybrid":
            success = self.hybrid_attack(
                wordlist or "rockyou.txt",
                prefixes or ["admin", "user", "test"],
                suffixes or ["123", "!", "2024"],
            )
        elif mode == "rules":
            success = self.rules_attack(wordlist or "rockyou.txt")

        self.end_time = time.time()
        return success

    # ----- Report Generation -----

    def print_report(self, json_path=None):
        """Print a summary of the cracking attempt and optionally save as JSON."""
        elapsed = self.end_time - self.start_time
        speed = self.tested / elapsed if elapsed > 0 else 0

        # Display report using Rich table or plain text
        if RICH_AVAILABLE:
            table = Table(title="Cracking Report", show_header=False, border_style="bright_cyan")
            table.add_column("Key", style="bold")
            table.add_column("Value")

            status = "[bold green]CRACKED" if self.found_password else "[bold red]FAILED"
            table.add_row("Status", status)
            table.add_row("Password", self.found_password or "-")
            table.add_row("Tested", f"{self.tested:,}")
            table.add_row("Speed", f"{speed:,.0f} passwords/sec")
            table.add_row("Elapsed", f"{elapsed:.2f}s")
            console.print()
            console.print(table)
        else:
            print(f"\n{'=' * 55}")
            print("  CRACKING REPORT")
            print(f"{'=' * 55}")
            print(f"  Status   : {'CRACKED' if self.found_password else 'FAILED'}")
            print(f"  Password : {self.found_password or '-'}")
            print(f"  Tested   : {self.tested:,}")
            print(f"  Speed    : {speed:,.0f} passwords/sec")
            print(f"  Elapsed  : {elapsed:.2f}s")
            print(f"{'=' * 55}")

        # Save the decrypted PDF if password was found
        if self.found_password:
            self._save_decrypted()

        # Optionally save report as JSON
        if json_path:
            data = {
                "status": "cracked" if self.found_password else "failed",
                "password": self.found_password,
                "tested": self.tested,
                "speed": round(speed, 1),
                "elapsed_seconds": round(elapsed, 2),
                "pdf": self.pdf_path,
            }
            Path(json_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info("JSON report saved to %s", json_path)

    def _save_decrypted(self):
        """Save a decrypted copy of the PDF after cracking."""
        try:
            pdf = pikepdf.Pdf.open(self.pdf_path, password=self.found_password)
            out = self.output or str(
                Path(self.pdf_path).with_stem(Path(self.pdf_path).stem + "_decrypted")
            )
            pdf.save(out)
            pdf.close()
            display(f"\n[+] Decrypted PDF saved: {out}", style="bold green")
        except Exception as exc:
            logger.error("Could not save decrypted PDF: %s", exc)


# ===========================
# Command-Line Interface
# ===========================

def build_parser():
    """Build the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="pdf-cracker",
        description="PDF Password Cracker - Recover passwords from encrypted PDF files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s secret.pdf\n"
            "  %(prog)s secret.pdf -m brute -c abc123 -L 4\n"
            "  %(prog)s secret.pdf -m rules -w passwords.txt\n"
            "  %(prog)s secret.pdf -m hybrid -p admin root -s 123 ! -w words.txt\n"
        ),
    )

    parser.add_argument("pdf", help="Target encrypted PDF file")
    parser.add_argument("-m", "--mode", choices=["dict", "brute", "hybrid", "rules"],
                        default="dict", help="Attack mode (default: dict)")
    parser.add_argument("-w", "--wordlist", default=None,
                        help="Path to wordlist file (default: rockyou.txt)")
    parser.add_argument("-c", "--charset", default=DEFAULT_CHARSET,
                        help="Character set for brute-force mode")
    parser.add_argument("-l", "--min-len", type=int, default=1,
                        help="Min password length for brute-force (default: 1)")
    parser.add_argument("-L", "--max-len", type=int, default=4,
                        help="Max password length for brute-force (default: 4)")
    parser.add_argument("-t", "--threads", type=int,
                        default=min(32, (os.cpu_count() or 4) * 2),
                        help="Number of worker threads (default: auto)")
    parser.add_argument("-p", "--prefixes", nargs="+", default=[],
                        help="Prefixes for hybrid mode")
    parser.add_argument("-s", "--suffixes", nargs="+", default=[],
                        help="Suffixes for hybrid mode")
    parser.add_argument("-o", "--output", default=None,
                        help="Output path for decrypted PDF")
    parser.add_argument("--json", default=None, metavar="FILE",
                        help="Save report as JSON file")
    parser.add_argument("--log", default=None, metavar="FILE",
                        help="Save logs to file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed debug output")
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")

    return parser


def main():
    """Entry point of the application."""
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log)

    # Make sure wordlist exists for modes that need it
    if args.mode in ("dict", "hybrid", "rules"):
        wl = args.wordlist or "rockyou.txt"
        if not os.path.isfile(wl):
            logger.error("Wordlist not found: %s", wl)
            sys.exit(1)

    # Setup Ctrl+C handler for clean shutdown
    original_sigint = signal.getsignal(signal.SIGINT)
    cracker = PDFCracker(args.pdf, threads=args.threads, output=args.output)

    def handle_interrupt(_sig, _frame):
        cracker.stop_event.set()
        display("\n[!] Shutting down gracefully...", style="bold red")
        signal.signal(signal.SIGINT, original_sigint)

    signal.signal(signal.SIGINT, handle_interrupt)

    # Run the cracker
    cracker.crack(
        mode=args.mode,
        wordlist=args.wordlist,
        charset=args.charset,
        min_len=args.min_len,
        max_len=args.max_len,
        prefixes=args.prefixes or None,
        suffixes=args.suffixes or None,
    )

    # Show results
    cracker.print_report(json_path=args.json)


if __name__ == "__main__":
    main()
