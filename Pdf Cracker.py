#!/usr/bin/env python3
"""
PDFCrack Pro — Professional PDF Password Recovery Tool

Supports dictionary, brute-force, hybrid, and rule-based attacks
with multithreaded execution, live progress, and early termination.

Requirements:
    pip install pikepdf rich
"""

__version__ = "3.0.0"
__author__ = "PDFCrack Pro"

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
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Optional, Iterator, List

import pikepdf

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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = r"""
  ____  ____  _____ ____                _      ____
 |  _ \|  _ \|  ___/ ___|_ __ __ _  ___| | __ |  _ \ _ __ ___
 | |_) | | | | |_ | |   | '__/ _` |/ __| |/ / | |_) | '__/ _ \
 |  __/| |_| |  _|| |___| | | (_| | (__|   <  |  __/| | | (_) |
 |_|   |____/|_|   \____|_|  \__,_|\___|_|\_\ |_|   |_|  \___/
"""

DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
BATCH_SIZE = 1000  # futures submitted per batch to limit memory

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("pdfcrack")


def _setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt="%H:%M:%S"))
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(file_handler)


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

console = Console() if RICH_AVAILABLE else None


def _print(msg: str, style: str = "") -> None:
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


def _print_banner() -> None:
    if console:
        console.print(Panel(Text(BANNER, style="bold cyan"), subtitle=f"v{__version__}"))
    else:
        print(BANNER)
        print(f"  v{__version__}\n")


# ---------------------------------------------------------------------------
# Progress helper
# ---------------------------------------------------------------------------

def _make_progress(total: Optional[int] = None) -> "Progress | None":
    if not RICH_AVAILABLE:
        return None
    cols = [
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
    ]
    if total:
        cols.append(MofNCompleteColumn())
    cols += [
        TextColumn("[green]{task.fields[speed]}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ]
    return Progress(*cols, console=console, transient=False)


# ---------------------------------------------------------------------------
# Wordlist utilities
# ---------------------------------------------------------------------------

def _count_lines(path: str) -> int:
    """Fast line count without loading file into memory."""
    count = 0
    with open(path, "rb") as f:
        for _ in f:
            count += 1
    return count


def _stream_wordlist(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word:
                yield word


# ---------------------------------------------------------------------------
# Core cracker
# ---------------------------------------------------------------------------

class PDFCracker:
    """Multithreaded PDF password recovery engine."""

    def __init__(self, pdf_path: str, threads: int = 8, output: Optional[str] = None):
        self.pdf_path = pdf_path
        self.threads = threads
        self.output = output

        self.found_password: Optional[str] = None
        self.stop_event = threading.Event()
        self.tested = 0
        self._lock = threading.Lock()
        self.start_time: float = 0.0
        self.end_time: float = 0.0

        # Validate PDF
        if not os.path.isfile(pdf_path):
            logger.error("PDF not found: %s", pdf_path)
            sys.exit(1)

        size_mb = os.path.getsize(pdf_path) / (1024 * 1024)
        try:
            pikepdf.Pdf.open(pdf_path).close()
            _print(f"[*] PDF is not encrypted ({size_mb:.1f} MB). Nothing to crack.", style="yellow")
            sys.exit(0)
        except pikepdf.PasswordError:
            logger.info("PDF is encrypted (%s, %.1f MB). Ready to crack.", pdf_path, size_mb)
        except Exception as exc:
            logger.error("Cannot open PDF: %s", exc)
            sys.exit(1)

    # ---- password test ----------------------------------------------------

    def _test(self, password: str) -> bool:
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

    # ---- batched parallel runner ------------------------------------------

    def _run_batched(
        self,
        passwords: Iterator[str],
        total: Optional[int],
        description: str,
    ) -> bool:
        """Submit passwords in batches, track progress, stop early on success."""

        progress = _make_progress(total)

        if progress:
            progress.start()
            task_id = progress.add_task(description, total=total, speed="0 pwd/s")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                batch: List[Future] = []

                for pwd in passwords:
                    if self.stop_event.is_set():
                        break

                    future = pool.submit(self._test, pwd)
                    future._pwd = pwd  # type: ignore[attr-defined]
                    batch.append(future)

                    if len(batch) >= BATCH_SIZE:
                        if self._drain(batch, progress, task_id if progress else None):
                            return True
                        batch = []

                # drain remaining
                if batch and not self.stop_event.is_set():
                    if self._drain(batch, progress, task_id if progress else None):
                        return True

        except KeyboardInterrupt:
            self.stop_event.set()
            _print("\n[!] Interrupted by user.", style="bold red")
        finally:
            if progress:
                progress.stop()

        return False

    def _drain(self, futures: List[Future], progress, task_id) -> bool:
        for f in as_completed(futures):
            if self.stop_event.is_set():
                return False
            result = f.result()
            with self._lock:
                self.tested += 1
                count = self.tested

            if progress and task_id is not None:
                elapsed = time.time() - self.start_time
                speed = count / elapsed if elapsed > 0 else 0
                progress.update(task_id, advance=1, speed=f"{speed:,.0f} pwd/s")

            if not progress and count % 10000 == 0:
                elapsed = time.time() - self.start_time
                speed = count / elapsed if elapsed > 0 else 0
                print(f"\r  Tested: {count:,}  Speed: {speed:,.0f} pwd/s", end="", flush=True)

            if result:
                self.found_password = f._pwd  # type: ignore[attr-defined]
                self.stop_event.set()
                return True
        return False

    # ---- attack modes -----------------------------------------------------

    def dictionary_attack(self, wordlist: str) -> bool:
        total = _count_lines(wordlist)
        logger.info("Dictionary attack — %s (%s words)", wordlist, f"{total:,}")
        return self._run_batched(_stream_wordlist(wordlist), total, "Dictionary")

    def brute_force(self, charset: str, min_len: int, max_len: int) -> bool:
        total = sum(len(charset) ** i for i in range(min_len, max_len + 1))
        logger.info("Brute-force — charset[%d] len[%d-%d] (%s combos)",
                     len(charset), min_len, max_len, f"{total:,}")

        def gen() -> Iterator[str]:
            for length in range(min_len, max_len + 1):
                for combo in product(charset, repeat=length):
                    if self.stop_event.is_set():
                        return
                    yield "".join(combo)

        return self._run_batched(gen(), total, "Brute-force")

    def hybrid_attack(self, wordlist: str, prefixes: List[str], suffixes: List[str]) -> bool:
        base_count = _count_lines(wordlist)
        total = base_count * (len(prefixes) + 1) * (len(suffixes) + 1)
        logger.info("Hybrid attack — %s combos", f"{total:,}")

        def gen() -> Iterator[str]:
            for word in _stream_wordlist(wordlist):
                for pre in [""] + prefixes:
                    for suf in [""] + suffixes:
                        if self.stop_event.is_set():
                            return
                        yield pre + word + suf

        return self._run_batched(gen(), total, "Hybrid")

    def rules_attack(self, wordlist: str) -> bool:
        rules = [
            lambda x: x,
            lambda x: x.upper(),
            lambda x: x.lower(),
            lambda x: x.capitalize(),
            lambda x: x.title(),
            lambda x: x[::-1],
            lambda x: x + "123",
            lambda x: x + "1234",
            lambda x: x + "!",
            lambda x: x + "@",
            lambda x: x + "2024",
            lambda x: x + "2025",
            lambda x: x.replace("a", "@").replace("e", "3").replace("o", "0"),
            lambda x: x[0].upper() + x[1:] if len(x) > 1 else x.upper(),
            lambda x: x + x[-1] * 2 if x else x,
        ]
        base_count = _count_lines(wordlist)
        total = base_count * len(rules)
        logger.info("Rules attack — %d rules x %s words = %s combos",
                     len(rules), f"{base_count:,}", f"{total:,}")

        def gen() -> Iterator[str]:
            for word in _stream_wordlist(wordlist):
                for rule in rules:
                    if self.stop_event.is_set():
                        return
                    try:
                        yield rule(word)
                    except Exception:
                        continue

        return self._run_batched(gen(), total, "Rules")

    # ---- orchestrator -----------------------------------------------------

    def crack(
        self,
        mode: str = "dict",
        wordlist: Optional[str] = None,
        charset: str = DEFAULT_CHARSET,
        min_len: int = 1,
        max_len: int = 4,
        prefixes: Optional[List[str]] = None,
        suffixes: Optional[List[str]] = None,
    ) -> bool:
        self.start_time = time.time()
        _print_banner()

        _print(f"[*] Target   : {self.pdf_path}", style="bold")
        _print(f"[*] Mode     : {mode.upper()}", style="bold")
        _print(f"[*] Threads  : {self.threads}", style="bold")
        _print("")

        success = False
        if mode == "dict":
            success = self.dictionary_attack(wordlist or "rockyou.txt")
        elif mode == "brute":
            success = self.brute_force(charset, min_len, max_len)
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

    # ---- reporting --------------------------------------------------------

    def report(self, json_path: Optional[str] = None) -> None:
        elapsed = self.end_time - self.start_time
        speed = self.tested / elapsed if elapsed > 0 else 0

        if RICH_AVAILABLE:
            table = Table(title="Cracking Report", show_header=False, border_style="bright_cyan")
            table.add_column("Key", style="bold")
            table.add_column("Value")

            status = "[bold green]CRACKED" if self.found_password else "[bold red]FAILED"
            table.add_row("Status", status)
            table.add_row("Password", self.found_password or "—")
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
            print(f"  Password : {self.found_password or '—'}")
            print(f"  Tested   : {self.tested:,}")
            print(f"  Speed    : {speed:,.0f} passwords/sec")
            print(f"  Elapsed  : {elapsed:.2f}s")
            print(f"{'=' * 55}")

        # Save decrypted PDF
        if self.found_password:
            self._save_decrypted()

        # JSON report
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

    def _save_decrypted(self) -> None:
        try:
            pdf = pikepdf.Pdf.open(self.pdf_path, password=self.found_password)
            out = self.output or str(
                Path(self.pdf_path).with_stem(Path(self.pdf_path).stem + "_decrypted")
            )
            pdf.save(out)
            pdf.close()
            _print(f"\n[+] Decrypted PDF saved: {out}", style="bold green")
        except Exception as exc:
            logger.error("Could not save decrypted PDF: %s", exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdfcrack-pro",
        description="PDFCrack Pro — Professional PDF Password Recovery Tool",
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
                        help="Path to wordlist (default: rockyou.txt)")
    parser.add_argument("-c", "--charset", default=DEFAULT_CHARSET,
                        help="Charset for brute-force mode")
    parser.add_argument("-l", "--min-len", type=int, default=1,
                        help="Min password length for brute-force (default: 1)")
    parser.add_argument("-L", "--max-len", type=int, default=4,
                        help="Max password length for brute-force (default: 4)")
    parser.add_argument("-t", "--threads", type=int,
                        default=min(32, (os.cpu_count() or 4) * 2),
                        help="Worker threads (default: auto)")
    parser.add_argument("-p", "--prefixes", nargs="+", default=[],
                        help="Prefixes for hybrid mode")
    parser.add_argument("-s", "--suffixes", nargs="+", default=[],
                        help="Suffixes for hybrid mode")
    parser.add_argument("-o", "--output", default=None,
                        help="Output path for decrypted PDF")
    parser.add_argument("--json", default=None, metavar="FILE",
                        help="Save report as JSON to FILE")
    parser.add_argument("--log", default=None, metavar="FILE",
                        help="Write log to FILE")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose / debug output")
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    _setup_logging(verbose=args.verbose, log_file=args.log)

    # Validate wordlist for modes that need it
    if args.mode in ("dict", "hybrid", "rules"):
        wl = args.wordlist or "rockyou.txt"
        if not os.path.isfile(wl):
            logger.error("Wordlist not found: %s", wl)
            sys.exit(1)

    # Graceful shutdown on Ctrl+C
    original_sigint = signal.getsignal(signal.SIGINT)

    cracker = PDFCracker(args.pdf, threads=args.threads, output=args.output)

    def _handler(_sig, _frame):
        cracker.stop_event.set()
        _print("\n[!] Shutting down gracefully...", style="bold red")
        signal.signal(signal.SIGINT, original_sigint)  # re-raise on double Ctrl+C

    signal.signal(signal.SIGINT, _handler)

    cracker.crack(
        mode=args.mode,
        wordlist=args.wordlist,
        charset=args.charset,
        min_len=args.min_len,
        max_len=args.max_len,
        prefixes=args.prefixes or None,
        suffixes=args.suffixes or None,
    )

    cracker.report(json_path=args.json)


if __name__ == "__main__":
    main()
