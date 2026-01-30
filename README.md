# PDF Password Cracker Tool

A Python-based command-line tool to recover passwords from encrypted PDF files. It supports multiple attack strategies including dictionary, brute-force, hybrid, and rule-based attacks with multithreaded execution for faster performance.

**Author:** phantom16
**Version:** 1.0.0
**Language:** Python 3.10+

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Libraries Used](#libraries-used)
- [Installation](#installation)
- [Usage](#usage)
  - [Dictionary Attack](#1-dictionary-attack-default)
  - [Brute-Force Attack](#2-brute-force-attack)
  - [Hybrid Attack](#3-hybrid-attack)
  - [Rules-Based Attack](#4-rules-based-attack)
- [CLI Options](#cli-options)
- [Code Structure Explained](#code-structure-explained)
- [Sample Output](#sample-output)
- [Limitations](#limitations)

---

## Features

- **4 Attack Modes** — Dictionary, Brute-Force, Hybrid, and Rule-Based
- **Multithreaded** — Tests multiple passwords in parallel using a thread pool
- **Live Progress Bar** — Shows speed (passwords/sec), ETA, and completion count
- **Memory Efficient** — Streams wordlists line-by-line instead of loading into RAM
- **Early Termination** — Stops all threads immediately when the password is found
- **Graceful Shutdown** — Press `Ctrl+C` once to stop cleanly, twice to force quit
- **Report Generation** — Prints a summary table and optionally exports to JSON
- **Auto Decryption** — Saves a decrypted copy of the PDF after cracking

---

## Project Structure

```
PDF Cracker Tool/
├── Pdf Cracker.py       # Main tool - all the code lives here
├── requirements.txt     # Python dependencies
├── .gitignore           # Files excluded from git
└── README.md            # This file
```

The entire tool is contained in a single file (`Pdf Cracker.py`) for simplicity. Here's how the code is organized internally:

| Section | Lines | Description |
|---------|-------|-------------|
| Imports & Constants | 1-71 | All imports, ASCII banner, default settings |
| Logging Setup | 74-101 | Configures console and file logging |
| Display Helpers | 104-153 | Functions for printing with Rich (or plain text fallback) |
| Wordlist Utilities | 156-179 | `count_lines()` and `read_wordlist()` generator |
| `PDFCracker` Class | 182-538 | Main class with all attack modes and reporting |
| CLI / `main()` | 541-634 | Argument parser and entry point |

---

## How It Works

### Overall Flow

```
User runs command
       │
       ▼
Parse CLI arguments (argparse)
       │
       ▼
Validate PDF file (check if encrypted)
       │
       ▼
Select attack mode (dict/brute/hybrid/rules)
       │
       ▼
Generate password candidates
       │
       ▼
Submit passwords to thread pool in batches of 1000
       │
       ▼
Each thread tries: pikepdf.Pdf.open(pdf, password=guess)
       │
       ├── PasswordError → wrong password, try next
       └── Success → set stop_event, save password
       │
       ▼
Print report + save decrypted PDF
```

### Attack Modes Explained

**1. Dictionary Attack** (`-m dict`)
Reads passwords from a wordlist file (like `rockyou.txt`) one by one and tries each against the PDF. This is the fastest mode if the password is a common word.

**2. Brute-Force Attack** (`-m brute`)
Generates every possible combination of characters from a given character set. For example, with `abc123` and max length 4, it tries: `a`, `b`, ..., `aa`, `ab`, ..., `3333`. Guarantees finding the password but is slow for long passwords.

**3. Hybrid Attack** (`-m hybrid`)
Combines dictionary words with prefixes and suffixes. For example, with prefix `admin` and suffix `123`, the word `password` becomes `adminpassword123`. This targets how real people often create passwords.

**4. Rules-Based Attack** (`-m rules`)
Takes dictionary words and applies common mutations like:
- UPPERCASE, lowercase, Capitalize
- Reverse the word (`password` → `drowssap`)
- Append numbers (`password123`, `password2024`)
- Leet speak (`password` → `p@ssw0rd`)
- Repeat last character (`pass` → `passss`)

### Multithreading

The tool uses Python's `ThreadPoolExecutor` to run multiple password tests in parallel. Passwords are submitted in batches of 1000 to avoid loading millions of futures into memory. A `threading.Event` is used as a shared stop signal — when any thread finds the correct password, all other threads stop immediately.

---

## Libraries Used

### Third-Party Libraries

| Library | Version | What It Does | Why I Used It |
|---------|---------|-------------|---------------|
| **pikepdf** | >= 8.0.0 | Python library for reading and writing PDF files | Used to open encrypted PDFs with a password guess. If the password is wrong, it throws `PasswordError`. If correct, the PDF opens successfully. Also used to save the decrypted copy. |
| **rich** | >= 13.0.0 | Terminal formatting library for Python | Used to display colored output, progress bars with speed/ETA, and formatted tables for the cracking report. Falls back to plain `print()` if not installed. |

### Standard Library Modules

| Module | What It Does | How It's Used In The Project |
|--------|-------------|------------------------------|
| `sys` | System-specific functions | `sys.exit()` to terminate on errors |
| `os` | Operating system interface | `os.path.isfile()` to check if files exist, `os.path.getsize()` to get PDF file size, `os.cpu_count()` to auto-detect thread count |
| `time` | Time-related functions | `time.time()` to measure elapsed time and calculate cracking speed |
| `json` | JSON encoder/decoder | `json.dumps()` to export the cracking report as a JSON file |
| `signal` | Signal handling | `signal.signal(SIGINT, handler)` to catch `Ctrl+C` and shut down threads gracefully |
| `logging` | Logging facility | Used for structured log messages with timestamps, supports both console and file output |
| `argparse` | Command-line argument parser | Parses all CLI flags like `--mode`, `--wordlist`, `--threads` etc. |
| `threading` | Thread-based parallelism | `threading.Event` for cross-thread stop signal, `threading.Lock` for thread-safe counter |
| `itertools.product` | Cartesian product iterator | Generates all character combinations for brute-force mode (e.g., all 4-letter combos of `a-z0-9`) |
| `pathlib.Path` | Object-oriented file paths | Used to construct output file paths for the decrypted PDF and JSON report |
| `concurrent.futures` | High-level threading interface | `ThreadPoolExecutor` manages a pool of worker threads, `as_completed()` processes results as they finish |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/phantom16/PDF-Cracker-Tool.git
cd PDF-Cracker-Tool
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install pikepdf rich
```

---

## Usage

### Basic syntax

```bash
python "Pdf Cracker.py" <pdf-file> [options]
```

### 1. Dictionary Attack (default)

```bash
python "Pdf Cracker.py" secret.pdf -w wordlist.txt
```

### 2. Brute-Force Attack

```bash
# Try all lowercase + digit combos up to length 4
python "Pdf Cracker.py" secret.pdf -m brute -c abcdefghijklmnopqrstuvwxyz0123456789 -L 4

# Try only digits up to length 6
python "Pdf Cracker.py" secret.pdf -m brute -c 0123456789 -L 6
```

### 3. Hybrid Attack

```bash
python "Pdf Cracker.py" secret.pdf -m hybrid -w wordlist.txt -p admin root -s 123 !
```

This tries combinations like: `adminpassword123`, `rootpassword!`, `password123`, etc.

### 4. Rules-Based Attack

```bash
python "Pdf Cracker.py" secret.pdf -m rules -w wordlist.txt
```

### Additional options

```bash
# Use 32 threads
python "Pdf Cracker.py" secret.pdf -w wordlist.txt -t 32

# Save decrypted PDF to specific path
python "Pdf Cracker.py" secret.pdf -w wordlist.txt -o decrypted.pdf

# Export report as JSON
python "Pdf Cracker.py" secret.pdf -w wordlist.txt --json report.json

# Save logs to file
python "Pdf Cracker.py" secret.pdf -w wordlist.txt --log crack.log

# Verbose debug output
python "Pdf Cracker.py" secret.pdf -w wordlist.txt -v
```

---

## CLI Options

| Flag | Long Form | Description | Default |
|------|-----------|-------------|---------|
| (positional) | — | Target encrypted PDF file | (required) |
| `-m` | `--mode` | Attack mode: `dict`, `brute`, `hybrid`, `rules` | `dict` |
| `-w` | `--wordlist` | Path to wordlist file | `rockyou.txt` |
| `-c` | `--charset` | Characters for brute-force | `a-z0-9` |
| `-l` | `--min-len` | Min password length (brute-force) | `1` |
| `-L` | `--max-len` | Max password length (brute-force) | `4` |
| `-t` | `--threads` | Number of worker threads | auto (CPU cores x 2) |
| `-p` | `--prefixes` | Prefixes for hybrid mode | `[]` |
| `-s` | `--suffixes` | Suffixes for hybrid mode | `[]` |
| `-o` | `--output` | Output path for decrypted PDF | auto-generated |
| | `--json` | Save report as JSON file | — |
| | `--log` | Save logs to file | — |
| `-v` | `--verbose` | Show debug output | off |
| `-V` | `--version` | Show version number | — |

---

## Code Structure Explained

### Key Classes and Functions

#### `PDFCracker` (main class)

| Method | Purpose |
|--------|---------|
| `__init__()` | Validates the PDF exists and is encrypted, sets up threading state |
| `try_password()` | Tests a single password using `pikepdf.Pdf.open()` |
| `run_attack()` | Core engine — submits passwords in batches to the thread pool |
| `_process_batch()` | Waits for a batch of results and checks if any password worked |
| `dictionary_attack()` | Streams passwords from a wordlist file |
| `brute_force_attack()` | Generates all character combinations using `itertools.product` |
| `hybrid_attack()` | Combines prefixes + dictionary words + suffixes |
| `rules_attack()` | Applies 15 mutation rules to each dictionary word |
| `crack()` | Main orchestrator — selects and runs the attack mode |
| `print_report()` | Displays results table and optionally saves JSON report |
| `_save_decrypted()` | Opens PDF with found password and saves an unencrypted copy |

#### Helper Functions

| Function | Purpose |
|----------|---------|
| `setup_logging()` | Configures Python logging for console and file output |
| `display()` | Prints text using Rich if available, otherwise `print()` |
| `show_banner()` | Shows ASCII art banner at startup |
| `create_progress_bar()` | Creates a Rich progress bar with speed and ETA columns |
| `count_lines()` | Counts lines in a file without loading it into memory |
| `read_wordlist()` | Generator that yields words from a file one at a time |
| `build_parser()` | Constructs the CLI argument parser |
| `main()` | Entry point — parses args, validates input, runs the cracker |

---

## Sample Output

```
+-----------------------------------------------------------------------------+
|   ____  ____  _____    ____                _                                 |
|  |  _ \|  _ \|  ___|  / ___|_ __ __ _  ___| | _____ _ __                    |
|  | |_) | | | | |_    | |   | '__/ _` |/ __| |/ / _ \ '__|                   |
|  |  __/| |_| |  _|   | |___| | | (_| | (__|   <  __/ |                      |
|  |_|   |____/|_|      \____|_|  \__,_|\___|_|\_\___|_|                       |
|                                                                              |
+----------------------------------------------- v1.0.0 ----------------------+
[*] Target   : secret.pdf
[*] Mode     : DICT
[*] Threads  : 24

  Dictionary ████████████████████████████████████████ 8/8 672 pwd/s 0:00:00

        Cracking Report
+------------------------------+
| Status   | CRACKED           |
| Password | test123           |
| Tested   | 8                 |
| Speed    | 590 passwords/sec |
| Elapsed  | 0.01s             |
+------------------------------+

[+] Decrypted PDF saved: secret_decrypted.pdf
```

---

## Limitations

- **Speed depends on PDF encryption** — PDFs with AES-256 encryption are slower to test than older RC4 encryption
- **Brute-force is exponential** — A 6-character password over 36 characters = ~2.2 billion combinations
- **Wordlist required** — Dictionary, hybrid, and rules modes need a wordlist file (e.g., `rockyou.txt`)
- **No GPU acceleration** — All password testing runs on CPU via threads
- **Python GIL** — While threads help with I/O-bound pikepdf calls, CPU-bound work doesn't fully parallelize

---

## Disclaimer

This tool is intended for **educational purposes** and **authorized password recovery** only. Only use it on PDF files that you own or have explicit permission to test. Unauthorized use of password cracking tools may violate laws in your jurisdiction.
