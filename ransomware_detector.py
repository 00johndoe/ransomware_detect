#!/usr/bin/env python3
"""
Ransomware Detection Tool
Monitors file system activity for ransomware-like behavior using:
  - File rename/extension change detection
  - Shannon entropy analysis
  - Mass write burst detection
  - Honeypot file monitoring
  - Known ransomware extension signatures
  - Shadow copy deletion detection (Windows)
"""

import os
import sys
import math
import time
import json
import hashlib
import argparse
import logging
import platform
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except ImportError:
    print("[ERROR] watchdog not installed. Run: pip install watchdog")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


# ─── Color helpers ────────────────────────────────────────────────────────────

def c(color, text):
    if not HAS_COLOR:
        return text
    return f"{color}{text}{Style.RESET_ALL}"

def red(t):    return c(Fore.RED, t)
def yellow(t): return c(Fore.YELLOW, t)
def green(t):  return c(Fore.GREEN, t)
def cyan(t):   return c(Fore.CYAN, t)
def white(t):  return c(Fore.WHITE + Style.BRIGHT, t)
def dim(t):    return c(Style.DIM, t)


# ─── Constants ────────────────────────────────────────────────────────────────

# Known ransomware file extensions
RANSOMWARE_EXTENSIONS = {
    # LockBit
    ".lockbit", ".locked", ".lock",
    # STOP/Djvu
    ".djvu", ".djvus", ".djvuu", ".uudjvu", ".djvuq",
    # REvil / Sodinokibi
    ".sodinokibi", ".xyza", ".kqgs",
    # BlackCat / ALPHV
    ".blackcat", ".sykafbt",
    # Ryuk
    ".RYK", ".ryk",
    # Conti
    ".CONTI",
    # Generic patterns
    ".encrypted", ".enc", ".crypto", ".crypted",
    ".crypt", ".crypz", ".cryp1",
    ".xxx", ".ttt", ".micro", ".vvv", ".breaking_bad",
    ".fun", ".vault", ".wnry", ".wcry",  # WannaCry
    ".wncry", ".wncryt",
    ".locky", ".zepto", ".odin",
    ".cerber", ".cerber2", ".cerber3",
    ".aaa", ".abc", ".xyz",
    ".r5a", ".r4a",
    # Extensions with random suffixes — detected heuristically below
}

# Ransom note filenames
RANSOM_NOTE_NAMES = {
    "readme.txt", "readme.html", "readme!.txt",
    "how_to_decrypt.txt", "how_to_decrypt.html",
    "decrypt_instructions.txt", "decrypt_instructions.html",
    "recovery.txt", "recovery.html",
    "your_files_are_encrypted.txt",
    "!decrypt_my_files.txt", "!decrypt_my_files.html",
    "restore_files.txt", "restore_my_files.html",
    "ransom.txt", "ransom_note.txt",
    "_readme.txt", "_important_readme.txt",
    "help_decrypt.html", "help_your_files.html",
    "attention.txt",
    "files_encrypted.txt",
}

# Entropy threshold (bits/byte) — 7.5+ is suspicious, 7.8+ is very likely encrypted
ENTROPY_HIGH   = 7.8
ENTROPY_MEDIUM = 7.2

# Rename burst threshold: N renames within window_seconds triggers alert
BURST_RENAME_COUNT  = 10
BURST_RENAME_WINDOW = 30  # seconds

# Write burst threshold
BURST_WRITE_COUNT  = 20
BURST_WRITE_WINDOW = 30


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class Alert:
    level: str           # CRITICAL / WARNING / INFO
    category: str
    message: str
    path: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    extra: dict = field(default_factory=dict)


@dataclass
class Stats:
    files_monitored: int = 0
    renames_detected: int = 0
    high_entropy_files: int = 0
    ransom_notes_found: int = 0
    honeypots_triggered: int = 0
    alerts_total: int = 0
    start_time: float = field(default_factory=time.time)


# ─── Entropy ──────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0–8 bits/byte)."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def file_entropy(path: str, sample_bytes: int = 65536) -> Optional[float]:
    """Read up to sample_bytes from a file and return its entropy."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        return shannon_entropy(data)
    except (OSError, PermissionError):
        return None


# ─── Honeypots ────────────────────────────────────────────────────────────────

class HoneypotManager:
    """Creates and monitors decoy files that should never be touched."""

    DEFAULT_NAMES = [
        "_IMPORTANT_README.txt",
        "passwords_backup.txt",
        "budget_confidential.xlsx.bak",
        "ssh_keys_backup.txt",
        "_DO_NOT_DELETE.txt",
    ]

    def __init__(self, directory: str, names: list = None):
        self.directory = Path(directory)
        self.names = names or self.DEFAULT_NAMES
        self.honeypot_paths: dict[str, str] = {}   # path -> sha256
        self._lock = threading.Lock()

    def deploy(self) -> list[str]:
        """Create honeypot files, return list of paths created."""
        self.directory.mkdir(parents=True, exist_ok=True)
        deployed = []
        for name in self.names:
            path = self.directory / name
            try:
                content = (
                    f"This file is a system integrity marker created on "
                    f"{datetime.now().isoformat()}.\n"
                    f"GUID: {hashlib.md5(name.encode()).hexdigest()}\n"
                    f"DO NOT MODIFY OR DELETE.\n"
                )
                if not path.exists():
                    path.write_text(content)
                with self._lock:
                    self.honeypot_paths[str(path)] = self._hash(path)
                deployed.append(str(path))
            except (OSError, PermissionError) as e:
                logging.warning(f"Could not create honeypot {path}: {e}")
        return deployed

    def remove(self):
        """Delete all deployed honeypot files."""
        for path_str in list(self.honeypot_paths.keys()):
            try:
                Path(path_str).unlink(missing_ok=True)
            except OSError:
                pass
        self.honeypot_paths.clear()

    def check(self, path: str) -> bool:
        """Return True if path is a honeypot file that has been triggered."""
        with self._lock:
            return path in self.honeypot_paths

    def _hash(self, path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return ""


# ─── Detection engine ─────────────────────────────────────────────────────────

class DetectionEngine:
    """Core detection logic, shared between the file-system handler and scanner."""

    def __init__(self, honeypot_manager: HoneypotManager, alert_callback):
        self.honeypots = honeypot_manager
        self.alert = alert_callback
        self.stats = Stats()

        # Sliding windows for burst detection
        self._rename_times: deque = deque()
        self._write_times: deque  = deque()
        self._lock = threading.Lock()

    # ── Extension checks ──────────────────────────────────────────────────────

    def check_extension(self, path: str) -> Optional[Alert]:
        ext = Path(path).suffix.lower()
        if ext in RANSOMWARE_EXTENSIONS:
            return Alert(
                level="CRITICAL",
                category="RANSOMWARE_EXTENSION",
                message=f"File has known ransomware extension '{ext}'",
                path=path,
                extra={"extension": ext},
            )
        return None

    def check_ransom_note(self, path: str) -> Optional[Alert]:
        name = Path(path).name.lower()
        if name in RANSOM_NOTE_NAMES:
            return Alert(
                level="CRITICAL",
                category="RANSOM_NOTE",
                message=f"Ransom note filename detected: '{name}'",
                path=path,
            )
        return None

    # ── Entropy ───────────────────────────────────────────────────────────────

    def check_entropy(self, path: str) -> Optional[Alert]:
        entropy = file_entropy(path)
        if entropy is None:
            return None
        self.stats.files_monitored += 1
        if entropy >= ENTROPY_HIGH:
            self.stats.high_entropy_files += 1
            return Alert(
                level="CRITICAL",
                category="HIGH_ENTROPY",
                message=f"File entropy {entropy:.3f} bits/byte (≥{ENTROPY_HIGH}) — likely encrypted",
                path=path,
                extra={"entropy": entropy},
            )
        if entropy >= ENTROPY_MEDIUM:
            return Alert(
                level="WARNING",
                category="MEDIUM_ENTROPY",
                message=f"File entropy {entropy:.3f} bits/byte — possibly compressed or partially encrypted",
                path=path,
                extra={"entropy": entropy},
            )
        return None

    # ── Burst detection ───────────────────────────────────────────────────────

    def record_rename(self, path: str) -> Optional[Alert]:
        now = time.time()
        with self._lock:
            self._rename_times.append(now)
            # Drop old events outside window
            while self._rename_times and now - self._rename_times[0] > BURST_RENAME_WINDOW:
                self._rename_times.popleft()
            count = len(self._rename_times)
        self.stats.renames_detected += 1
        if count >= BURST_RENAME_COUNT:
            return Alert(
                level="CRITICAL",
                category="RENAME_BURST",
                message=f"{count} file renames detected in {BURST_RENAME_WINDOW}s — ransomware pattern",
                path=path,
                extra={"count": count, "window_seconds": BURST_RENAME_WINDOW},
            )
        return None

    def record_write(self, path: str) -> Optional[Alert]:
        now = time.time()
        with self._lock:
            self._write_times.append(now)
            while self._write_times and now - self._write_times[0] > BURST_WRITE_WINDOW:
                self._write_times.popleft()
            count = len(self._write_times)
        if count >= BURST_WRITE_COUNT:
            return Alert(
                level="WARNING",
                category="WRITE_BURST",
                message=f"{count} file writes in {BURST_WRITE_WINDOW}s — possible encryption sweep",
                path=path,
                extra={"count": count, "window_seconds": BURST_WRITE_WINDOW},
            )
        return None

    # ── Honeypot ──────────────────────────────────────────────────────────────

    def check_honeypot(self, path: str) -> Optional[Alert]:
        if self.honeypots.check(path):
            self.stats.honeypots_triggered += 1
            return Alert(
                level="CRITICAL",
                category="HONEYPOT_TRIGGERED",
                message=f"Honeypot file was modified — ransomware almost certainly active",
                path=path,
            )
        return None

    def emit(self, alert: Optional[Alert]):
        if alert:
            self.stats.alerts_total += 1
            self.alert(alert)


# ─── File system event handler ────────────────────────────────────────────────

class RansomwareEventHandler(FileSystemEventHandler):

    def __init__(self, engine: DetectionEngine):
        super().__init__()
        self.engine = engine

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path = event.src_path
        self.engine.emit(self.engine.check_honeypot(path))
        self.engine.emit(self.engine.check_ransom_note(path))
        self.engine.emit(self.engine.record_write(path))
        # Entropy check — rate-limit to avoid pegging CPU
        self.engine.emit(self.engine.check_entropy(path))

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path = event.src_path
        self.engine.emit(self.engine.check_extension(path))
        self.engine.emit(self.engine.check_ransom_note(path))
        self.engine.emit(self.engine.check_honeypot(path))
        self.engine.emit(self.engine.record_write(path))

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        dest = event.dest_path
        self.engine.emit(self.engine.check_extension(dest))
        self.engine.emit(self.engine.record_rename(dest))
        self.engine.emit(self.engine.check_honeypot(dest))

    def on_deleted(self, event: FileSystemEvent):
        pass  # Can log shadow copy deletes if extended


# ─── Alert output ─────────────────────────────────────────────────────────────

class AlertLogger:
    ICONS = {
        "CRITICAL": "🔴",
        "WARNING":  "🟡",
        "INFO":     "🔵",
    }
    COLORS = {
        "CRITICAL": red,
        "WARNING":  yellow,
        "INFO":     cyan,
    }

    def __init__(self, log_file: Optional[str] = None, quiet: bool = False):
        self.log_file = log_file
        self.quiet = quiet
        self._seen: set = set()   # deduplicate noisy repeats
        self._lock = threading.Lock()
        if log_file:
            Path(log_file).write_text("")   # truncate on start

    def __call__(self, alert: Alert):
        # Simple dedup: skip if same (category, path) seen in last N alerts
        key = f"{alert.category}:{alert.path}"
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            # Keep set from growing unboundedly
            if len(self._seen) > 500:
                self._seen.pop()

        self._print(alert)
        if self.log_file:
            self._write(alert)

    def _print(self, alert: Alert):
        if self.quiet:
            return
        icon  = self.ICONS.get(alert.level, "⚪")
        color = self.COLORS.get(alert.level, white)
        ts    = dim(f"[{alert.timestamp}]")
        level = color(f"[{alert.level:<8}]")
        cat   = cyan(f"[{alert.category}]")
        msg   = color(alert.message)
        path  = dim(f"  → {alert.path}")
        print(f"\n{icon} {ts} {level} {cat}")
        print(f"   {msg}")
        print(path)
        if alert.extra:
            for k, v in alert.extra.items():
                print(dim(f"   {k}: {v}"))

    def _write(self, alert: Alert):
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(asdict(alert)) + "\n")
        except OSError:
            pass


# ─── File scanner (non-realtime) ──────────────────────────────────────────────

def scan_directory(path: str, engine: DetectionEngine, recursive: bool = True):
    """Walk a directory and run static checks on every file."""
    root = Path(path)
    if not root.exists():
        print(red(f"[ERROR] Path does not exist: {path}"))
        return

    all_files = list(root.rglob("*") if recursive else root.glob("*"))
    files = [f for f in all_files if f.is_file()]
    total = len(files)

    print(white(f"\n[SCAN] Scanning {total} files in {path}"))
    print(dim("─" * 60))

    for i, fpath in enumerate(files, 1):
        pstr = str(fpath)
        sys.stdout.write(f"\r  {dim(f'{i}/{total}')} {dim(fpath.name[:50]):<52}")
        sys.stdout.flush()

        engine.emit(engine.check_extension(pstr))
        engine.emit(engine.check_ransom_note(pstr))
        engine.emit(engine.check_entropy(pstr))

    sys.stdout.write("\r" + " " * 70 + "\r")
    print(green(f"[SCAN] Complete. {total} files analyzed."))


# ─── Stats printer ────────────────────────────────────────────────────────────

def print_stats(stats: Stats):
    elapsed = time.time() - stats.start_time
    mins, secs = divmod(int(elapsed), 60)
    print("\n" + white("=" * 60))
    print(white("  Detection Summary"))
    print(white("=" * 60))
    rows = [
        ("Uptime",                 f"{mins}m {secs}s"),
        ("Files analyzed",         stats.files_monitored),
        ("Renames detected",       stats.renames_detected),
        ("High-entropy files",     stats.high_entropy_files),
        ("Ransom notes found",     stats.ransom_notes_found),
        ("Honeypots triggered",    stats.honeypots_triggered),
        ("Total alerts emitted",   stats.alerts_total),
    ]
    for label, value in rows:
        indicator = ""
        if label in ("High-entropy files", "Ransom notes found", "Honeypots triggered") and value > 0:
            indicator = red("  ⚠")
        print(f"  {dim(label + ':'):<30} {white(str(value))}{indicator}")
    print(white("=" * 60) + "\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Ransomware Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor a directory in real-time:
    python ransomware_detector.py monitor /home/user/Documents

  Scan a directory for existing threats:
    python ransomware_detector.py scan /home/user --recursive

  Monitor with honeypots and JSON logging:
    python ransomware_detector.py monitor /data --honeypot-dir /data/.honeypots --log alerts.json

  Check entropy of a single file:
    python ransomware_detector.py entropy /path/to/file.bin
""",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # monitor
    mon = sub.add_parser("monitor", help="Real-time file system monitoring")
    mon.add_argument("path", help="Directory to monitor")
    mon.add_argument("--honeypot-dir", default=None,
                     help="Directory for honeypot files (default: <path>/.honeypots)")
    mon.add_argument("--no-honeypots", action="store_true", help="Disable honeypot deployment")
    mon.add_argument("--log", default=None, metavar="FILE",
                     help="Write alerts as JSONL to this file")
    mon.add_argument("--recursive", action="store_true", default=True,
                     help="Monitor subdirectories (default: True)")
    mon.add_argument("--quiet", action="store_true", help="Suppress console output")

    # scan
    sc = sub.add_parser("scan", help="Scan existing files for ransomware indicators")
    sc.add_argument("path", help="Directory or file to scan")
    sc.add_argument("--recursive", action="store_true", default=True)
    sc.add_argument("--log", default=None, metavar="FILE")
    sc.add_argument("--quiet", action="store_true")

    # entropy
    ent = sub.add_parser("entropy", help="Check Shannon entropy of a single file")
    ent.add_argument("file", help="File path to analyze")

    # extensions
    sub.add_parser("list-extensions", help="List all known ransomware extensions")

    return p


def cmd_monitor(args):
    watch_path = args.path
    honeypot_dir = args.honeypot_dir or os.path.join(watch_path, ".honeypots")
    log_file = getattr(args, "log", None)

    alert_logger = AlertLogger(log_file=log_file, quiet=getattr(args, "quiet", False))

    honeypots = HoneypotManager(honeypot_dir)
    engine = DetectionEngine(honeypots, alert_logger)

    if not getattr(args, "no_honeypots", False):
        deployed = honeypots.deploy()
        print(green(f"[HONEYPOT] Deployed {len(deployed)} honeypot files to {honeypot_dir}"))
        for hp in deployed:
            print(dim(f"  {hp}"))

    handler  = RansomwareEventHandler(engine)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()

    print(white(f"\n[MONITOR] Watching: {watch_path}"))
    print(dim("  Press Ctrl+C to stop.\n"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        if not getattr(args, "no_honeypots", False):
            honeypots.remove()
            print(dim("\n[HONEYPOT] Honeypot files removed."))
        print_stats(engine.stats)
        if log_file:
            print(green(f"[LOG] Alerts saved to: {log_file}"))


def cmd_scan(args):
    log_file = getattr(args, "log", None)
    alert_logger = AlertLogger(log_file=log_file, quiet=getattr(args, "quiet", False))
    # No honeypots for a static scan
    honeypots = HoneypotManager("/tmp", names=[])
    engine = DetectionEngine(honeypots, alert_logger)

    scan_directory(args.path, engine, recursive=getattr(args, "recursive", True))
    print_stats(engine.stats)
    if log_file:
        print(green(f"[LOG] Alerts saved to: {log_file}"))


def cmd_entropy(args):
    path = args.file
    if not os.path.isfile(path):
        print(red(f"[ERROR] Not a file: {path}"))
        sys.exit(1)
    entropy = file_entropy(path)
    if entropy is None:
        print(red(f"[ERROR] Could not read file: {path}"))
        sys.exit(1)

    bar_len = 40
    filled  = int((entropy / 8.0) * bar_len)
    bar     = "█" * filled + "░" * (bar_len - filled)

    if entropy >= ENTROPY_HIGH:
        level_str = red(f"HIGH — likely encrypted/compressed (ransomware range)")
        bar_colored = red(bar)
    elif entropy >= ENTROPY_MEDIUM:
        level_str = yellow(f"MEDIUM — possibly compressed or partially encrypted")
        bar_colored = yellow(bar)
    else:
        level_str = green(f"NORMAL — typical for unencrypted data")
        bar_colored = green(bar)

    print(f"\n{white('File:')}     {path}")
    print(f"{white('Entropy:')}  {bar_colored} {white(f'{entropy:.4f}')} bits/byte")
    print(f"{white('Level:')}    {level_str}\n")


def cmd_list_extensions():
    exts = sorted(RANSOMWARE_EXTENSIONS)
    print(white(f"\n[SIGNATURES] {len(exts)} known ransomware extensions:\n"))
    cols = 4
    for i, ext in enumerate(exts):
        end = "\n" if (i + 1) % cols == 0 else "  "
        print(f"  {yellow(ext):<20}", end=end)
    print("\n")


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    banner = r"""
  ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
  ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
  ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
  Detection Tool  |  Python {ver}  |  {plat}
    """.format(ver=platform.python_version(), plat=platform.system())

    print(red(banner) if HAS_COLOR else banner)

    if   args.command == "monitor":          cmd_monitor(args)
    elif args.command == "scan":             cmd_scan(args)
    elif args.command == "entropy":          cmd_entropy(args)
    elif args.command == "list-extensions":  cmd_list_extensions()


if __name__ == "__main__":
    main()
