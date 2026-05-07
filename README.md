# ransomware_detect
================================================================================
  RANSOMWARE DETECTOR
  A real-time file system monitoring and static analysis tool for detecting
  ransomware activity using behavioral heuristics and entropy analysis.
  Written in Python 3.
================================================================================

  Author   : John Doe
  GitHub   : https://github.com/00johndoe/ransomware-detector
  Language : Python 3.8+
  License  : MIT
  Version  : 1.0.0

--------------------------------------------------------------------------------
TABLE OF CONTENTS
--------------------------------------------------------------------------------

  1. Overview
  2. Features
  3. How It Works
  4. Requirements
  5. Installation
  6. Usage
       6.1  monitor  — Real-time directory monitoring
       6.2  scan     — Static file system scan
       6.3  entropy  — Single-file entropy check
       6.4  list-extensions — View signature database
  7. Alert Levels & Categories
  8. Ransomware Signature Database
  9. Honeypot System
  10. Shannon Entropy Explained
  11. Output & Logging
  12. Project Structure
  13. Extending the Tool
  14. Limitations & Disclaimer
  15. License

--------------------------------------------------------------------------------
1. OVERVIEW
--------------------------------------------------------------------------------

Ransomware Detector is a lightweight, dependency-minimal Python tool that
monitors a directory for ransomware-like behavior in real time, and can also
perform static scans of existing files to identify already-encrypted data or
dropped ransom notes.

It is designed to complement — not replace — enterprise EDR/AV solutions. It is
particularly useful for:

  - Homelab / self-hosted server protection
  - SOC training environments and blue team exercises
  - Security research and malware analysis workflows
  - CI/CD pipelines checking build output directories for unexpected encryption
  - Understanding how behavioral ransomware detection works at the OS level

The tool operates entirely locally. No data is sent anywhere. No network
connections are made. It works on Linux, macOS, and Windows.

--------------------------------------------------------------------------------
2. FEATURES
--------------------------------------------------------------------------------

  REAL-TIME MONITORING
  --------------------
  [+] File system event hooks via watchdog (inotify on Linux, FSEvents on macOS,
      ReadDirectoryChangesW on Windows)
  [+] Instant detection of file creates, writes, renames, and deletes
  [+] Recursive subdirectory monitoring

  BEHAVIORAL DETECTION
  --------------------
  [+] Rename burst detection — flags N+ renames within a time window
      (default: 10 renames in 30 seconds)
  [+] Write burst detection — flags mass write activity
      (default: 20 writes in 30 seconds)
  [+] Ransom note filename detection — 20+ known note filenames
  [+] Known ransomware extension matching — 45+ extensions across major families

  ENTROPY ANALYSIS
  ----------------
  [+] Shannon entropy calculation on file contents (samples up to 64 KB)
  [+] CRITICAL alert at >= 7.8 bits/byte (consistent with AES/ChaCha20
      encrypted output)
  [+] WARNING alert at >= 7.2 bits/byte (possible compression or partial
      encryption)
  [+] Visual entropy bar for single-file analysis

  HONEYPOT SYSTEM
  ---------------
  [+] Automatically deploys decoy files that should never be touched
  [+] Honeypot modification triggers immediate CRITICAL alert
  [+] Honeypots are safely cleaned up on exit (Ctrl+C)
  [+] Customizable honeypot directory and file names

  STATIC SCANNER
  --------------
  [+] Walk an entire directory tree and analyze every file at rest
  [+] Progress indicator showing files processed
  [+] Useful for post-incident forensics to find already-encrypted files

  OUTPUT & LOGGING
  ----------------
  [+] Color-coded terminal output (colorama)
  [+] JSONL alert log for SIEM ingestion or post-processing
  [+] Deduplication — repeated alerts for the same file are suppressed
  [+] Summary statistics on exit (uptime, files analyzed, alert counts)

--------------------------------------------------------------------------------
3. HOW IT WORKS
--------------------------------------------------------------------------------

The tool uses a layered detection approach. Each layer catches different stages
of a ransomware attack:

  LAYER 1 — EXTENSION SIGNATURES (earliest indicator, pre-encryption)
  ─────────────────────────────────────────────────────────────────────
  When ransomware renames or creates files, it typically appends a known
  extension (.locked, .encrypted, .ryk, etc.). The tool maintains a database
  of 45+ known extensions and fires a CRITICAL alert the moment a matching
  file appears.

  LAYER 2 — RANSOM NOTE DETECTION (confirms active infection)
  ────────────────────────────────────────────────────────────
  Ransomware almost always drops a ransom note alongside encrypted files.
  The tool matches against 20+ known note filenames (e.g. HOW_TO_DECRYPT.txt,
  _README.txt, RESTORE_FILES.html). A note appearing in a directory is a near-
  certain indicator of active encryption.

  LAYER 3 — ENTROPY ANALYSIS (catches unknown/new ransomware families)
  ─────────────────────────────────────────────────────────────────────
  Shannon entropy measures randomness in a file's byte distribution. Normal
  files (text, executables, images) score between 3.5 and 7.0 bits/byte.
  Files encrypted with modern symmetric ciphers (AES-256, ChaCha20) are
  indistinguishable from random data and score 7.8–8.0 bits/byte. This layer
  catches new ransomware variants that use novel extensions not yet in the
  signature database.

  LAYER 4 — BURST DETECTION (catches behavioral patterns)
  ────────────────────────────────────────────────────────
  Ransomware typically encrypts hundreds or thousands of files in rapid
  succession. Normal user activity never produces 10+ file renames or 20+
  writes in 30 seconds. Sliding-window counters track event rate and fire
  alerts when thresholds are crossed, even if the individual file events look
  benign.

  LAYER 5 — HONEYPOTS (tripwires for guaranteed early detection)
  ──────────────────────────────────────────────────────────────
  Honeypot files are decoys placed in monitored directories. Legitimate
  processes have no reason to touch them. If ransomware modifies a honeypot,
  it triggers a CRITICAL alert immediately — often before mass encryption
  begins — giving the operator time to respond.

--------------------------------------------------------------------------------
4. REQUIREMENTS
--------------------------------------------------------------------------------

  Runtime
  -------
  - Python 3.8 or higher

  Required packages
  -----------------
  - watchdog >= 3.0.0    (file system event monitoring)

  Optional packages (degrade gracefully if absent)
  -------------------------------------------------
  - colorama >= 0.4.6    (colored terminal output; works without it,
                          output is plain text)
  - psutil >= 5.9.0      (reserved for future process-level detection)

  OS support
  ----------
  - Linux   : Full support (inotify backend)
  - macOS   : Full support (FSEvents backend)
  - Windows : Full support (ReadDirectoryChangesW backend)
                Note: Some paths may require Administrator privileges

--------------------------------------------------------------------------------
5. INSTALLATION
--------------------------------------------------------------------------------

  From source (recommended)
  --------------------------

    git clone https://github.com/00johndoe/ransomware-detector.git
    cd ransomware-detector

    # Install dependencies
    pip install watchdog colorama

    # Or using a virtual environment (recommended)
    python -m venv venv
    source venv/bin/activate          # Linux/macOS
    venv\Scripts\activate             # Windows
    pip install watchdog colorama

    # Verify installation
    python ransomware_detector.py --help


  Single-file usage (no install)
  --------------------------------
  The tool is a single Python file with no compiled components. You can drop
  ransomware_detector.py onto any system with Python 3.8+ and watchdog
  installed and run it directly.

--------------------------------------------------------------------------------
6. USAGE
--------------------------------------------------------------------------------

  Global syntax:
    python ransomware_detector.py <command> [options]

  Commands:
    monitor           Real-time monitoring of a directory
    scan              Static analysis of existing files
    entropy           Entropy check on a single file
    list-extensions   Print all known ransomware extensions

  ─────────────────────────────────────────────────────────
  6.1  MONITOR — Real-time directory monitoring
  ─────────────────────────────────────────────────────────

  Syntax:
    python ransomware_detector.py monitor <path> [options]

  Arguments:
    path              Directory to monitor (required)

  Options:
    --honeypot-dir    Directory to place honeypot files
                      (default: <path>/.honeypots)
    --no-honeypots    Disable honeypot deployment
    --log FILE        Write alerts as JSONL to FILE
    --recursive       Monitor subdirectories (default: enabled)
    --quiet           Suppress console output (useful when logging to file)

  Examples:
    # Basic monitoring of Documents folder
    python ransomware_detector.py monitor /home/user/Documents

    # Monitor a data volume and save alerts to a log file
    python ransomware_detector.py monitor /mnt/data --log /var/log/rw_alerts.jsonl

    # Monitor with custom honeypot directory
    python ransomware_detector.py monitor /srv/files --honeypot-dir /srv/.traps

    # Quiet mode — alerts only go to log file
    python ransomware_detector.py monitor /home/user --log alerts.jsonl --quiet

    # Windows example
    python ransomware_detector.py monitor C:\Users\Admin\Documents

  Press Ctrl+C to stop monitoring. Honeypot files are cleaned up automatically
  on exit.

  ─────────────────────────────────────────────────────────
  6.2  SCAN — Static file system scan
  ─────────────────────────────────────────────────────────

  Syntax:
    python ransomware_detector.py scan <path> [options]

  Arguments:
    path              Directory to scan (required)

  Options:
    --recursive       Include subdirectories (default: enabled)
    --log FILE        Write alerts as JSONL to FILE
    --quiet           Suppress console output

  Examples:
    # Scan a user home directory
    python ransomware_detector.py scan /home/user

    # Scan and save results
    python ransomware_detector.py scan /mnt/backup --log scan_results.jsonl

    # Post-incident: scan an entire volume
    python ransomware_detector.py scan /mnt/affected_disk --log incident_report.jsonl

  Use the scan command after an incident to identify which files have already
  been encrypted, or as a scheduled cron job for periodic checks.

  ─────────────────────────────────────────────────────────
  6.3  ENTROPY — Single-file entropy check
  ─────────────────────────────────────────────────────────

  Syntax:
    python ransomware_detector.py entropy <file>

  Arguments:
    file              Path to file to analyze (required)

  Examples:
    python ransomware_detector.py entropy /home/user/document.pdf
    python ransomware_detector.py entropy suspicious_file.bin
    python ransomware_detector.py entropy backup.zip

  Output includes:
    - Visual entropy bar (0–8 scale)
    - Entropy score in bits/byte (4 decimal places)
    - Classification: NORMAL / MEDIUM / HIGH

  Entropy thresholds:
    < 7.2   NORMAL    — typical for unencrypted files
    7.2–7.8 MEDIUM    — possibly compressed or partially encrypted
    >= 7.8  HIGH      — consistent with AES/ChaCha20 encrypted output

  Note: Legitimately compressed files (ZIP, 7z, PNG, MP4) can also score
  7.5–8.0. Always correlate with extension and context.

  ─────────────────────────────────────────────────────────
  6.4  LIST-EXTENSIONS — View the signature database
  ─────────────────────────────────────────────────────────

  Syntax:
    python ransomware_detector.py list-extensions

  Prints all 45+ known ransomware file extensions currently in the database.

--------------------------------------------------------------------------------
7. ALERT LEVELS & CATEGORIES
--------------------------------------------------------------------------------

  Alert levels
  ─────────────
  CRITICAL    Ransomware activity is almost certainly occurring. Immediate
              action recommended: isolate the host from the network.

  WARNING     Suspicious activity that warrants investigation. May be a false
              positive (e.g. a backup program doing mass writes).

  INFO        Informational event that may be relevant to an investigation.

  Alert categories
  ─────────────────
  RANSOMWARE_EXTENSION    File created or renamed with a known ransomware
                          extension (e.g. .locked, .encrypted, .ryk)

  RANSOM_NOTE             File matching a known ransom note filename appeared
                          (e.g. HOW_TO_DECRYPT.txt, _README.txt)

  HIGH_ENTROPY            File with entropy >= 7.8 bits/byte detected — byte
                          distribution consistent with AES/ChaCha20 encryption

  MEDIUM_ENTROPY          File with entropy 7.2–7.8 bits/byte — possibly
                          compressed or partially encrypted

  RENAME_BURST            10+ file renames detected within a 30-second window —
                          characteristic of mass encryption sweeps

  WRITE_BURST             20+ file writes detected within a 30-second window

  HONEYPOT_TRIGGERED      A honeypot decoy file was modified — near-certain
                          indicator of active ransomware

--------------------------------------------------------------------------------
8. RANSOMWARE SIGNATURE DATABASE
--------------------------------------------------------------------------------

  The tool includes signatures for the following ransomware families:

  Family              Extensions
  ──────────────────  ──────────────────────────────────────────────
  LockBit             .lockbit  .locked  .lock
  STOP / Djvu         .djvu  .djvus  .djvuu  .uudjvu  .djvuq
  REvil / Sodinokibi  .sodinokibi  .xyza  .kqgs
  BlackCat / ALPHV    .blackcat  .sykafbt
  Ryuk                .RYK  .ryk
  Conti               .CONTI
  WannaCry            .wnry  .wcry  .wncry  .wncryt
  Cerber              .cerber  .cerber2  .cerber3
  Locky               .locky  .zepto  .odin
  Generic             .encrypted  .enc  .crypto  .crypted  .crypt
                      .crypz  .cryp1  .xxx  .ttt  .micro  .vvv
                      .breaking_bad  .fun  .vault  .r5a  .r4a  .aaa
                      .abc  .xyz

  To add new extensions, edit the RANSOMWARE_EXTENSIONS set in
  ransomware_detector.py.

--------------------------------------------------------------------------------
9. HONEYPOT SYSTEM
--------------------------------------------------------------------------------

  When the monitor command runs, the tool deploys 5 decoy files into
  the honeypot directory (default: <watched_path>/.honeypots/):

    _IMPORTANT_README.txt
    passwords_backup.txt
    budget_confidential.xlsx.bak
    ssh_keys_backup.txt
    _DO_NOT_DELETE.txt

  These files contain harmless placeholder text with a timestamp and hash.
  They serve as tripwires: no legitimate process should ever open, modify, or
  rename them. If ransomware sweeps the directory and touches one, the tool
  fires a CRITICAL alert immediately.

  Honeypot strategy tips:
  - Place honeypots in directories ransomware is likely to hit first
    (Desktop, Documents, Downloads)
  - Use names that look appealing to ransomware (passwords, backup, readme)
  - The tool auto-removes honeypots when you press Ctrl+C. If the process
    is killed hard (SIGKILL), you can delete the .honeypots directory manually.

--------------------------------------------------------------------------------
10. SHANNON ENTROPY EXPLAINED
--------------------------------------------------------------------------------

  Shannon entropy measures how random (or information-dense) the bytes in a
  file are, on a scale of 0 to 8 bits/byte:

    0.0       Every byte is the same (e.g. a file of all zeros)
    3.0–5.0   Typical text, source code, XML, HTML
    5.0–7.0   Executables, compiled code, some images
    7.0–7.5   Compressed files (ZIP, GZIP) — already near-maximum
    7.8–8.0   AES-256, ChaCha20, or any properly implemented cipher output
              This is the ransomware range.

  The entropy check samples the first 64 KB of each file to keep CPU usage
  manageable on large directories.

  Important caveat: ZIP, PNG, MP4, and other compressed/binary formats can
  also score in the 7.0–8.0 range. Entropy alone is not sufficient — the tool
  always correlates entropy with extension, filename, and behavioral signals
  before issuing a CRITICAL alert.

--------------------------------------------------------------------------------
11. OUTPUT & LOGGING
--------------------------------------------------------------------------------

  Terminal output
  ───────────────
  Each alert prints:

    🔴 [2026-05-07T13:42:08] [CRITICAL ] [HONEYPOT_TRIGGERED]
       Honeypot file was modified — ransomware almost certainly active
      → /home/user/Documents/.honeypots/_IMPORTANT_README.txt

  Color coding:
    Red     CRITICAL alerts
    Yellow  WARNING alerts
    Cyan    INFO alerts and category tags
    Dim     Timestamps, paths, metadata

  JSONL log format
  ────────────────
  When --log is specified, each alert is written as a single JSON object on
  its own line (JSON Lines format), compatible with tools like jq, Splunk,
  Elasticsearch, and Grafana Loki.

  Example alert record:
    {
      "level": "CRITICAL",
      "category": "RANSOMWARE_EXTENSION",
      "message": "File has known ransomware extension '.locked'",
      "path": "/home/user/Documents/taxes.pdf.locked",
      "timestamp": "2026-05-07T13:42:08",
      "extra": {"extension": ".locked"}
    }

  Querying with jq:
    # Show only CRITICAL alerts
    jq 'select(.level == "CRITICAL")' alerts.jsonl

    # Show all unique categories triggered
    jq -r '.category' alerts.jsonl | sort -u

    # Count alerts by category
    jq -r '.category' alerts.jsonl | sort | uniq -c | sort -rn

  Exit summary
  ─────────────
  On Ctrl+C, the tool prints a summary:

    ============================================================
      Detection Summary
    ============================================================
      Uptime:                        5m 42s
      Files analyzed:                14,827
      Renames detected:              53
      High-entropy files:            47
      Ransom notes found:            1
      Honeypots triggered:           1
      Total alerts emitted:          6
    ============================================================

--------------------------------------------------------------------------------
12. PROJECT STRUCTURE
--------------------------------------------------------------------------------

  ransomware-detector/
  ├── ransomware_detector.py    Main tool (single file, all logic)
  ├── README.txt                This file
  └── LICENSE                   MIT license

  Key sections inside ransomware_detector.py:

    Constants               RANSOMWARE_EXTENSIONS, RANSOM_NOTE_NAMES,
                            entropy thresholds, burst thresholds

    HoneypotManager         Deploy, monitor, and remove honeypot files

    DetectionEngine         Core detection logic:
                              check_extension()
                              check_ransom_note()
                              check_entropy()
                              record_rename() / record_write()   (burst detection)
                              check_honeypot()

    RansomwareEventHandler  watchdog event handler — routes file system
                            events to the detection engine

    AlertLogger             Console + JSONL output with deduplication

    scan_directory()        Static recursive file walker

    main() / argparse       CLI subcommands and argument parsing

--------------------------------------------------------------------------------
13. EXTENDING THE TOOL
--------------------------------------------------------------------------------

  Adding new ransomware extensions
  ──────────────────────────────────
  Add entries to the RANSOMWARE_EXTENSIONS set near the top of the file:

    RANSOMWARE_EXTENSIONS = {
        ...
        ".mynewextension",   # My new ransomware family
    }

  Adding new ransom note filenames
  ──────────────────────────────────
  Add lowercase entries to the RANSOM_NOTE_NAMES set:

    RANSOM_NOTE_NAMES = {
        ...
        "new_ransom_note.html",
    }

  Adjusting burst thresholds
  ──────────────────────────────────
  Tune these constants to reduce false positives in environments with heavy
  file activity (e.g. build servers, backup jobs):

    BURST_RENAME_COUNT  = 10   # renames before alert fires
    BURST_RENAME_WINDOW = 30   # sliding window in seconds

    BURST_WRITE_COUNT   = 20   # writes before alert fires
    BURST_WRITE_WINDOW  = 30   # sliding window in seconds

  Adding custom honeypot files
  ──────────────────────────────────
  Pass a custom list to HoneypotManager:

    honeypots = HoneypotManager(directory, names=[
        "database_passwords.txt",
        "api_keys_production.env",
        "_PLEASE_READ_ME.txt",
    ])

  Integrating with external alerting (Slack, PagerDuty, email)
  ──────────────────────────────────────────────────────────────
  The alert_callback argument in DetectionEngine accepts any callable. Replace
  AlertLogger with your own function:

    def my_alert(alert):
        if alert.level == "CRITICAL":
            requests.post(SLACK_WEBHOOK, json={"text": alert.message})

    engine = DetectionEngine(honeypots, my_alert)

  Running as a systemd service (Linux)
  ──────────────────────────────────────
  Create /etc/systemd/system/ransomware-detector.service:

    [Unit]
    Description=Ransomware Detector
    After=network.target

    [Service]
    ExecStart=/usr/bin/python3 /opt/ransomware-detector/ransomware_detector.py \
      monitor /home --log /var/log/ransomware_alerts.jsonl --quiet
    Restart=always
    User=root

    [Install]
    WantedBy=multi-user.target

  Then: systemctl enable --now ransomware-detector

--------------------------------------------------------------------------------
14. LIMITATIONS & DISCLAIMER
--------------------------------------------------------------------------------

  LIMITATIONS
  ─────────────

  This is a detection tool, not a prevention tool. It observes and alerts
  but does not block processes or quarantine files. By the time an alert fires,
  some files may already be encrypted.

  False positives are possible in environments with:
  - Backup software doing mass renames or writes
  - File compression utilities (high entropy output)
  - Build systems generating many files rapidly
  - Legitimate encrypted archives (ZIP, 7z) triggering entropy alerts

  Tune BURST_RENAME_COUNT, BURST_WRITE_COUNT, and ENTROPY_HIGH to match
  your environment's normal activity baseline.

  The entropy check samples only the first 64 KB of each file. Large files
  with encrypted payloads hidden after a normal header may not be caught.
  Increase the sample_bytes parameter in file_entropy() if needed (at the cost
  of higher CPU usage on large files).

  The tool does not perform process-level analysis (which process triggered
  the events). Extending it with psutil to correlate events to PIDs would
  significantly reduce false positives and is a natural next step.

  Network-based ransomware propagation (lateral movement via SMB) is not
  detected by this tool — only local file system events are monitored.

  DISCLAIMER
  ───────────
  This tool is provided for educational and defensive security purposes only.
  It is intended to help system administrators, security researchers, and
  homelab operators detect ransomware activity on systems they own or are
  authorized to monitor.

  Do not deploy this tool on systems you do not own or have explicit written
  permission to monitor. The authors accept no liability for misuse or for
  any damage caused by ransomware that this tool fails to detect.

  This tool does not replace a full EDR/XDR solution, enterprise antivirus,
  or a professionally managed security operations center.

--------------------------------------------------------------------------------
15. LICENSE
--------------------------------------------------------------------------------

  MIT License

  Copyright (c) 2026 [John Doe]

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

================================================================================
  END OF README
================================================================================
