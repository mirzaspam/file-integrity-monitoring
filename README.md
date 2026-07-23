# File Integrity Monitor (FIM)

A command-line File Integrity Monitoring tool written in Python. It takes a SHA-256 baseline snapshot of a directory tree and later compares a fresh scan against that baseline to detect new, deleted, or modified files — the same core concept behind blue team tools like Tripwire or OSSEC's file integrity checks.

## Why I built this

File integrity monitoring is a core detective control in a SOC — it's how you catch unauthorized changes to critical files (config files, binaries, web server directories, etc.) after the fact. I built this as a hands-on way to understand how FIM actually works under the hood before relying on production tools like Wazuh's built-in FIM module.

## Features

- **Baseline scanning** — recursively walks a target directory and records a SHA-256 hash for every file.
- **Multi-directory support** — baselines for different directories are stored side by side in the same file. Baselining a new directory doesn't erase the baseline for a previous one.
- **No re-scanning required** — once a directory has been baselined, you can run an integrity check on it anytime without re-baselining first. The tool looks up that directory's own stored baseline directly.
- **Integrity checking** — re-scans a directory and compares it against its own saved baseline to report:
  - Deleted files
  - New files
  - Modified files (hash mismatch)
- **Timestamps** — every baseline and integrity check is timestamped (baseline time is also shown during checks), so results can be correlated with other logs.
- **Error handling** — per-file errors (missing files, permission issues) are reported without crashing the whole scan.
- **Input validation** — rejects invalid menu choices and non-existent directory paths instead of failing silently.
- **Self-exclusion** — the tool excludes its own baseline file (`hashes.json`) from scans, so it never flags itself as a change.

## How it works

Baselines are stored in `hashes.json`, keyed by the absolute path of the directory they belong to:

```json
{
  "/home/user/ProjectA": {
    "timestamp": "2026-07-24 14:00:00",
    "hashes": {
      "/home/user/ProjectA/file1.txt": "abc123...",
      "/home/user/ProjectA/file2.txt": "def456..."
    }
  },
  "/home/user/ProjectB": {
    "timestamp": "2026-07-24 15:10:00",
    "hashes": {
      "/home/user/ProjectB/file1.txt": "789xyz..."
    }
  }
}
```

1. **Baseline scan** walks the target directory, hashes every file with SHA-256, and saves/updates just that directory's entry in `hashes.json` — other directories already stored are left untouched.
2. **Integrity check** re-walks the same directory, looks up that directory's stored baseline directly, and compares the two using set operations to identify what changed. If no baseline exists yet for that directory, it tells you clearly instead of comparing against unrelated data.

## Requirements

- Python 3.x
- No external dependencies — uses only the standard library (`os`, `hashlib`, `json`, `datetime`).

## Usage

```bash
python File_integrity_monitoring.py
```

You'll see a simple menu:

```
File Integrity Monitoring

1. Baseline scan.
2. Integrity Check
3. Exit
```

- **Option 1**: Enter a directory path to create/update its baseline. Baselines for other directories are preserved.
- **Option 2**: Enter a directory path to check it against its own stored baseline. No need to re-baseline first — as long as that directory has been baselined at least once before.
- **Option 3**: Exit the tool.

## Example output

```
[i] Baseline taken at: 2026-07-24 14:00:00
[i] Integrity check run at: 2026-07-24 14:32:10

[-] DELETED: None
[+] NEW: 1
    + /path/to/newfile.txt

[*] MODIFIED: 1
    * /path/to/config.conf

[x] ERRORS: None
```

## Known limitations

This is a learning project, not a production-grade FIM tool. Some honest limitations:

- No real-time monitoring; it's scan-based, not event-driven (no `inotify`/filesystem watcher).
- No alerting/notification integration — output is console-only.
- Baseline file (`hashes.json`) is stored in plaintext with no integrity protection of its own — in a real deployment, the baseline itself needs to be protected from tampering (e.g., stored off-host or signed).
- No history of past baselines per directory — each new baseline for a directory replaces that directory's previous one (by design, so you consciously "accept" a new trusted state, but it does mean no built-in audit trail of baseline changes over time).

## Roadmap / possible next steps

- Add a config file for excluding specific paths/extensions.
- Add logging (Python's `logging` module) instead of `print()` for better auditability.
- Support multiple hash algorithms as a configurable option.
- Explore real-time monitoring using `watchdog` or OS-level file system events.

## Author

Built by [SecOpsAli](https://github.com/mirzaspam) as part of an ongoing blue team portfolio.
