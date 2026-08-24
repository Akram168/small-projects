# File Integrity Monitor

A minimal Tripwire/AIDE-style tool: hash every file under a directory into a baseline, then re-check later and report exactly what was added, removed, or modified. Useful for watching config directories, web roots, or anything you want to notice tampering in.

## Usage

```bash
# Take a baseline snapshot
python monitor.py baseline /path/to/watch --out baseline.json

# ...time passes, files change...

# Check for drift against the baseline
python monitor.py check /path/to/watch --baseline baseline.json
```

Exit code is `2` if any changes were found (so it's cron/CI friendly — e.g. wire it into a scheduled task and alert on non-zero exit), `0` if the directory matches the baseline exactly.

## Example

```
$ python monitor.py baseline ./test_dir --out baseline.json
Baseline written: baseline.json (2 files hashed)

# a.txt edited, subdir/b.txt deleted, c.txt added...

$ python monitor.py check ./test_dir --baseline baseline.json

ADDED (1):
  + c.txt

REMOVED (1):
  - subdir/b.txt

MODIFIED (1):
  * a.txt
      baseline: 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
      current:  4487e24377581c1a43c957c7700c8b49920de7b8500c05590cee74996ef73f42
```

## How it works

- Recursively walks the target directory, SHA-256-hashes every file's contents, and stores `{relative_path: hash}` as JSON.
- On `check`, re-hashes the current state and diffs the two maps: keys only in current = added, keys only in baseline = removed, keys in both with a different hash = modified.
- Content-based (hash), not metadata-based (mtime) — a change that preserves the timestamp (a real tamper technique) still gets caught.

## Limitations

This is a point-in-time snapshot diff, not continuous monitoring like `inotify`/`fanotify`-based tools, and it doesn't itself protect the baseline file from tampering — in a real deployment you'd store the baseline somewhere the monitored system can't write to (e.g. signed, or on separate read-only storage).
