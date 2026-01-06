# section8.1 diag (portable)

An **observe-only** diagnostic sweep that captures update-relevant system state into a **timestamped JSONL log + summary**.

It’s designed to be:
- **system-agnostic** (root path, systemd units, and HTTP probes are configurable)
- **safe** (no mutations; read-only shell-outs + file hashing)
- **useful for remote debugging / upgrades** (you can attach a single folder to a bug report)

## Requirements
- Python 3.9+ (tested on 3.12)
- Linux (uses `systemctl`, `journalctl`, `ip`, `ss`, etc.)
- Optional: a local HTTP service you want probed

## Quick start (one command)

From the folder containing `section8_1_diag.py`:

```bash
python3 section8_1_diag.py --allow-any-out --out ./data-logs
```

Outputs land under:

```
./data-logs/<node>/<timestamp>/
  section8_1_diag.jsonl
  summary.txt
  SHA256SUMS
```

## Target a specific application root
By default, the tool inspects `$SECTION81_ROOT` (or `$HBAI_ROOT`) and falls back to `/opt/hbai`.

```bash
python3 section8_1_diag.py --allow-any-out --root /opt/myapp --out ./data-logs
```

## Customize what gets checked

### systemd units
Repeat `--unit` to inspect additional units:

```bash
python3 section8_1_diag.py --allow-any-out \
  --unit myapp.service \
  --unit myapp-worker.service \
  --out ./data-logs
```

Or set:

```bash
export SECTION81_UNITS="myapp.service,myapp-worker.service"
```

### HTTP probes
Repeat `--endpoint name=url`:

```bash
python3 section8_1_diag.py --allow-any-out \
  --endpoint app_health=http://127.0.0.1:8080/health \
  --endpoint metrics=http://127.0.0.1:8080/metrics \
  --out ./data-logs
```

Skip HTTP entirely:

```bash
python3 section8_1_diag.py --allow-any-out --no-http --out ./data-logs
```

### “Critical files” (optional hints)
By default, it checks for `main.py` under `<root>/app/` and `updater_server.py` under `<root>/updater/`.

Override:

```bash
export SECTION81_APP_FILES="main.py,app.py,pyproject.toml"
export SECTION81_UPDATER_FILES="updater.py,updater_server.py"
```

## Notes
- This is a **diagnostic**. If a check doesn’t apply on your machine, you’ll typically see it recorded as “missing” rather than crashing.
- The output JSONL is meant to be machine-readable and diffable across runs.
How to Use This Tool (and When)
What this tool is for

section8_1_diag.py is an observe-only diagnostic probe.

Personal notes about this tool:

It is designed to answer one question reliably:

“What is this system actually doing right now?”

It does not:

change configuration

restart services

attempt remediation

interpret intent or correctness

It only records factual state as it exists at runtime.

This makes it suitable for:

validating documentation against reality

capturing pre-change / post-change system snapshots

debugging “works on my machine” discrepancies

auditing systems you did not design or fully trust

preserving evidence before maintenance, upgrades, or outages

Typical workflow

Run the probe

python3 section8_1_diag.py --out ./data-logs


Inspect the outputs

section8_1_diag.jsonl → raw, timestamped evidence

summary.txt → human-readable overview

SHA256SUMS → integrity verification

Compare runs

Run before and after a change

Diff the JSONL or summaries

Use hashes to prove nothing was altered

Running from anywhere (CLI-style use)

This tool is intentionally safe to run from any directory.

If you want a “grep-like” experience (run it wherever you are):

python3 /path/to/section8_1_diag.py --root . --out ./data-logs


This captures the current working directory as the observation root and writes results locally.

Selecting specific targets

You can narrow what gets observed without modifying the system:

python3 section8_1_diag.py \
  --unit myservice.service \
  --endpoint health=http://127.0.0.1:8080/health \
  --out ./data-logs


This is useful when:

focusing on a single subsystem

capturing evidence during an incident

reducing output noise for review

Design philosophy (important)

This tool follows three strict rules:

No mutation
Observation must never change the system being observed.

No interpretation
Output is evidence, not conclusions.

No hidden behavior
Everything it does is visible in the output.

If a system cannot tolerate being observed, that fact itself is meaningful.
