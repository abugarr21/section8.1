#!/usr/bin/env python3
"""
section8.1 — update-focused diagnostic scanner (observe-only)

This is the "bigger brother" of the section8 / OCAM Level-1 scanner.
It focuses on collecting update-relevant signals for a Python/systemd application stack:

  - Node identity & roles
  - Python / venv reality
  - Application file layout & hashes (root folder)
  - systemd wiring for app / updater / agent units
  - Updater inventory (plans/bundles) + health
  - HTTP endpoint probes (optional)

IMPORTANT:
  - All output is written ONLY under the folder this script lives in:
        <script_dir>/data-logs/
    so scans never touch Caelus/SUFI disks.
"""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TS = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sh(cmd: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """Run a shell command, return (rc, stdout, stderr)."""
    p = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return 124, out, err


class Writer:
    """Writer matching section8-style layout, but rooted at PU-Key."""

    def __init__(self, base_outdir: Path, node: str):
        """
        base_outdir: e.g. <PU-Key>/section8.1/data-logs
        epoch dir:   <base_outdir>/<node>_<timestamp>/
        """
        self.base_outdir = base_outdir
        self.base_outdir.mkdir(parents=True, exist_ok=True)

        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        dirname = f"{node}_{ts}"
        self.epoch_dir = self.base_outdir / dirname
        self.epoch_dir.mkdir(parents=True, exist_ok=True)

        self.jsonl = self.epoch_dir / "diag.jsonl"
        self.summary = self.epoch_dir / "summary.txt"
        self.sha = self.epoch_dir / "SHA256SUMS"
        self._lines = 0

    def jl(self, obj: Dict[str, Any]) -> None:
        if "ts" not in obj:
            obj["ts"] = TS()
        with self.jsonl.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._lines += 1

    def add_summary(self, text: str) -> None:
        with self.summary.open("a", encoding="utf-8") as f:
            f.write(text.rstrip() + "\n")

    def finalize(self) -> None:
        # symlinks (best-effort) next to data-logs root
        try:
            for name, src in [
                ("latest.jsonl", self.jsonl),
                ("latest.summary.txt", self.summary),
            ]:
                dst = self.base_outdir / name
                if dst.exists() or dst.is_symlink():
                    dst.unlink()
                # symlink to epoch-relative path
                dst.symlink_to(src.relative_to(self.base_outdir))
        except Exception:
            pass

        # SHA256SUMS inside the epoch dir
        with self.sha.open("w", encoding="utf-8") as f:
            for p in sorted(self.epoch_dir.rglob("*")):
                if p.is_file():
                    try:
                        h = hashlib.sha256()
                        with p.open("rb") as pf:
                            for chunk in iter(lambda: pf.read(65536), b""):
                                h.update(chunk)
                        rel = p.relative_to(self.epoch_dir)
                        f.write(f"{h.hexdigest()}  {rel}\n")
                    except Exception:
                        continue


def rec(
    node: str,
    id: str,
    sev: str,
    ok: bool,
    **details: Any,
) -> Dict[str, Any]:
    return {
        "ts": TS(),
        "node": node,
        "id": id,
        "sev": sev,
        "ok": bool(ok),
        "details": details or None,
    }


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def detect_node_name(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("HBAI_NODE")
    if env:
        return env
    return socket.gethostname()


def check_node_identity(node: str, root: Path) -> Dict[str, Any]:
    hostname = socket.gethostname()
    roles: List[str] = []

    # crude role detection based on presence of files
    if (root / "updater" / "updater_server.py").exists():
        roles.append("hbai-core")
        roles.append("updater-server")
    if (root / "edge").exists():
        roles.append("edge-node")

    version_file = (root / "VERSION")
    version = None
    if version_file.exists():
        try:
            version = version_file.read_text(encoding="utf-8").strip()
        except Exception:
            version = None

    return rec(
        node,
        "node.identity",
        "info",
        True,
        hostname=hostname,
        roles=roles,
        hbai_version=version,
    )


def check_python_stack(node: str, root: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    rc, ver_out, ver_err = sh("python3 --version")
    out.append(
        rec(
            node,
            "python.version",
            "info",
            rc == 0,
            cmd="python3 --version",
            rc=rc,
            stdout=ver_out.strip(),
            stderr=ver_err.strip(),
        )
    )

    rc, which_out, which_err = sh("which python3")
    out.append(
        rec(
            node,
            "python.which",
            "info",
            rc == 0,
            cmd="which python3",
            rc=rc,
            stdout=which_out.strip(),
            stderr=which_err.strip(),
        )
    )

    venv = (root / ".venv")
    if venv.exists():
        rc, v_ver, v_err = sh(f"{venv}/bin/python --version")
        out.append(
            rec(
                node,
                "python.venv",
                "info",
                rc == 0,
                path=str(venv),
                rc=rc,
                stdout=v_ver.strip(),
                stderr=v_err.strip(),
            )
        )
    else:
        out.append(
            rec(
                node,
                "python.venv",
                "warn",
                False,
                path=str(venv),
                error="venv_missing",
            )
        )

    return out


def _file_info(p: Path) -> Dict[str, Any]:
    try:
        st = p.stat()
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return {
            "path": str(p),
            "size": st.st_size,
            "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
            "sha256": h.hexdigest(),
        }
    except Exception as e:
        return {"path": str(p), "error": str(e)}


def check_app_files(node: str, root: Path) -> List[Dict[str, Any]]:
    app_root = root / "app"
    upd_root = root / "updater"

    critical_app = [
        "main.py",
        "tracs_logger.py",
        "context_short.py",
    ]
    critical_upd = [
        "apply_plan.py",
        "updater_server.py",
    ]

    files_app: List[Dict[str, Any]] = []
    files_upd: List[Dict[str, Any]] = []

    if app_root.exists():
        for name in critical_app:
            p = app_root / name
            if p.exists():
                files_app.append(_file_info(p))
            else:
                files_app.append({"path": str(p), "error": "missing"})
    else:
        files_app.append({"path": str(app_root), "error": "root_missing"})

    if upd_root.exists():
        for name in critical_upd:
            p = upd_root / name
            if p.exists():
                files_upd.append(_file_info(p))
            else:
                files_upd.append({"path": str(p), "error": "missing"})
    else:
        files_upd.append({"path": str(upd_root), "error": "root_missing"})

    return [
        rec(node, "fs.hbai_app", "info", True, root=str(app_root), files=files_app),
        rec(node, "fs.hbai_updater", "info", True, root=str(upd_root), files=files_upd),
    ]


def _systemd_show(unit: str) -> Dict[str, Any]:
    rc, out, err = sh(
        f"systemctl show --no-page --property=Id,LoadState,ActiveState,SubState,FragmentPath,ExecStart {unit}"
    )
    return {
        "rc": rc,
        "stdout": out.strip(),
        "stderr": err.strip(),
    }


def check_systemd(node: str, units: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for unit in units:
        info = _systemd_show(unit)
        ok = info["rc"] == 0
        sev = "info" if ok else "warn"
        out.append(
            rec(
                node,
                f"systemd.{unit}",
                sev,
                ok,
                unit=unit,
                **info,
            )
        )
    return out


def check_updater_inventory(node: str, root: Path, updater_health_url: str) -> List[Dict[str, Any]]:
    upd_root = root / "updater"
    plans_dir = upd_root / "plans"
    bundles_dir = upd_root / "bundles"

    plans = sorted([p.name for p in plans_dir.glob("*")]) if plans_dir.exists() else []
    bundles = (
        sorted([p.name for p in bundles_dir.glob("*")]) if bundles_dir.exists() else []
    )

    inv = rec(
        node,
        "updater.inventory",
        "info",
        True,
        root=str(upd_root),
        plans=plans,
        bundles=bundles,
    )

    # health check (updater HTTP)
    rc, out, err = sh(
        f"curl -s -o /dev/null -w '%{{http_code}}' {updater_health_url}",
        timeout=5,
    )
    ok = rc == 0 and out.strip().isdigit() and int(out.strip()) == 200
    health = rec(
        node,
        "updater.health",
        "info" if ok else "warn",
        ok,
        url=updater_health_url,
        rc=rc,
        http_code=out.strip(),
        stderr=err.strip(),
    )

    return [inv, health]


def _http_probe(url: str, timeout: int = 5) -> Dict[str, Any]:
    rc, out, err = sh(
        f"curl -s -o /dev/null -w '%{{http_code}}' {url}",
        timeout=timeout,
    )
    ok = rc == 0 and out.strip().isdigit()
    code = int(out.strip()) if out.strip().isdigit() else None
    return {
        "rc": rc,
        "http_code": code,
        "stderr": err.strip(),
        "ok": ok and (code is not None),
    }


def check_http_endpoints(node: str, endpoints: List[Tuple[str,str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for id_name, url in endpoints:
        info = _http_probe(url)
        sev = "info" if info["ok"] else "warn"
        out.append(
            rec(
                node,
                id_name,
                sev,
                info["ok"],
                url=url,
                rc=info["rc"],
                http_code=info["http_code"],
                stderr=info["stderr"],
            )
        )
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def run_section8_1(
    node: str,
    base_outdir: Path,
    root: Path,
    units: List[str],
    endpoints: List[Tuple[str, str]],
    updater_health_url: str,
    do_http: bool = True,
) -> None:
    """Run the section8.1 diagnostic sweep and write results under base_outdir/node/*.

    This tool is observe-only: it shells out to read state, inspects files, and optionally probes HTTP endpoints.
    """
    w = Writer(base_outdir, node)

    records: List[Dict[str, Any]] = []

    # 1) Node identity / role hints
    records.append(check_node_identity(node, root))

    # 2) Python / venv
    records.extend(check_python_stack(node, root))

    # 3) App file layout & hashes
    records.extend(check_app_files(node, root))

    # 4) systemd wiring
    records.extend(check_systemd(node, units))

    # 5) Updater inventory + health (best-effort)
    records.extend(check_updater_inventory(node, root, updater_health_url))

    # 6) HTTP endpoints (optional)
    if do_http and endpoints:
        records.extend(check_http_endpoints(node, endpoints))

    # write JSONL
    for r in records:
        w.jl(r)

    # summary
    ok_count = sum(1 for r in records if r.get("ok") is True)
    total = len(records)
    w.add_summary(f"section8.1 diag for node={node}")
    w.add_summary(f"root={root}")
    w.add_summary(f"records: {total}, ok: {ok_count}, bad: {total - ok_count}")
    w.finalize()


def main() -> None:
    here = Path(__file__).resolve().parent
    default_out = here / "data-logs"
    default_root = os.environ.get("SECTION81_ROOT") or os.environ.get("HBAI_ROOT") or "/opt/hbai"

    ap = argparse.ArgumentParser(
        description="section8.1 — observe-only diagnostic sweep (systemd + files + optional HTTP probes)"
    )
    ap.add_argument(
        "--node",
        help="Node name override (default: hostname or $HBAI_NODE)",
        default=None,
    )
    ap.add_argument(
        "--root",
        help="Application root directory to inspect (default: $SECTION81_ROOT or $HBAI_ROOT or /opt/hbai)",
        default=default_root,
    )
    ap.add_argument(
        "--out",
        help="Output directory (default: <script_dir>/data-logs). Recommended: a removable drive.",
        default=str(default_out),
    )
    ap.add_argument(
        "--allow-any-out",
        action="store_true",
        help="Allow --out outside the script directory (disabled by default for safety).",
    )
    ap.add_argument(
        "--unit",
        action="append",
        default=None,
        help="systemd unit to inspect (repeatable). If omitted, uses $SECTION81_UNITS or common defaults.",
    )
    ap.add_argument(
        "--endpoint",
        action="append",
        default=None,
        help="HTTP endpoint probe in the form name=url (repeatable). If omitted, uses $SECTION81_ENDPOINTS or defaults.",
    )
    ap.add_argument(
        "--no-http",
        action="store_true",
        help="Skip HTTP endpoint probes.",
    )
    ap.add_argument(
        "--updater-health-url",
        default=os.environ.get("SECTION81_UPDATER_HEALTH_URL") or "http://127.0.0.1:8082/api/health",
        help="Updater health URL (default: http://127.0.0.1:8082/api/health).",
    )
    args = ap.parse_args()

    node = detect_node_name(args.node)
    root = Path(args.root).expanduser().resolve()
    base_outdir = Path(args.out).expanduser().resolve()

    # Safety: by default, keep writes under the script directory.
    if not args.allow_any_out:
        try:
            base_outdir.relative_to(here)
        except Exception:
            raise SystemExit(
                f"Refusing to write outside script dir without --allow-any-out: out={base_outdir}"
            )

    # units
    env_units = os.environ.get("SECTION81_UNITS")
    units = args.unit or (env_units.split(",") if env_units else ["hbai.service", "hbai-updater.service", "hbai-edge-agent.service"])

    # endpoints
    def parse_endpoint(spec: str) -> Tuple[str, str]:
        if "=" in spec:
            name, url = spec.split("=", 1)
            return name.strip(), url.strip()
        return spec.strip(), spec.strip()

    endpoints: List[Tuple[str, str]] = []
    if args.endpoint:
        endpoints = [parse_endpoint(s) for s in args.endpoint]
    else:
        env_eps = os.environ.get("SECTION81_ENDPOINTS")
        if env_eps:
            endpoints = [parse_endpoint(s) for s in env_eps.split(",") if s.strip()]
        else:
            # reasonable defaults for a localhost app + updater; safe to disable with --no-http
            endpoints = [
                ("app_health", "http://127.0.0.1:8081/api/ping"),
                ("app_ctx_current", "http://127.0.0.1:8081/api/context/current"),
                ("updater_health", "http://127.0.0.1:8082/api/health"),
            ]

    run_section8_1(
        node=node,
        base_outdir=base_outdir,
        root=root,
        units=[u for u in units if u],
        endpoints=endpoints,
        updater_health_url=args.updater_health_url,
        do_http=not args.no_http,
    )


if __name__ == "__main__":
    main()

