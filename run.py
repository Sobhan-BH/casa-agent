#!/usr/bin/env python
"""CASA Launcher — one command to bring the whole agent up.

    python run.py                 # interactive menu (starts lab + API)
    python run.py --demo          # start everything, run lab assessment, exit
    python run.py --target https://example.com [--yes]
                                  # start everything, assess one target, exit
    python run.py --check         # preflight only (deps/ports), no services

What it does:
  1. Preflight: Python version, dependencies (auto-installs from
     requirements.txt if missing), port availability.
  2. Starts the local vulnerable lab (127.0.0.1:8001) and the CASA API
     (127.0.0.1:8000) as managed subprocesses; logs go to data/launcher-*.log.
     If a healthy CASA/lab is already running on those ports it is REUSED.
  3. Interactive menu: run the demo assessment (local lab), assess a custom
     authorized target (with typed-host confirmation), open the Swagger UI,
     open the latest HTML report, run tests / the validation harness.
  4. On exit (menu quit or Ctrl+C) both services are terminated cleanly.

Safety: the launcher never edits scope logic; every assessment still passes
the same Authorization Gate. Custom targets require typing the hostname to
confirm you are authorized to assess it.
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
API_PORT = int(os.environ.get("CASA_API_PORT", "8000"))
LAB_PORT = int(os.environ.get("CASA_LAB_PORT", "8001"))
API_URL = f"http://127.0.0.1:{API_PORT}"
LAB_URL = f"http://127.0.0.1:{LAB_PORT}"

REQUIRED_MODULES = [
    "fastapi",
    "uvicorn",
    "httpx",
    "sqlalchemy",
    "aiosqlite",
    "jinja2",
    "pydantic",
    "pydantic_settings",
    "dotenv",
    "multipart",
]


def log(msg: str) -> None:
    print(msg, flush=True)


def http_ok(url: str, timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "casa-launcher"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 500
    except Exception:
        return False


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ----------------------------------------------------------------- preflight
def preflight(auto_install: bool = True) -> bool:
    log("[preflight] python " + sys.version.split()[0])
    if sys.version_info < (3, 10):
        log("[preflight] FAIL: Python 3.10+ required")
        return False

    missing = []
    for mod in REQUIRED_MODULES:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        log(f"[preflight] missing dependencies: {', '.join(missing)}")
        if not auto_install:
            return False
        answer = input("  install from requirements.txt now? [Y/n] ").strip().lower()
        if answer in ("", "y", "yes"):
            rc = subprocess.call(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
            )
            if rc != 0:
                log("[preflight] pip install failed")
                return False
        else:
            return False

    (ROOT / "data" / "reports").mkdir(parents=True, exist_ok=True)
    log("[preflight] dependencies OK")
    return True


# ------------------------------------------------------------------ services
def spawn(name: str, cmd: list[str]) -> subprocess.Popen:
    logfile = ROOT / "data" / f"launcher-{name}.log"
    handle = open(logfile, "ab")
    log(f"[start] {name}: {' '.join(cmd)}")
    log(f"        logs -> {logfile}")
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    return proc


def wait_healthy(url: str, name: str, proc: subprocess.Popen | None, timeout: float = 40.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            log(f"[start] {name} exited early (code {proc.returncode})."
                f" See data/launcher-{name}.log")
            return False
        if http_ok(url):
            log(f"[start] {name} healthy at {url}")
            return True
        time.sleep(0.5)
    log(f"[start] {name} did not become healthy within {timeout:.0f}s")
    return False


def start_services() -> tuple[subprocess.Popen | None, subprocess.Popen | None, list[subprocess.Popen]]:
    """Start lab + API. Reuse already-running healthy services."""
    owned: list[subprocess.Popen] = []
    lab_proc = api_proc = None

    if http_ok(API_URL + "/health"):
        log("[start] CASA API already running — reusing it")
    elif port_in_use(API_PORT):
        log(f"[start] FAIL: port {API_PORT} is busy but not a healthy CASA API."
            " Free the port or set CASA_API_PORT.")
        return None, None, owned
    else:
        api_proc = spawn(
            "api",
            [sys.executable, "-m", "uvicorn", "agent.api.main:app",
             "--host", "127.0.0.1", "--port", str(API_PORT)],
        )
        owned.append(api_proc)
        if not wait_healthy(API_URL + "/health", "api", api_proc):
            return api_proc, None, owned

    if http_ok(LAB_URL + "/"):
        log("[start] vulnerable lab already running — reusing it")
    elif port_in_use(LAB_PORT):
        log(f"[start] FAIL: port {LAB_PORT} is busy but not the lab."
            " Free the port or set CASA_LAB_PORT.")
        return api_proc, None, owned
    else:
        lab_proc = spawn(
            "lab",
            [sys.executable, "-m", "lab.vulnerable_app"],
        )
        owned.append(lab_proc)
        if not wait_healthy(LAB_URL + "/", "lab", lab_proc):
            return api_proc, lab_proc, owned

    return api_proc, lab_proc, owned


def shutdown(owned: list[subprocess.Popen]) -> None:
    for proc in owned:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + 8
    for proc in owned:
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.2)
        if proc.poll() is None:
            proc.kill()
    if owned:
        log("[shutdown] services stopped")


# -------------------------------------------------------------------- actions
def run_script(cmd: list[str]) -> int:
    log("")
    rc = subprocess.call(cmd, cwd=str(ROOT))
    log("")
    return rc


def latest_report() -> Path | None:
    reports = sorted((ROOT / "data" / "reports").glob("*.html"), key=os.path.getmtime)
    return reports[-1] if reports else None


def open_in_browser(path: Path) -> None:
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            webbrowser.open(f"file://{path}")
        log(f"[open] {path}")
    except Exception as exc:  # noqa: BLE001
        log(f"[open] failed: {exc} — open manually: {path}")


def choose_profile() -> str:
    """Ask the user which assessment profile to run."""
    log("  profile: [1] QUICK (fast, passive)  [2] STANDARD (full web)  [3] DEEP (+tools & active-safe)")
    choice = input("  profile select> ").strip() or "2"
    return {"1": "QUICK", "2": "STANDARD", "3": "DEEP"}.get(choice, "STANDARD")


def assess_target(target: str | None, assume_yes: bool, profile: str = "STANDARD") -> int:
    if not target:
        target = input("Target URL (https://host you are authorized to test): ").strip()
    parsed = urlparse(target if "://" in target else "https://" + target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        log("[target] invalid URL")
        return 1
    target = f"{parsed.scheme}://{parsed.netloc}"
    log(f"[target] {target} (host: {parsed.hostname}, profile: {profile})")
    if not assume_yes:
        typed = input(f"Type the hostname to confirm you are AUTHORIZED to assess it"
                      f" [{parsed.hostname}]: ").strip()
        if typed != parsed.hostname:
            log("[target] confirmation mismatch — assessment cancelled")
            return 1
    return run_script(
        [sys.executable, "scripts/demo_assessment.py", target, "--profile", profile]
    )


# ---------------------------------------------------------------------- menu
def show_tools_status() -> None:
    """Security Tools panel (dashboard equivalent)."""
    import json
    import urllib.request

    try:
        req = urllib.request.Request(API_URL + "/api/v1/tools",
                                     headers={"User-Agent": "casa-launcher"})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = json.loads(r.read().decode())
    except Exception as exc:  # noqa: BLE001
        log(f"[tools] unavailable ({exc})")
        return
    log("")
    log(" Security Tools:")
    marker = {"READY": "[OK] ", "NOT_INSTALLED": "[--] ", "DISABLED": "[off]"}
    for name, t in body.get("tools", {}).items():
        log(f"   {name:<16} {marker.get(t['status'], '[??] ')}{t['status']}")
    log("   (missing tools are skipped by assessments — install to enable)")


def menu(api_proc, lab_proc) -> None:
    while True:
        log("")
        log("=" * 62)
        log(f" CASA is up.  API: {API_URL}   Lab: {LAB_URL}")
        log("=" * 62)
        log("  [1] Run demo assessment (local vulnerable lab)")
        log("  [2] Assess a custom authorized target")
        log("  [3] Open Swagger UI (API docs)")
        log("  [4] Open latest HTML report")
        log("  [5] Security Tools status")
        log("  [6] Run test suite (pytest)")
        log("  [7] Run validation harness (scripts/validate.py)")
        log("  [8] Show service logs (last 15 lines)")
        log("  [0] Quit")
        try:
            choice = input("select> ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "1":
            run_script([sys.executable, "scripts/demo_assessment.py",
                        "--profile", choose_profile()])
        elif choice == "2":
            assess_target(None, assume_yes=False, profile=choose_profile())
        elif choice == "3":
            webbrowser.open(API_URL + "/docs")
            log("[open] " + API_URL + "/docs")
        elif choice == "4":
            rpt = latest_report()
            if rpt:
                open_in_browser(rpt)
            else:
                log("[open] no reports yet — run an assessment first")
        elif choice == "5":
            show_tools_status()
        elif choice == "6":
            run_script([sys.executable, "-m", "pytest", "tests/", "-q"])
        elif choice == "7":
            run_script([sys.executable, "scripts/validate.py"])
        elif choice == "8":
            for name in ("api", "lab"):
                f = ROOT / "data" / f"launcher-{name}.log"
                log(f"--- {name} ({f}) ---")
                if f.exists():
                    lines = f.read_text(errors="replace").splitlines()[-15:]
                    log("\n".join(lines) if lines else "(empty)")
        elif choice == "0":
            return


def main() -> int:
    parser = argparse.ArgumentParser(description="CASA one-command launcher")
    parser.add_argument("--demo", action="store_true",
                        help="start services, run the lab assessment, then exit")
    parser.add_argument("--target", metavar="URL",
                        help="start services, assess this authorized target, then exit")
    parser.add_argument("--profile", default="STANDARD",
                        choices=["QUICK", "STANDARD", "DEEP"],
                        help="assessment profile for --demo/--target (default STANDARD)")
    parser.add_argument("--yes", action="store_true",
                        help="skip the typed-host authorization confirmation (automation)")
    parser.add_argument("--check", action="store_true",
                        help="preflight checks only; do not start services")
    parser.add_argument("--tools", action="store_true",
                        help="print the Security Tools status table and exit (services must be up)")
    args = parser.parse_args()

    if args.check:
        return 0 if preflight(auto_install=False) else 1
    if not preflight(auto_install=True):
        return 1

    api_proc, lab_proc, owned = start_services()
    if args.tools:
        try:
            show_tools_status()
            return 0
        finally:
            shutdown(owned if (api_proc or lab_proc) else [])
    if api_proc is None and not http_ok(API_URL + "/health"):
        shutdown(owned)
        return 1
    try:
        if args.demo:
            return run_script([sys.executable, "scripts/demo_assessment.py",
                               "--profile", args.profile])
        if args.target:
            return assess_target(args.target, assume_yes=args.yes, profile=args.profile)
        menu(api_proc, lab_proc)
        return 0
    finally:
        shutdown(owned)


if __name__ == "__main__":
    sys.exit(main())
