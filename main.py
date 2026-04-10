#!/usr/bin/env python3
"""
main.py — OpenElia CLI entry point.
"""

import argparse
import asyncio
import os
import sys
import subprocess  # nosec: B404
import shutil
import json
import http.client
from urllib.parse import urlparse
import ipaddress
import hashlib
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv
from secret_store import SecretStore

load_dotenv()


def print_openelia_banner():
    # ANSI Colors: White (Logo), Dark Gray (Borders), Green (Highlights), Reset
    W = "\033[1;37m"
    DG = "\033[1;30m"
    G = "\033[1;32m"
    R = "\033[0m"

    banner = f"""
{W}   ____                   _______ __      
  / __ \\____  ___  ____  / ____/ (_)___ _ 
 / / / / __ \\/ _ \\/ __ \\/ __/ / / / __ `/ 
/ /_/ / /_/ /  __/ / / / /___/ / / /_/ /  
\\____/ .___/\\___/_/ /_/_____/_/_/\\__,_/   
    /_/                                   {R}
    
    {DG}Operations Framework | Version 1.0{R}
    
    {DG}--------------------------------------------------{R}
    [ {G}Initialization{R} ] Core Modules Loaded
    {DG}--------------------------------------------------{R}
    
    Goal:    Initialize defensive agents.
    Connect: Type 'help' to view available modules.
    """
    print(banner)


def _is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _check_ollama() -> bool:
    base_url = SecretStore.get_secret("OLLAMA_BASE_URL") or "http://localhost:11434/v1"
    try:
        url = f"{base_url}/models"
        if not _is_safe_url(url):
            return False

        parsed = urlparse(url)
        conn = http.client.HTTPConnection(parsed.netloc, timeout=3) if parsed.scheme == "http" else http.client.HTTPSConnection(parsed.netloc, timeout=3)
        conn.request("GET", parsed.path or "/")
        response = conn.getresponse()
        return 200 <= response.status < 400
    except Exception:
        return False


def _require_api_key() -> None:
    if not _check_ollama():
        base_url = SecretStore.get_secret("OLLAMA_BASE_URL") or "http://localhost:11434/v1"
        print(f"ERROR: Ollama is not reachable at {base_url}.")
        print("Make sure Ollama is running: ollama serve")
        sys.exit(1)


async def cmd_check(args) -> None:
    """Tier 2: Operational Readiness Check"""
    print("🛡️ OpenElia Core Operational Readiness Check")
    print("="*40)
    
    overall_pass = True

    # 1. Docker Check
    print("[ ] Checking Docker...", end="\r")
    try:
        import docker
        client = docker.from_env()
        client.ping()
        print(f"[✓] Docker: Running")
        
        # Check image
        try:
            client.images.get("cyber-ops-recon:strict")
            print(f"    [✓] Image 'cyber-ops-recon:strict': Found")
        except:
            print(f"    [✗] Image 'cyber-ops-recon:strict': Not found (Run: python main.py doctor)")
            overall_pass = False
    except Exception as e:
        print(f"[✗] Docker: Error ({str(e)})")
        overall_pass = False

    # 2. Ollama Check
    print("[ ] Checking Ollama...", end="\r")
    if _check_ollama():
        model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
        print(f"[✓] Ollama: Reachable (Target Model: {model})")
    else:
        print(f"[✗] Ollama: Not reachable at {os.environ.get('OLLAMA_BASE_URL', 'localhost')}")
        overall_pass = False

    # 3. Connectivity Check
    print("[ ] Checking CVE Intel API...", end="\r")
    try:
        intel_url = "https://cve.circl.lu/api/browse"
        if _is_safe_url(intel_url):
            parsed = urlparse(intel_url)
            conn = http.client.HTTPSConnection(parsed.netloc, timeout=5)
            conn.request("GET", parsed.path or "/")
            response = conn.getresponse()
            if 200 <= response.status < 400:
                print(f"[✓] Intel API: Reachable (cve.circl.lu)")
            else:
                print(f"[✗] Intel API: Not reachable")
                overall_pass = False
        else:
            print(f"[✗] Intel API: Unsafe URL detected")
            overall_pass = False
    except Exception:
        print(f"[✗] Intel API: Not reachable")
    # 4. Permissions Check
    print("[ ] Checking Permissions...", end="\r")
    paths = ["state", "artifacts", "mcp_servers"]
    perm_pass = True
    for p in paths:
        if not os.access(p, os.W_OK):
            print(f"    [✗] Write access denied: {p}")
            perm_pass = False
            overall_pass = False
    if perm_pass:
        print(f"[✓] Permissions: Write access confirmed for core directories")

    # 5. RBAC Check
    print("[ ] Checking RBAC Status...", end="\r")
    from rbac_manager import RBACManager
    is_admin = RBACManager.is_os_admin()
    has_idp = os.path.exists("state/idp_session.json")
    status = "Admin" if is_admin else "User"
    print(f"[✓] RBAC: Running as {status} | IdP Session: {'Found' if has_idp else 'Missing'}")

    print("="*40)
    if overall_pass:
        print("✅ SYSTEM READY")
    else:
        print("❌ SYSTEM NOT READY - Fix the errors above or run 'python main.py doctor'.")
        sys.exit(1)


async def cmd_red(args) -> None:
    from state_manager import StateManager
    from orchestrator import Orchestrator
    state = StateManager()
    
    targets = [args.target] if args.target else []
    if args.target and "/" in args.target:
        try:
            network = ipaddress.ip_network(args.target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            print(f"[*] Expanded CIDR {args.target} into {len(targets)} targets.")
        except ValueError:
            pass

    if not args.resume:
        if not targets:
            print("ERROR: --target is required for a new engagement.")
            sys.exit(1)
        
        for target in targets:
            scope = args.scope or "Authorized engagement"
            state.initialize_engagement(target, scope)
            print(f"[main] Engagement initialized — target: {target}")

    _require_api_key()
    orch = Orchestrator(state)
    
    if args.passive:
        from agents.red.pentester_recon import PentesterRecon
        for target in targets:
            recon = PentesterRecon(state, brain_tier=args.brain_tier)
            await recon.run_passive(
                task=args.task or "Passive OSINT reconnaissance",
                target=target,
            )
    else:
        task = args.task or "Full penetration test"
        await orch.route(task, targets=targets, stealth=args.stealth, proxy_port=args.proxy_port, brain_tier=args.brain_tier, apt_profile=args.apt)


async def cmd_blue(args) -> None:
    _require_api_key()
    from state_manager import StateManager
    from agents.blue.defender_os import DefenderOS
    state = StateManager()
    log_text = ""
    if args.logs:
        log_path = Path(args.logs)
        if not log_path.exists():
            print(f"ERROR: Log file not found: {args.logs}")
            sys.exit(1)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
    if args.log_text:
        log_text = (log_text + "\n" + args.log_text).strip()
    blue_os = DefenderOS(state, brain_tier=args.brain_tier)
    await blue_os.analyze_logs(log_text=log_text)


async def cmd_status(args) -> None:
    from state_manager import StateManager
    from orchestrator import Orchestrator
    state = StateManager()
    if not state.read():
        print("No active engagement.")
        return
    orch = Orchestrator(state)
    orch._print_status()


async def cmd_clear(args) -> None:
    from state_manager import StateManager
    state = StateManager()
    if state.read():
        if args.force:
            state.clear()
            print("[main] Engagement state cleared (forced).")
            return
        confirm = input("Clear current engagement state? [y/N]: ").strip().lower()
        if confirm == "y":
            state.clear()
            print("[main] Engagement state cleared.")
        else:
            print("[main] Cancelled.")
    else:
        print("[main] No state to clear.")


async def cmd_nmap(args) -> None:
    from state_manager import StateManager
    from agents.red.pentester_recon import PentesterRecon
    state = StateManager()
    recon = PentesterRecon(state, brain_tier=args.brain_tier)
    if not state.read():
        state.initialize_engagement(args.target, "Ad-hoc nmap scan")
    _require_api_key()
    print(f"[main] Running nmap scan for target {args.target}...")
    await recon.run(f"Run nmap scan on {args.target}", stealth=args.stealth, proxy_port=args.proxy_port, apt_profile=args.apt)


def _validate_ip_target(target: str) -> str:
    """Validate target is a valid IP address or CIDR. Returns target on success."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    raise ValueError(f"Invalid target '{target}': must be a valid IP address or CIDR range.")


async def cmd_msf(args) -> None:
    import re
    import tempfile
    from state_manager import StateManager
    state = StateManager()

    try:
        _validate_ip_target(args.target)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    secret = None
    if args.cred_alias:
        secret = SecretStore.get_secret(args.cred_alias)

    # Validate optional msf_args — allow only word chars, spaces, dots, slashes, equals
    msf_extra = args.args or "show options"
    if not re.match(r'^[\w\s\.\-/=,]+$', msf_extra):
        print("ERROR: Invalid metasploit arguments. Only alphanumeric characters and common flags allowed.")
        sys.exit(1)

    # Write commands to a temp resource file instead of injecting via -x flag
    rc_lines = [f"set RHOSTS {args.target}"]
    if secret:
        rc_lines.append(f"set PASSWORD {secret}")
    rc_lines.append(msf_extra)
    rc_lines.append("exit")

    try:
        import docker
        from security_manager import enforce_security_gate
        enforce_security_gate("cmd_msf", args.target, f"msfconsole -r <resource_file> target={args.target}")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', prefix='msf_', delete=False) as tf:
            tf.write("\n".join(rc_lines) + "\n")
            rc_path = tf.name
        os.chmod(rc_path, 0o600)

        try:
            client = docker.from_env()
            container = client.containers.run(
                image="cyber-ops-recon:strict",
                command=["msfconsole", "-q", "-r", "/tmp/msf.rc"],
                volumes={rc_path: {"bind": "/tmp/msf.rc", "mode": "ro"}},
                network="bridge",
                cap_drop=["ALL"],
                cap_add=["NET_RAW"],
                user="nobody",
                auto_remove=True
            )
            output = container.decode('utf-8')
            state.write_agent_result("exploit", "raw_msf", output)
            print(output)
        finally:
            try:
                os.unlink(rc_path)
            except OSError:
                pass
    except Exception as e:
        print(f"ERROR: Metasploit execution failed: {e}")


async def cmd_purple(args) -> None:
    from state_manager import StateManager
    from orchestrator import Orchestrator
    state = StateManager()
    
    targets = [args.target] if args.target else []
    if args.target and "/" in args.target:
        try:
            network = ipaddress.ip_network(args.target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            print(f"[*] Expanded CIDR {args.target} into {len(targets)} targets for simulation.")
        except ValueError:
            pass

    if not args.resume:
        if not targets:
            print("ERROR: --target is required for a new purple team simulation.")
            sys.exit(1)
        for target in targets:
            state.initialize_engagement(target, args.scope or "Authorized engagement")
            print(f"[main] Purple Team engagement initialized — target: {target}")

    _require_api_key()
    orch = Orchestrator(state)
    await orch.run_purple_loop(args.task or "Collaborative Purple Team simulation", targets=targets, stealth=args.stealth, proxy_port=args.proxy_port, brain_tier=args.brain_tier, iterations=args.iterations, apt_profile=args.apt)


async def cmd_dashboard(args) -> None:
    from dashboard import Dashboard
    Dashboard().run()


async def cmd_sbom(args) -> None:
    """Tier 5: Generate Software Bill of Materials (SBOM)"""
    print("[*] Generating OpenElia Software Bill of Materials...")
    bom = {
        "project": "OpenElia",
        "version": "1.0.0-Platinum",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "dependencies": [],
        "infrastructure": [
            {"name": "Docker", "image": "cyber-ops-recon:strict", "base": "python:3.11-alpine"},
            {"name": "SQLite", "role": "State Persistence"},
            {"name": "ChromaDB", "role": "Vector Memory"}
        ]
    }
    if os.path.exists("requirements.txt.lock"):
        with open("requirements.txt.lock", "r") as f:
            for line in f:
                if "==" in line:
                    parts = line.strip().split("==")
                    bom["dependencies"].append({"name": parts[0], "version": parts[1].split()[0]})
    output_path = "state/bom.json"
    with open(output_path, "w") as f:
        json.dump(bom, f, indent=2)
    print(f"✅ SBOM generated at {output_path}")


async def cmd_archive(args) -> None:
    """Tier 4: Package Engagement into a Forensic Case File"""
    import zipfile
    from state_manager import StateManager
    state_mgr = StateManager()
    state = state_mgr.read()
    if not state:
        print("Error: No active engagement to archive.")
        return
    eng_id = state["engagement"]["id"]
    archive_name = f"OpenElia_Case_{eng_id}.zip"
    archive_path = os.path.join("state", archive_name)
    print(f"[*] Packaging Forensic Case File: {archive_name}...")
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        if os.path.exists("state/engagement.db"):
            zipf.write("state/engagement.db", arcname="engagement.db")
        if os.path.exists("state/audit.log"):
            zipf.write("state/audit.log", arcname="audit.log")
        if os.path.exists("state/bom.json"):
            zipf.write("state/bom.json", arcname="bom.json")
        if os.path.exists("artifacts"):
            for root, _, files in os.walk("artifacts"):
                for file in files:
                    if file != ".gitkeep":
                        zipf.write(os.path.join(root, file), arcname=os.path.join("evidence", file))
        # Case Summary
        summary = f"# OpenElia Case Summary\nID: {eng_id}\nTarget: {state['engagement']['target']}\nDate: {datetime.now().isoformat()}"
        zipf.writestr("Case_Summary.md", summary)

    # Master Hash
    sha256_hash = hashlib.sha256()
    with open(archive_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    print(f"✅ Case File successfully packaged at {archive_path}")
    print(f"🔒 Master SHA-256: {sha256_hash.hexdigest()}")


async def cmd_doctor(args) -> None:
    """Tier 2: Automate Environment Repair"""
    print("🩺 OpenElia System Doctor")
    print("="*40)
    try:
        import docker
        client = docker.from_env()
        try:
            client.images.get("cyber-ops-recon:strict")
            print("[✓] Offensive image 'cyber-ops-recon:strict' is present.")
        except:
            print("[!] Offensive image missing. Building now...")
            docker_path = shutil.which("docker")
            if not docker_path:
                raise RuntimeError("Docker executable not found in PATH")
            subprocess.run([docker_path, "build", "-t", "cyber-ops-recon:strict", "-f", "Dockerfile.offensive", "."], check=True)  # nosec: B603
            print("[✓] Offensive image built successfully.")
    except Exception as e:
        print(f"[✗] Docker error: {e}")
    if not os.path.exists("state"):
        os.makedirs("state")
        print("[✓] Created state directory.")
    print("="*40)
    print("✅ Doctor's check complete.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openelia", description="OpenElia — AI-powered pentesting and blue team analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--brain-tier", choices=["local", "expensive"], default="local", help="Intelligence level")
    common.add_argument("--apt", help="Adversary Persona Profile")
    
    sub.add_parser("check", help="Run operational readiness check")
    sub.add_parser("doctor", help="Auto-repair environment issues")
    
    red_p = sub.add_parser("red", parents=[common], help="Run red team pipeline")
    red_p.add_argument("--target")
    red_p.add_argument("--scope")
    red_p.add_argument("--task")
    red_p.add_argument("--passive", action="store_true")
    red_p.add_argument("--resume", action="store_true")
    red_p.add_argument("--stealth", action="store_true")
    red_p.add_argument("--cred-alias")
    red_p.add_argument("--proxy-port", type=int)
    
    blue_p = sub.add_parser("blue", parents=[common], help="Run blue team analysis")
    blue_p.add_argument("--logs")
    blue_p.add_argument("--log-text")
    
    nmap_p = sub.add_parser("nmap", parents=[common], help="Run nmap")
    nmap_p.add_argument("--target", required=True)
    nmap_p.add_argument("--args")
    nmap_p.add_argument("--stealth", action="store_true")
    nmap_p.add_argument("--cred-alias")
    nmap_p.add_argument("--proxy-port", type=int)
    
    msf_p = sub.add_parser("msf", parents=[common], help="Run metasploit")
    msf_p.add_argument("--target", required=True)
    msf_p.add_argument("--args")
    msf_p.add_argument("--cred-alias")
    msf_p.add_argument("--proxy-port", type=int)
    
    sub.add_parser("status", help="Show status")
    sub.add_parser("dashboard", help="Launch live TUI")
    sub.add_parser("sbom", help="Generate SBOM")
    sub.add_parser("archive", help="Package engagement archive")
    
    purple_p = sub.add_parser("purple", parents=[common], help="Run purple team loop")
    purple_p.add_argument("--target")
    purple_p.add_argument("--scope")
    purple_p.add_argument("--task")
    purple_p.add_argument("--stealth", action="store_true")
    purple_p.add_argument("--proxy-port", type=int)
    purple_p.add_argument("--resume", action="store_true")
    purple_p.add_argument("--iterations", type=int, default=2)
    
    clear_p = sub.add_parser("clear", help="Clear state")
    clear_p.add_argument("--force", "-f", action="store_true")
    return parser


def main() -> None:
    print_openelia_banner()
    SecretStore.bootstrap()
    parser = build_parser()
    args = parser.parse_args()
    handlers = {"check": cmd_check, "doctor": cmd_doctor, "red": cmd_red, "blue": cmd_blue, "status": cmd_status, "clear": cmd_clear, "nmap": cmd_nmap, "msf": cmd_msf, "purple": cmd_purple, "dashboard": cmd_dashboard, "sbom": cmd_sbom, "archive": cmd_archive}
    handler = handlers.get(args.command)
    if handler:
        asyncio.run(handler(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
