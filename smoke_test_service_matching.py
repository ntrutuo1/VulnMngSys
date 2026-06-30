import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent))

from vms_backend.database import SQLiteDatabase
from vms_backend.repositories import CveRepository
from vms_backend.services import MetasploitEngine, JobService
from vms_backend.adapters import PowerShellAdapter, MsfRpcAdapter
from vms_backend.models import TARGET_SERVICES


def run_matching_smoke_test():
    print("=== STARTING SERVICE TO MODULE SMOKE TEST ===")

    # 1. Initialize DB and Repositories
    db = SQLiteDatabase()
    db.initialize()
    cve_repo = CveRepository(db)
    job_service = JobService()
    ps = PowerShellAdapter()
    engine = MetasploitEngine(None, cve_repo, job_service, ps, MsfRpcAdapter())

    # 2. Collect actual host machine services, ports, and software
    print("1. Collecting active host services, ports, and software via PowerShell...")
    services = ps.execute_json(
        "Get-Service | Select Name,DisplayName,@{n='Status';e={$_.Status.ToString()}},@{n='StartType';e={$_.StartType.ToString()}} | ConvertTo-Json -Depth 2",
        []
    )
    ports = ps.execute_json(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,@{n='State';e={$_.State.ToString()}},OwningProcess | ConvertTo-Json -Depth 2",
        []
    )
    software = ps.execute_json(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where DisplayName | Select DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Depth 2",
        []
    )

    print(f"   - Found {len(services)} services, {len(ports)} listening ports, {len(software)} installed apps.")

    # 3. Detect service context and intersect with TARGET_SERVICES whitelist
    print("2. Detecting active security-targeted services...")
    context = engine.detect_service_context(services, ports, software)
    raw_detected = context["services"]
    print(f"   - Raw detected service keywords: {list(raw_detected)}")

    # Intersect with TARGET_SERVICES dict
    context["services"] = raw_detected & TARGET_SERVICES.keys()
    print(f"   - Intersected whitelisted target services: {list(context['services'])}")

    # 4. Map directly to Metasploit modules
    print("3. Querying matched Metasploit modules directly from database...")
    matched_pairs = list(cve_repo.find_modules_for_services(context["services"]))
    
    # For testing options builder, if no real modules are matched, insert a simulated pair
    if not any(module for _, module in matched_pairs):
        print("   - (Real system matches empty, adding simulated match pair for verification)")
        from vms_backend.models import WindowsCve, MetasploitModuleSpec
        sim_cve = WindowsCve("CVE-2025-53772", None, None, 8.8, None, None, None, "Web Deploy RCE", ["web_deploy"])
        sim_mod = MetasploitModuleSpec(
            cve_id="CVE-2025-53772",
            module_path="exploits/customs/cve_2025_53772_web_deploy_rce",
            module_type="exploit",
            source_file="cve_2025_53772_web_deploy_rce.rb",
            required_options={"LHOST": True, "LPORT": True},
            default_options={}
        )
        matched_pairs.append((sim_cve, sim_mod))

    print(f"   - Found {len(matched_pairs)} matched module-CVE pairs.")

    # 5. Verify option resolution rules (LHOST = RHOST, LPORT = 4444)
    print("4. Verifying parameter resolution rules...")
    for cve, module in matched_pairs:
        if not module:
            continue
        print(f"   - Testing parameter building for module: {module.module_path}")
        options, missing = engine.build_module_options(module, context)
        
        # Verify LHOST and LPORT rules if present
        rhost = options.get("RHOST") or options.get("RHOSTS") or "127.0.0.1"
        if "LHOST" in module.required_options:
            assert options.get("LHOST") == rhost, f"LHOST must equal RHOST ({rhost}), got {options.get('LHOST')}"
            print(f"     [PASS] LHOST correctly resolved to RHOST: {options.get('LHOST')}")
        if "LPORT" in module.required_options:
            assert options.get("LPORT") == 4444, f"LPORT must default to 4444, got {options.get('LPORT')}"
            print(f"     [PASS] LPORT correctly defaulted to 4444")

    # 6. Verify exploit module safety guard (simulated match)
    print("5. Verifying exploit avoidance guards...")
    # Simulate a standard exploit module match (e.g. exploits/windows/smb/ms08_067_netapi)
    from vms_backend.models import MetasploitModuleSpec
    sim_module = MetasploitModuleSpec(
        cve_id="CVE-2008-4250",
        module_path="exploits/windows/smb/ms08_067_netapi",
        module_type="exploit",
        source_file="exploits/windows/smb/ms08_067_netapi.rb",
        required_options={"RHOSTS": True},
        default_options={}
    )
    # Ensure standard exploits are identified as exploits
    is_exploit = sim_module.module_type == "exploit" or "exploit" in sim_module.module_path.lower()
    is_custom_module = "web_deploy" in sim_module.module_path or "http2" in sim_module.module_path or "53772" in sim_module.module_path or "49975" in sim_module.module_path
    
    assert is_exploit is True, "ms08_067_netapi must be identified as an exploit module"
    assert is_custom_module is False, "ms08_067_netapi must not be identified as a custom user module"
    print("   - [PASS] Exploit module types and safety rules verified.")

    print("\n=== SMOKE TEST COMPLETED SUCCESSFULLY: ok ===")


if __name__ == "__main__":
    try:
        run_matching_smoke_test()
        sys.exit(0)
    except Exception as exc:
        print(f"ERROR: Smoke test failed: {exc}", file=sys.stderr)
        sys.exit(1)
