from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

MODULE_TYPES = {"auxiliary", "exploits", "post"}
NON_WINDOWS_MODULE_PREFIXES = (
    "exploits/aix/",
    "exploits/bsdi/",
    "exploits/freebsd/",
    "exploits/linux/",
    "exploits/osx/",
    "exploits/solaris/",
    "exploits/unix/",
    "post/aix/",
    "post/bsdi/",
    "post/freebsd/",
    "post/linux/",
    "post/osx/",
    "post/solaris/",
    "post/unix/",
)
DEFAULT_FRAMEWORK_ROOTS = (
    Path(r"E:\VulnMngApp\Tools\metasploit-framework\embedded\framework"),
    Path(r"E:\VulnMngSys\metasploit-framework\embedded\framework"),
    Path(r"E:\VulnMngSys\metasploit-framework"),
)

COMPONENT_ALIASES: dict[str, tuple[str, ...]] = {
    "WINDOWS_HOST": ("windows", "win32", "win64", "microsoft windows"),
    "IIS_CORE": ("iis", "microsoft-iis", "w3svc", "internet information services"),
    "HTTP_SYS": ("http.sys", "http_sys", "httpsys", "http server api", "http protocol stack"),
    "WEBDAV": ("webdav", "web-dav", "propfind", "proppatch", "mkcol"),
    "WEBDEPLOY": ("web deploy", "webdeploy", "msdeploy", "wmsvc", "msdepsvc", "8172"),
    "WSUS": ("wsus", "windows server update service", "update services", "8530", "8531"),
    "SMB": ("smb", "samba", "srvsvc", "ms17-010", "eternalblue", "445"),
    "RDP": ("rdp", "remote desktop", "terminal services", "3389", "bluekeep"),
    "WINRM": ("winrm", "wsman", "windows remote management", "5985", "5986"),
    "AD_CS": ("ad cs", "adcs", "certificate services", "certifried", "icpr", "esc1", "esc8"),
    "ACTIVE_DIRECTORY": ("active directory", "domain controller", "netlogon", "kerberos"),
    "EXCHANGE": ("exchange", "owa", "ecp", "powershell backend", "proxylogon", "proxyshell"),
    "MSSQL": ("mssql", "microsoft sql server", "microsoft sql"),
    "PRINT_SPOOLER": ("print spooler", "spoolss", "spooler", "printnightmare"),
}
WINDOWS_SERVER_HINTS = {
    "windows",
    "win",
    "server",
    "microsoft",
    "domain",
    "dcerpc",
    "smb",
    "ldap",
    "kerberos",
    "iis",
    "http.sys",
    "exchange",
    "wsus",
    "mssql",
}
WINDOWS_PRODUCT_PHRASES = (
    "microsoft windows",
    "windows server",
    "windows domain",
    "microsoft server",
    "ms17-010",
    "eternalblue",
    "zerologon",
    "certifried",
    "bluekeep",
)
SERVER_COMPONENTS = {
    "ACTIVE_DIRECTORY",
    "AD_CS",
    "EXCHANGE",
    "HTTP_SYS",
    "IIS_CORE",
    "MSSQL",
    "PRINT_SPOOLER",
    "RDP",
    "WEBDAV",
    "WEBDEPLOY",
    "WINRM",
    "WSUS",
}
SERVER_TREE_PREFIXES = (
    "exploits/windows/",
    "post/windows/",
    "auxiliary/admin/dcerpc/",
    "auxiliary/admin/ldap/",
    "auxiliary/admin/mssql/",
    "auxiliary/admin/smb/",
    "auxiliary/gather/ldap/",
    "auxiliary/gather/smb",
    "auxiliary/scanner/dcerpc/",
    "auxiliary/scanner/ldap/",
    "auxiliary/scanner/mssql/",
    "auxiliary/scanner/rdp/",
    "auxiliary/scanner/smb/",
    "auxiliary/scanner/winrm/",
)
EXPLICIT_SERVER_PHRASES = (
    "windows server",
    "domain controller",
    "active directory",
    "certificate services",
    "exchange server",
    "update service",
    "sql server",
    "terminal services",
    "remote desktop services",
)
COMPONENT_DEFAULT_DATASTORE: dict[str, dict[str, Any]] = {
    "IIS_CORE": {"RPORT": 80, "SSL": False},
    "HTTP_SYS": {"RPORT": 80, "SSL": False},
    "WEBDAV": {"RPORT": 80, "SSL": False},
    "WEBDEPLOY": {"RPORT": 8172, "SSL": True},
    "WSUS": {"RPORT": 8530, "SSL": False},
    "SMB": {"RPORT": 445, "SSL": False},
    "RDP": {"RPORT": 3389, "SSL": False},
    "WINRM": {"RPORT": 5985, "SSL": False},
    "EXCHANGE": {"RPORT": 443, "SSL": True},
    "MSSQL": {"RPORT": 1433, "SSL": False},
    "AD_CS": {"RPORT": 80, "SSL": False},
    "ACTIVE_DIRECTORY": {"RPORT": 389, "SSL": False},
}


def text_tokens(*values: Any) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        text = str(value or "").casefold()
        replacements = {
            "http.sys": "http_sys httpsys http sys",
            "msdeploy.axd": "msdeploy msdeploy.axd axd",
            "web-dav": "webdav web dav",
            "ms17-010": "ms17_010 eternalblue smb",
        }
        for key, replacement in replacements.items():
            if key in text:
                tokens.update(replacement.split())
        cleaned = re.sub(r"[^a-z0-9.]+", " ", text)
        tokens.update(item for item in cleaned.split() if item)
        joined = "_".join(cleaned.split())
        if joined:
            tokens.add(joined)
    return tokens


@dataclass(frozen=True)
class WarehousePaths:
    framework_root: Path
    modules_root: Path


def discover_framework() -> WarehousePaths:
    for root in DEFAULT_FRAMEWORK_ROOTS:
        modules = root / "modules"
        if modules.is_dir():
            return WarehousePaths(framework_root=root, modules_root=modules)
    raise FileNotFoundError("Metasploit framework modules folder was not found on the expected USB paths.")


def build_windows_server_warehouse(
    *,
    framework_root: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    paths = _paths(framework_root)
    output = output_dir or Path("metasploit_modules") / "warehouse"
    output.mkdir(parents=True, exist_ok=True)

    all_modules = load_modules(paths)
    windows_server_modules = [module for module in all_modules if is_windows_server_cve_module(module)]
    indexes = build_indexes(windows_server_modules)

    catalog = {
        "schema_version": "2026-06-26.local-msf-warehouse.v1",
        "generated_at": datetime.now().isoformat(),
        "framework_root": str(paths.framework_root),
        "modules_root": str(paths.modules_root),
        "all_module_count": len(all_modules),
        "windows_server_cve_module_count": len(windows_server_modules),
        "all_modules": all_modules,
        "windows_server_cve_modules": windows_server_modules,
    }
    index_payload = {
        "schema_version": catalog["schema_version"],
        "generated_at": catalog["generated_at"],
        "framework_root": str(paths.framework_root),
        "module_count": len(windows_server_modules),
        "indexes": indexes,
    }
    audit_payload = {
        "schema_version": catalog["schema_version"],
        "generated_at": catalog["generated_at"],
        "framework_root": str(paths.framework_root),
        "module_count": len(windows_server_modules),
        "modules": [_audit_module(module) for module in windows_server_modules],
    }

    catalog_path = output / "windows_server_msf_module_catalog.json"
    index_path = output / "windows_server_msf_module_index.json"
    audit_path = output / "windows_server_msf_module_audit.json"
    catalog_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")
    index_path.write_text(json.dumps(index_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_path.write_text(json.dumps(audit_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "catalog_path": str(catalog_path),
        "index_path": str(index_path),
        "audit_path": str(audit_path),
        "all_module_count": len(all_modules),
        "windows_server_cve_module_count": len(windows_server_modules),
        "component_counts": _component_counts(windows_server_modules),
    }


def parse_module_file(path: Path, modules_root: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    relative = path.relative_to(modules_root).as_posix()
    parts = relative.split("/")
    module_dir = parts[0]
    module_type = "exploit" if module_dir == "exploits" else module_dir
    fullname = f"{module_type}/{'/'.join(parts[1:])}".removesuffix(".rb")
    references = _references(raw)
    cves = sorted({_normalize_cve(ref) for ref in references if _normalize_cve(ref)})
    text = "\n".join([relative, _field(raw, "Name"), _field(raw, "Description"), raw])
    tokens = sorted(text_tokens(text))
    components = _components(text, tokens)
    if relative.startswith(("exploits/windows/", "post/windows/")):
        components.add("WINDOWS_HOST")
    components = sorted(components)
    options = sorted(set(re.findall(r"Opt[A-Za-z0-9_]*\.new\(['\"]([^'\"]+)['\"]", raw)))
    datastore = _source_default_datastore(raw, components)
    check_methods = sorted(set(re.findall(r"^\s*def\s+(check(?:_[a-z0-9_]+)?)\b", raw, flags=re.M)))
    reasons = _candidate_reasons(relative, text, references, cves, components, tokens)
    return {
        "module_type": module_type,
        "fullname": fullname,
        "relative_path": relative,
        "name": _field(raw, "Name"),
        "description": _field(raw, "Description"),
        "rank": _field(raw, "Rank"),
        "disclosure_date": _field(raw, "DisclosureDate"),
        "platform": _platforms(raw),
        "references": references,
        "cves": cves,
        "components": components,
        "tokens": tokens,
        "options": options,
        "default_datastore": datastore,
        "default_datastore_source": "source",
        "has_check": bool(check_methods),
        "check_methods": check_methods,
        "check_supported": bool(check_methods) and module_type in {"exploit", "auxiliary"},
        "windows_server_candidate": bool(reasons),
        "candidate_reasons": reasons,
    }


def load_modules(paths: WarehousePaths) -> list[dict[str, Any]]:
    metadata_modules = _metadata_modules(paths)
    if metadata_modules:
        return metadata_modules
    return [module for module in (parse_module_file(path, paths.modules_root) for path in _module_files(paths.modules_root)) if module]


def is_windows_server_cve_module(module: dict[str, Any]) -> bool:
    return bool(module.get("windows_server_candidate")) and not _is_non_windows_module_path(str(module.get("relative_path") or ""))


def build_indexes(modules: list[dict[str, Any]]) -> dict[str, dict[str, list[str]]]:
    cve_index: dict[str, list[str]] = defaultdict(list)
    reference_index: dict[str, list[str]] = defaultdict(list)
    component_index: dict[str, list[str]] = defaultdict(list)
    token_index: dict[str, list[str]] = defaultdict(list)
    check_index: dict[str, list[str]] = defaultdict(list)
    for module in modules:
        fullname = str(module["fullname"])
        for cve in module.get("cves", []):
            cve_index[cve].append(fullname)
        for ref in module.get("references", []):
            reference_index[_reference_key(ref)].append(fullname)
        for component in module.get("components", []):
            component_index[component].append(fullname)
        for token in module.get("tokens", []):
            token_index[token].append(fullname)
        if module.get("check_supported"):
            check_index["check_supported"].append(fullname)
    return {
        "cve": _sorted_index(cve_index),
        "reference": _sorted_index(reference_index),
        "component": _sorted_index(component_index),
        "token": _sorted_index(token_index),
        "capability": _sorted_index(check_index),
    }


def _paths(framework_root: Path | None) -> WarehousePaths:
    if framework_root is None:
        return discover_framework()
    root = Path(framework_root)
    modules = root / "modules"
    if not modules.is_dir() and (root / "embedded" / "framework" / "modules").is_dir():
        root = root / "embedded" / "framework"
        modules = root / "modules"
    if not modules.is_dir():
        raise FileNotFoundError(f"Metasploit modules folder not found under {framework_root}")
    return WarehousePaths(framework_root=root, modules_root=modules)


def _module_files(modules_root: Path) -> list[Path]:
    paths: list[Path] = []
    for module_dir in MODULE_TYPES:
        root = modules_root / module_dir
        if root.is_dir():
            paths.extend(root.rglob("*.rb"))
    return sorted(paths, key=lambda item: item.relative_to(modules_root).as_posix().casefold())


def _metadata_modules(paths: WarehousePaths) -> list[dict[str, Any]]:
    metadata_path = paths.framework_root / "db" / "modules_metadata_base.json"
    if not metadata_path.is_file():
        return []
    raw_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    modules = []
    for item in raw_metadata.values():
        module = _module_from_metadata(item, paths.modules_root)
        if module and module["module_type"] in {"auxiliary", "exploit", "post"}:
            modules.append(module)
    return sorted(modules, key=lambda item: str(item["relative_path"]).casefold())


def _module_from_metadata(item: dict[str, Any], modules_root: Path) -> dict[str, Any] | None:
    module_type = "exploit" if item.get("type") == "exploit" else str(item.get("type") or "")
    if module_type not in {"auxiliary", "exploit", "post"}:
        return None
    relative = _metadata_relative_path(item)
    if not relative:
        return None
    references = sorted(str(ref) for ref in item.get("references", []) if ref)
    cves = sorted({_normalize_cve(ref) for ref in references if _normalize_cve(ref)})
    source = modules_root / relative
    source_text = _read_source_text(source)
    text = "\n".join([
        relative,
        str(item.get("fullname") or ""),
        str(item.get("name") or ""),
        str(item.get("description") or ""),
        " ".join(references),
        source_text,
    ])
    tokens = sorted(text_tokens(text))
    components = _components(text, tokens)
    if relative.startswith(("exploits/windows/", "post/windows/")):
        components.add("WINDOWS_HOST")
    check_methods = sorted(set(re.findall(r"^\s*def\s+(check(?:_[a-z0-9_]+)?)\b", source_text, flags=re.M)))
    has_check = bool(item.get("check")) or bool(check_methods)
    reasons = _candidate_reasons(relative, text, references, cves, sorted(components), tokens)
    rport = _int_or_none(item.get("rport"))
    autofilter_ports = [_int_or_none(port) for port in item.get("autofilter_ports") or []]
    autofilter_ports = [port for port in autofilter_ports if port is not None]
    autofilter_services = _metadata_list(item.get("autofilter_services"))
    datastore = _metadata_default_datastore(
        rport=rport,
        autofilter_ports=autofilter_ports,
        autofilter_services=autofilter_services,
        components=sorted(components),
        source_text=source_text,
    )
    return {
        "module_type": module_type,
        "fullname": str(item.get("fullname") or ""),
        "relative_path": relative,
        "name": " ".join(str(item.get("name") or "").split()),
        "description": " ".join(str(item.get("description") or "").split()),
        "rank": str(item.get("rank") or ""),
        "disclosure_date": str(item.get("disclosure_date") or ""),
        "platform": _metadata_list(item.get("platform")),
        "references": references,
        "cves": cves,
        "components": sorted(components),
        "tokens": tokens,
        "options": sorted(set(_source_options(source_text) + _datastore_option_names(datastore))),
        "rport": rport,
        "autofilter_ports": autofilter_ports,
        "autofilter_services": autofilter_services,
        "targets": item.get("targets"),
        "default_datastore": datastore,
        "default_datastore_source": "metadata",
        "has_check": has_check,
        "check_methods": check_methods,
        "check_supported": has_check and module_type in {"exploit", "auxiliary"},
        "windows_server_candidate": bool(reasons),
        "candidate_reasons": reasons,
    }


def _metadata_relative_path(item: dict[str, Any]) -> str:
    path = str(item.get("path") or "").replace("\\", "/")
    if "/modules/" in path:
        return path.split("/modules/", 1)[1].lstrip("/")
    fullname = str(item.get("fullname") or "")
    module_type = str(item.get("type") or "")
    if fullname and "/" in fullname:
        root = {"auxiliary": "auxiliary", "exploit": "exploits", "post": "post"}.get(module_type, f"{module_type}s")
        return f"{root}/{'/'.join(fullname.split('/')[1:])}.rb"
    return ""


def _read_source_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""
    except OSError:
        return ""


def _metadata_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(str(item) for item in value if item)
    if value:
        return [str(value)]
    return []


def _source_options(raw: str) -> list[str]:
    return sorted(set(re.findall(r"Opt[A-Za-z0-9_]*\.new\(['\"]([^'\"]+)['\"]", raw or "")))


def _source_default_datastore(raw: str, components: list[str]) -> dict[str, Any]:
    datastore: dict[str, Any] = {}
    rport_match = re.search(r"Opt::RPORT\((\d+)\)", raw or "")
    if rport_match:
        datastore["RPORT"] = int(rport_match.group(1))
    if re.search(r"['\"]SSL['\"]\s*=>\s*true\b", raw or "", flags=re.I):
        datastore["SSL"] = True
    elif re.search(r"['\"]SSL['\"]\s*=>\s*false\b", raw or "", flags=re.I):
        datastore["SSL"] = False
    return _with_component_defaults(datastore, components)


def _metadata_default_datastore(
    *,
    rport: int | None,
    autofilter_ports: list[int],
    autofilter_services: list[str],
    components: list[str],
    source_text: str,
) -> dict[str, Any]:
    datastore = _source_default_datastore(source_text, components)
    if rport is not None:
        datastore["RPORT"] = rport
    services = {service.casefold() for service in autofilter_services}
    if "https" in services or datastore.get("RPORT") in {443, 5986, 8531, 8172}:
        datastore.setdefault("SSL", True)
    elif "http" in services or datastore.get("RPORT") in {80, 5985, 8530}:
        datastore.setdefault("SSL", False)
    if "RPORT" not in datastore and autofilter_ports:
        datastore["RPORT"] = autofilter_ports[0]
    return _with_component_defaults(datastore, components)


def _with_component_defaults(datastore: dict[str, Any], components: list[str]) -> dict[str, Any]:
    for component in components:
        defaults = COMPONENT_DEFAULT_DATASTORE.get(component)
        if defaults:
            for key, value in defaults.items():
                datastore.setdefault(key, value)
            break
    return dict(sorted(datastore.items()))


def _datastore_option_names(datastore: dict[str, Any]) -> list[str]:
    return sorted(name for name in ("RHOSTS", "RHOST", "RPORT", "SSL", "TARGETURI") if name in datastore)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _references(raw: str) -> list[str]:
    refs = [f"{kind}-{value}" for kind, value in re.findall(
        r"\[\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\]",
        raw,
    )]
    refs.extend(f"CVE-{year}-{num}" for year, num in re.findall(r"CVE[-_ ]?(\d{4})[-_ ](\d{4,8})", raw, flags=re.I))
    return sorted(set(refs))


def _normalize_cve(value: str) -> str:
    match = re.search(r"(?:CVE[-\s]?)?(\d{4})[-\s](\d{4,8})", str(value), flags=re.I)
    return f"CVE-{match.group(1)}-{match.group(2)}".upper() if match else ""


def _field(raw: str, name: str) -> str:
    patterns = [
        rf"['\"]{re.escape(name)}['\"]\s*=>\s*%q\{{(.*?)\}}",
        rf"['\"]{re.escape(name)}['\"]\s*=>\s*['\"]([^'\"]+)['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.S)
        if match:
            return " ".join(match.group(1).split())
    return ""


def _platforms(raw: str) -> list[str]:
    match = re.search(r"['\"]Platform['\"]\s*=>\s*(.+?)(?:,\n|,\r\n|\n\s*['\"])", raw, flags=re.S)
    if not match:
        return []
    text = match.group(1)
    values = re.findall(r"['\"]([^'\"]+)['\"]", text)
    return sorted(set(values))


def _components(text: str, tokens: list[str]) -> set[str]:
    lower = text.casefold()
    token_set = set(tokens)
    components = set()
    for component, aliases in COMPONENT_ALIASES.items():
        if any(alias in lower or alias.replace(" ", "_") in token_set for alias in aliases):
            components.add(component)
    return components


def _candidate_reasons(
    relative: str,
    text: str,
    references: list[str],
    cves: list[str],
    components: list[str],
    tokens: list[str],
) -> list[str]:
    token_set = set(tokens)
    reasons = []
    lower = text.casefold()
    has_reference = bool(cves)
    if not has_reference:
        return []
    if _is_non_windows_module_path(relative):
        return []

    windows_tree = any(relative.startswith(prefix) for prefix in ("exploits/windows/", "post/windows/"))
    windows_product_hint = any(phrase in lower for phrase in WINDOWS_PRODUCT_PHRASES)
    explicit_server_hint = any(phrase in lower for phrase in EXPLICIT_SERVER_PHRASES)
    component_set = set(components)
    server_component_hit = bool(component_set.intersection(SERVER_COMPONENTS))
    smb_component_hit = "SMB" in component_set and windows_product_hint
    server_tree_hit = any(relative.startswith(prefix) for prefix in SERVER_TREE_PREFIXES) and (
        windows_product_hint or explicit_server_hint or server_component_hit or smb_component_hit
    )

    if cves and windows_tree:
        reasons.append("CVE in Windows Metasploit module tree")
    if server_tree_hit:
        reasons.append("CVE/reference plus Windows Server module tree")
    if windows_product_hint and (server_component_hit or smb_component_hit or "WINDOWS_HOST" in component_set):
        reasons.append("CVE/reference plus Microsoft Windows product hint")
    if server_component_hit:
        reasons.append("CVE/reference plus server component alias")
    if smb_component_hit:
        reasons.append("CVE/reference plus Microsoft SMB alias")
    return sorted(set(reasons))


def _is_non_windows_module_path(relative: str) -> bool:
    return str(relative or "").casefold().startswith(NON_WINDOWS_MODULE_PREFIXES)


def _reference_key(value: str) -> str:
    return re.sub(r"[^A-Z0-9-]+", "-", str(value).upper()).strip("-")


def _sorted_index(index: dict[str, list[str]]) -> dict[str, list[str]]:
    return {key: sorted(set(values)) for key, values in sorted(index.items()) if key}


def _component_counts(modules: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for module in modules:
        for component in module.get("components", []):
            counts[component] += 1
    return dict(sorted(counts.items()))


def _audit_module(module: dict[str, Any]) -> dict[str, Any]:
    return {
        "relative_path": module.get("relative_path"),
        "fullname": module.get("fullname"),
        "module_type": module.get("module_type"),
        "name": module.get("name"),
        "description": module.get("description"),
        "cves": module.get("cves", []),
        "components": module.get("components", []),
        "references": module.get("references", []),
        "check_supported": module.get("check_supported", False),
        "check_methods": module.get("check_methods", []),
        "default_datastore": module.get("default_datastore", {}),
        "rport": module.get("rport"),
        "autofilter_ports": module.get("autofilter_ports", []),
        "autofilter_services": module.get("autofilter_services", []),
        "candidate_reasons": module.get("candidate_reasons", []),
    }
