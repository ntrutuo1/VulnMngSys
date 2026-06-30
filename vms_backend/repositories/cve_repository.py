import json
import re
from concurrent.futures import ThreadPoolExecutor

from ..config import METASPLOIT_FRAMEWORK_DIR, WINDOWS_CVE_DATASET_PATH
from ..models import MetasploitModuleSpec, WindowsCve


class CveRepository:
    def __init__(self, database):
        self.database = database

    def import_dataset(self):
        if not WINDOWS_CVE_DATASET_PATH.exists():
            return 0
        data = json.loads(WINDOWS_CVE_DATASET_PATH.read_text(encoding="utf-8-sig"))
        cves = [self._from_json(item) for item in data.get("vulnerabilities", [])]
        self.upsert_cves(cves)

        cve_ids = {cve.cve_id for cve in cves}
        modules = []
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cve", "").upper()
            for module_data in self._json_modules(item):
                if cve_id in cve_ids and module_data.get("module_path"):
                    modules.append(
                        MetasploitModuleSpec(
                            cve_id=cve_id,
                            module_path=module_data["module_path"],
                            module_type=module_data["module_path"].split("/", 1)[0],
                            source_file=module_data.get("source_file", "windows_cve_dataset.json"),
                            required_options=module_data.get("required_options", {}),
                            default_options=module_data.get("default_options", {}),
                        )
                    )

        modules_dir = METASPLOIT_FRAMEWORK_DIR / "modules"
        if modules_dir.exists():
            files = list(modules_dir.rglob("*.rb"))

            def scan_file(path):
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                    matches = re.findall(r"\['CVE',\s*'(\d{4}-\d+)'\]", text, re.I)
                    if not matches:
                        return []
                    found_specs = []
                    for m in matches:
                        cve_id = f"CVE-{m}".upper()
                        if cve_id in cve_ids:
                            module_path = path.relative_to(modules_dir).with_suffix("").as_posix()
                            required_options, default_options = self._parse_options(text)
                            spec = MetasploitModuleSpec(
                                cve_id=cve_id,
                                module_path=module_path,
                                module_type=module_path.split("/", 1)[0],
                                source_file=str(path),
                                required_options=required_options,
                                default_options=default_options,
                            )
                            found_specs.append(spec)
                    return found_specs
                except Exception:
                    return []

            with ThreadPoolExecutor(max_workers=32) as executor:
                for result in executor.map(scan_file, files):
                    modules.extend(result)

        self.upsert_modules(modules)
        return len(cves)


    def upsert_cves(self, cves: list[WindowsCve]):
        with self.database.session() as connection:
            connection.executemany(
                """
                INSERT INTO windows_cves(cve_id,published,last_update,max_cvss_base_score,epss_score,cisa_kev_added,public_exploit_exists,summary,service_keywords)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                  published=excluded.published,
                  last_update=excluded.last_update,
                  max_cvss_base_score=excluded.max_cvss_base_score,
                  epss_score=excluded.epss_score,
                  cisa_kev_added=excluded.cisa_kev_added,
                  public_exploit_exists=excluded.public_exploit_exists,
                  summary=excluded.summary,
                  service_keywords=excluded.service_keywords
                """,
                [
                    (
                        cve.cve_id,
                        cve.published,
                        cve.last_update,
                        cve.max_cvss_base_score,
                        cve.epss_score,
                        cve.cisa_kev_added,
                        cve.public_exploit_exists,
                        cve.summary,
                        json.dumps(cve.service_keywords),
                    )
                    for cve in cves
                ],
            )

    def upsert_modules(self, modules: list[MetasploitModuleSpec]):
        with self.database.session() as connection:
            connection.executemany(
                """
                INSERT INTO metasploit_modules(cve_id,module_path,module_type,source_file,required_options,default_options)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                  module_path=excluded.module_path,
                  module_type=excluded.module_type,
                  source_file=excluded.source_file,
                  required_options=excluded.required_options,
                  default_options=excluded.default_options
                """,
                [
                    (
                        module.cve_id,
                        module.module_path,
                        module.module_type,
                        module.source_file,
                        json.dumps(module.required_options),
                        json.dumps(module.default_options),
                    )
                    for module in modules
                ],
            )

    def find_for_services(self, service_names: set[str]):
        if not service_names:
            return []
        rows = []
        with self.database.session() as connection:
            for row in connection.execute(
                """
                SELECT c.*, m.module_path, m.module_type, m.source_file, m.required_options, m.default_options
                FROM windows_cves c
                LEFT JOIN metasploit_modules m ON m.cve_id = c.cve_id
                """
            ):
                keywords = set(json.loads(row["service_keywords"] or "[]"))
                if keywords & service_names:
                    rows.append(self._row_to_cve_module(row))
        return rows

    def find_modules_for_services(self, service_names: set[str]):
        if not service_names:
            return []
        modules = []
        with self.database.session() as connection:
            # Query all modules and their associated CVE information
            for row in connection.execute(
                """
                SELECT m.cve_id, m.module_path, m.module_type, m.source_file, m.required_options, m.default_options,
                       c.published, c.last_update, c.max_cvss_base_score, c.epss_score, c.cisa_kev_added, c.public_exploit_exists, c.summary, c.service_keywords
                FROM metasploit_modules m
                LEFT JOIN windows_cves c ON c.cve_id = m.cve_id
                """
            ):
                keywords = set(json.loads(row["service_keywords"] or "[]"))
                if keywords & service_names:
                    modules.append(self._row_to_cve_module(row))
        return modules


    def count_cves(self):
        with self.database.session() as connection:
            return connection.execute("SELECT COUNT(*) FROM windows_cves").fetchone()[0]

    def count_modules(self):
        with self.database.session() as connection:
            return connection.execute("SELECT COUNT(*) FROM metasploit_modules").fetchone()[0]

    def _from_json(self, item: dict):
        return WindowsCve(
            cve_id=item["cve"].upper(),
            published=item.get("published"),
            last_update=item.get("last_update"),
            max_cvss_base_score=item.get("max_cvss_base_score"),
            epss_score=item.get("epss_score"),
            cisa_kev_added=item.get("cisa_kev_added"),
            public_exploit_exists=item.get("public_exploit_exists"),
            summary=item.get("summary", ""),
            service_keywords=item.get("service_keywords") or self._keywords(item.get("summary", "")),
        )

    def _json_modules(self, item: dict):
        modules = item.get("metasploit_modules") or []
        if item.get("metasploit_module"):
            modules.append(item["metasploit_module"])
        normalized = []
        for module in modules:
            if isinstance(module, str):
                normalized.append({"module_path": module})
            elif isinstance(module, dict):
                normalized.append(module)
        return normalized

    def _keywords(self, summary: str):
        text = summary.lower()
        mapping = {
            "iis": ["iis", "internet information services"],
            "smb": ["smb", "server message block"],
            "webdav": ["webdav", "web dav"],
            "http2": ["http/2", "http2", "hpack"],
            "web_deploy": ["web deploy", "msdeploy", "ms deploy"],
            "nfs": ["network file system", " nfs "],
            "rdp": ["remote desktop", "rdp"],
            "rpc": ["rpc ", "rpc marshalling"],
            "spooler": ["spooler", "print spooler"],
            "winrm": ["winrm", "ws-management"],
            "wsus": ["wsus", "server update services"],
        }
        return [key for key, needles in mapping.items() if any(needle in text for needle in needles)]



    def _parse_options(self, text):
        required = {}
        defaults = {}
        for opt_name, normalized in [("RHOST", "RHOST"), ("RHOSTS", "RHOSTS"), ("RPORT", "RPORT"), ("TARGETURI", "TARGETURI")]:
            if re.search(rf"Opt::{opt_name}\b", text):
                required[normalized] = True
        for match in re.finditer(r"Opt::RPORT\((\d+)\)", text):
            defaults["RPORT"] = int(match.group(1))

        option_pattern = re.compile(
            r"Opt(?:String|Int|Bool|Path|Enum|Address|Port|Float)\.new\(\s*['\"]([^'\"]+)['\"]\s*,\s*\[(.*?)\]\s*\)",
            re.S,
        )
        for match in option_pattern.finditer(text):
            name = match.group(1).upper()
            args = self._split_ruby_args(match.group(2))
            if not args:
                continue
            required_flag = args[0].strip().lower() == "true"
            default_value = self._clean_default(args[-1]) if len(args) >= 3 else None
            if required_flag:
                required[name] = True
            if default_value is not None:
                defaults[name] = default_value
        return required, defaults

    def _split_ruby_args(self, raw):
        args = []
        current = []
        quote = None
        depth = 0
        for char in raw:
            if quote:
                current.append(char)
                if char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
                current.append(char)
            elif char in "[{(":
                depth += 1
                current.append(char)
            elif char in "]})":
                depth = max(0, depth - 1)
                current.append(char)
            elif char == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            args.append("".join(current).strip())
        return args

    def _first_number(self, text):
        match = re.search(r"\((\d+)\)", text)
        return int(match.group(1)) if match else None

    def _clean_default(self, raw):
        if raw is None:
            return None
        value = raw.strip().strip("'\"")
        if not value or value.lower() == "nil":
            return None
        if value.startswith("%q{") and value.endswith("}"):
            return value[3:-1]
        if value.startswith("/"):
            return value
        if value in {"true", "false"}:
            return value == "true"
        try:
            return int(value)
        except ValueError:
            return value

    def _row_to_cve_module(self, row):
        cve = WindowsCve(
            cve_id=row["cve_id"],
            published=row["published"],
            last_update=row["last_update"],
            max_cvss_base_score=row["max_cvss_base_score"],
            epss_score=row["epss_score"],
            cisa_kev_added=row["cisa_kev_added"],
            public_exploit_exists=row["public_exploit_exists"],
            summary=row["summary"],
            service_keywords=json.loads(row["service_keywords"] or "[]"),
        )
        module = None
        if row["module_path"]:
            module = MetasploitModuleSpec(
                cve_id=row["cve_id"],
                module_path=row["module_path"],
                module_type=row["module_type"],
                source_file=row["source_file"],
                required_options=json.loads(row["required_options"] or "{}"),
                default_options=json.loads(row["default_options"] or "{}"),
            )
        return cve, module
