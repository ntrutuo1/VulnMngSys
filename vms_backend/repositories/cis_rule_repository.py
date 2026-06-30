import hashlib
import json

from ..config import RULES_DIR
from ..models import CisRule


class CisRuleRepository:
    def __init__(self, database):
        self.database = database

    def import_from_files(self):
        if not RULES_DIR.exists():
            return 0
        rules = []
        for path in RULES_DIR.rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                data = [data]
            benchmark = path.relative_to(RULES_DIR).parts[0] if len(path.relative_to(RULES_DIR).parts) > 1 else "DEFAULT"
            for item in data:
                rule_id = str(item.get("id", "")).strip()
                title = str(item.get("title", "")).strip()
                script = str(item.get("powershell_check", "")).strip()
                if not rule_id or not title or not script:
                    continue
                hash_id = str(item.get("hash_id") or "").strip()
                if not hash_id:
                    hash_id = hashlib.sha1(f"{benchmark}:{path}:{rule_id}:{title}".encode("utf-8")).hexdigest()[:12]
                rules.append(
                    CisRule(
                        hash_id=hash_id,
                        benchmark=benchmark,
                        source_file=str(path.relative_to(RULES_DIR)),
                        service=str(item.get("service", "")),
                        rule_id=rule_id,
                        title=title,
                        check_type=str(item.get("check_type", "")),
                        registry_path=str(item.get("registry_path", "")),
                        expected=json.dumps(item.get("expected", ""), ensure_ascii=False),
                        operator=str(item.get("operator", "==")),
                        powershell_check=script,
                        remediation=str(item.get("remediation", "")),
                        reason=str(item.get("reason", "")),
                        service_id=int(item.get("service_id") or 0),
                    )
                )
        self.upsert_many(rules)
        return len(rules)

    def upsert_many(self, rules: list[CisRule]):
        with self.database.session() as connection:
            connection.executemany(
                """
                INSERT INTO cis_rules(hash_id,benchmark,source_file,service,rule_id,title,check_type,registry_path,expected,operator,powershell_check,remediation,reason,service_id,enabled)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(hash_id) DO UPDATE SET
                  benchmark=excluded.benchmark,
                  source_file=excluded.source_file,
                  service=excluded.service,
                  rule_id=excluded.rule_id,
                  title=excluded.title,
                  check_type=excluded.check_type,
                  registry_path=excluded.registry_path,
                  expected=excluded.expected,
                  operator=excluded.operator,
                  powershell_check=excluded.powershell_check,
                  remediation=excluded.remediation,
                  reason=excluded.reason,
                  service_id=excluded.service_id,
                  enabled=excluded.enabled
                """,
                [
                    (
                        rule.hash_id,
                        rule.benchmark,
                        rule.source_file,
                        rule.service,
                        rule.rule_id,
                        rule.title,
                        rule.check_type,
                        rule.registry_path,
                        rule.expected,
                        rule.operator,
                        rule.powershell_check,
                        rule.remediation,
                        rule.reason,
                        rule.service_id,
                        int(rule.enabled),
                    )
                    for rule in rules
                ],
            )

    def list_enabled(self, benchmark: str | None = None):
        sql = "SELECT * FROM cis_rules WHERE enabled=1"
        params = []
        if benchmark:
            sql += " AND benchmark=?"
            params.append(benchmark)
        sql += " ORDER BY benchmark, service_id, rule_id, title"
        with self.database.session() as connection:
            return [
                CisRule(
                    hash_id=row["hash_id"],
                    benchmark=row["benchmark"],
                    source_file=row["source_file"],
                    service=row["service"],
                    rule_id=row["rule_id"],
                    title=row["title"],
                    check_type=row["check_type"],
                    registry_path=row["registry_path"],
                    expected=row["expected"],
                    operator=row["operator"],
                    powershell_check=row["powershell_check"],
                    remediation=row["remediation"],
                    reason=row["reason"],
                    service_id=row["service_id"],
                    enabled=bool(row["enabled"]),
                )
                for row in connection.execute(sql, params)
            ]

    def list_benchmarks(self):
        with self.database.session() as connection:
            return [
                {"benchmark": row["benchmark"], "count": row["count"]}
                for row in connection.execute(
                    "SELECT benchmark,COUNT(*) count FROM cis_rules WHERE enabled=1 GROUP BY benchmark ORDER BY benchmark"
                )
            ]

    def count_enabled(self):
        with self.database.session() as connection:
            return connection.execute("SELECT COUNT(*) FROM cis_rules WHERE enabled=1").fetchone()[0]
