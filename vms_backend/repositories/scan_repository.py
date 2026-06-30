import json
import uuid

from ..models import CisFinding, CveFinding, ScanHistory, TargetServer


class ScanRepository:
    def __init__(self, database):
        self.database = database

    def save_target(self, target: TargetServer):
        with self.database.session() as connection:
            connection.execute(
                """
                INSERT INTO target_servers(target_id,ip_address,os_version,iis_features,running_services)
                VALUES(?,?,?,?,?)
                ON CONFLICT(target_id) DO UPDATE SET
                  ip_address=excluded.ip_address,
                  os_version=excluded.os_version,
                  iis_features=excluded.iis_features,
                  running_services=excluded.running_services
                """,
                (target.target_id, target.ip_address, target.os_version, target.iis_features, target.running_services),
            )

    def create_scan(self, scan: ScanHistory):
        with self.database.session() as connection:
            connection.execute(
                """
                INSERT INTO scan_history(scan_id,target_id,status,start_time,completed_at,scan_type,score,summary)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    scan.scan_id,
                    scan.target_id,
                    scan.status,
                    scan.start_time,
                    scan.completed_at,
                    scan.scan_type,
                    scan.score,
                    json.dumps(scan.summary),
                ),
            )

    def update_scan(self, scan: ScanHistory):
        with self.database.session() as connection:
            connection.execute(
                "UPDATE scan_history SET status=?,completed_at=?,score=?,summary=? WHERE scan_id=?",
                (scan.status, scan.completed_at, scan.score, json.dumps(scan.summary), scan.scan_id),
            )

    def save_cve_findings(self, findings: list[CveFinding]):
        with self.database.session() as connection:
            connection.executemany(
                """
                INSERT INTO cve_findings(id,scan_id,cve_id,affected_service,msf_module,evidence,risk_score,patch_status,severity)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        finding.id,
                        finding.scan_id,
                        finding.cve_id,
                        finding.affected_service,
                        finding.msf_module,
                        finding.evidence,
                        finding.risk_score,
                        finding.patch_status,
                        finding.severity,
                    )
                    for finding in findings
                ],
            )

    def save_cis_findings(self, findings: list[CisFinding]):
        with self.database.session() as connection:
            connection.executemany(
                """
                INSERT INTO cis_findings(id,scan_id,rule_id,is_passed,registry_key,title,evidence,status,remediation)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        finding.id,
                        finding.scan_id,
                        finding.rule_id,
                        int(finding.is_passed),
                        finding.registry_key,
                        finding.title,
                        finding.evidence,
                        finding.status,
                        finding.remediation,
                    )
                    for finding in findings
                ],
            )

    def list_scans(self, limit: int):
        with self.database.session() as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT scan_id AS id, scan_type AS type, COALESCE(target_servers.ip_address, '') AS target,
                           status, score, start_time AS created_at, completed_at, summary
                    FROM scan_history
                    LEFT JOIN target_servers ON target_servers.target_id = scan_history.target_id
                    ORDER BY start_time DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            ]
            for row in rows:
                row["summary"] = json.loads(row["summary"] or "{}")
            return rows

    def find_scan(self, scan_id: str):
        with self.database.session() as connection:
            row = connection.execute(
                """
                SELECT scan_id AS id, scan_type AS type, COALESCE(target_servers.ip_address, '') AS target,
                       status, score, start_time AS created_at, completed_at, summary
                FROM scan_history
                LEFT JOIN target_servers ON target_servers.target_id = scan_history.target_id
                WHERE scan_id=?
                """,
                (scan_id,),
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            result["summary"] = json.loads(result["summary"] or "{}")
            return result

    def list_findings(self, scan_id: str):
        with self.database.session() as connection:
            cve = [
                {
                    "severity": row["severity"],
                    "title": row["cve_id"] or row["affected_service"] or "Service vulnerability finding",
                    "evidence": row["evidence"],
                    "fix": row["patch_status"] or "Review and patch affected service.",
                }
                for row in connection.execute("SELECT * FROM cve_findings WHERE scan_id=?", (scan_id,))
            ]
            cis = [
                {
                    "severity": "low" if row["is_passed"] else "medium",
                    "title": row["title"],
                    "evidence": row["evidence"],
                    "fix": row["remediation"] or "Apply CIS recommendation and scan again.",
                }
                for row in connection.execute("SELECT * FROM cis_findings WHERE scan_id=?", (scan_id,))
            ]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            return sorted(cve + cis, key=lambda item: order.get(item["severity"], 9))

    def delete_scan(self, scan_id: str):
        with self.database.session() as connection:
            connection.execute("DELETE FROM scan_history WHERE scan_id=?", (scan_id,))

    def new_id(self):
        return str(uuid.uuid4())
