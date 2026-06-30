class StatRepository:
    def __init__(self, database):
        self.database = database

    def dashboard_metrics(self):
        with self.database.session() as connection:
            totals = [dict(row) for row in connection.execute("SELECT status,COUNT(*) count FROM scan_history GROUP BY status")]
            risk_rows = []
            risk_rows.extend(
                dict(row)
                for row in connection.execute("SELECT severity,COUNT(*) count FROM cve_findings GROUP BY severity")
            )
            risk_rows.extend(
                {"severity": "low" if row["is_passed"] else "medium", "count": row["count"]}
                for row in connection.execute("SELECT is_passed,COUNT(*) count FROM cis_findings GROUP BY is_passed")
            )
            risk = {}
            for row in risk_rows:
                risk[row["severity"]] = risk.get(row["severity"], 0) + row["count"]
            return {"totals": totals, "risk": [{"severity": key, "count": value} for key, value in risk.items()]}
