import sqlite3
import shutil
from contextlib import contextmanager

from .config import DATABASE_PATH, SEED_DATABASE_PATH


class SQLiteDatabase:
    def __init__(self, path=DATABASE_PATH):
        self.path = path

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() and SEED_DATABASE_PATH.exists() and SEED_DATABASE_PATH != self.path:
            shutil.copy2(SEED_DATABASE_PATH, self.path)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self):
        with self.session() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS target_servers(
                  target_id TEXT PRIMARY KEY,
                  ip_address TEXT NOT NULL,
                  os_version TEXT NOT NULL DEFAULT '',
                  iis_features TEXT NOT NULL DEFAULT '',
                  running_services TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS scan_history(
                  scan_id TEXT PRIMARY KEY,
                  target_id TEXT,
                  status TEXT NOT NULL,
                  start_time TEXT NOT NULL,
                  completed_at TEXT,
                  scan_type TEXT NOT NULL,
                  score INTEGER NOT NULL DEFAULT 0,
                  summary TEXT NOT NULL DEFAULT '{}',
                  FOREIGN KEY(target_id) REFERENCES target_servers(target_id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS cve_findings(
                  id TEXT PRIMARY KEY,
                  scan_id TEXT NOT NULL REFERENCES scan_history(scan_id) ON DELETE CASCADE,
                  cve_id TEXT NOT NULL DEFAULT '',
                  affected_service TEXT NOT NULL DEFAULT '',
                  msf_module TEXT NOT NULL DEFAULT '',
                  evidence TEXT NOT NULL,
                  risk_score REAL NOT NULL DEFAULT 0,
                  patch_status TEXT NOT NULL DEFAULT '',
                  severity TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cis_findings(
                  id TEXT PRIMARY KEY,
                  scan_id TEXT NOT NULL REFERENCES scan_history(scan_id) ON DELETE CASCADE,
                  rule_id TEXT NOT NULL DEFAULT '',
                  is_passed INTEGER NOT NULL DEFAULT 0,
                  registry_key TEXT NOT NULL DEFAULT '',
                  title TEXT NOT NULL,
                  evidence TEXT NOT NULL,
                  status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cis_rules(
                  hash_id TEXT PRIMARY KEY,
                  benchmark TEXT NOT NULL,
                  source_file TEXT NOT NULL,
                  service TEXT NOT NULL DEFAULT '',
                  rule_id TEXT NOT NULL,
                  title TEXT NOT NULL,
                  check_type TEXT NOT NULL DEFAULT '',
                  registry_path TEXT NOT NULL DEFAULT '',
                  expected TEXT NOT NULL DEFAULT '',
                  operator TEXT NOT NULL DEFAULT '==',
                  powershell_check TEXT NOT NULL,
                  remediation TEXT NOT NULL DEFAULT '',
                  reason TEXT NOT NULL DEFAULT '',
                  service_id INTEGER NOT NULL DEFAULT 0,
                  enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS windows_cves(
                  cve_id TEXT PRIMARY KEY,
                  published TEXT,
                  last_update TEXT,
                  max_cvss_base_score REAL,
                  epss_score TEXT,
                  cisa_kev_added TEXT,
                  public_exploit_exists TEXT,
                  summary TEXT NOT NULL,
                  service_keywords TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS metasploit_modules(
                  cve_id TEXT PRIMARY KEY REFERENCES windows_cves(cve_id) ON DELETE CASCADE,
                  module_path TEXT NOT NULL,
                  module_type TEXT NOT NULL,
                  source_file TEXT NOT NULL,
                  required_options TEXT NOT NULL DEFAULT '{}',
                  default_options TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
            self._ensure_column(connection, "cis_findings", "remediation", "TEXT NOT NULL DEFAULT ''")

    def _ensure_column(self, connection, table_name, column_name, definition):
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})")}
        if column_name not in columns:
            connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")

    @contextmanager
    def session(self):
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
