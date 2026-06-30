import sqlite3
from contextlib import contextmanager

from .config import DATABASE_PATH


class SQLiteDatabase:
    def __init__(self, path=DATABASE_PATH):
        self.path = path

    def connect(self):
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
                """
            )

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
