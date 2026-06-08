from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from infrastructure.backup_manager import BackupManager, _normalize_reg_path


class BackupManagerTests(unittest.TestCase):
    def test_normalize_reg_path_accepts_powershell_registry_provider_path(self) -> None:
        self.assertEqual(
            _normalize_reg_path("HKLM:\\Software\\VulnMngSysTest"),
            "HKLM\\Software\\VulnMngSysTest",
        )
        self.assertEqual(
            _normalize_reg_path("HKEY_LOCAL_MACHINE\\Software\\VulnMngSysTest"),
            "HKLM\\Software\\VulnMngSysTest",
        )

    def test_backup_registry_exports_unique_keys(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            with patch("infrastructure.backup_manager.subprocess.run", side_effect=fake_run):
                BackupManager()._backup_registry(
                    Path(tmp),
                    ["HKLM:\\Software\\VulnMngSysTest", "HKLM\\Software\\VulnMngSysTest"],
                )

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0:3], ["reg", "export", "HKLM\\Software\\VulnMngSysTest"])
        self.assertEqual(commands[0][-1], "/y")

    def test_rollback_imports_registry_backups(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            manager = BackupManager()
            manager.backup_path = lambda backup_id: Path(tmp) / backup_id
            registry_dir = Path(tmp) / "backup-1" / "registry"
            registry_dir.mkdir(parents=True)
            (registry_dir / "001_HKLM_Software_Test.reg").write_text("Windows Registry Editor Version 5.00", encoding="utf-8")

            with patch("infrastructure.backup_manager.subprocess.run", side_effect=fake_run):
                self.assertTrue(manager.rollback_config("backup-1"))

        self.assertIn(["reg", "import", str(registry_dir / "001_HKLM_Software_Test.reg")], commands)


if __name__ == "__main__":
    unittest.main()
