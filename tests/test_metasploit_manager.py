from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnmngsys_app.services.scanflow.msf_audit import metasploit_manager
from vulnmngsys_app.services.scanflow.msf_audit.metasploit_manager import MetasploitManager


class MetasploitManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env = {
            "VULNMNGSYS_MSF_RPCD": os.environ.get("VULNMNGSYS_MSF_RPCD"),
            "VULNMNGSYS_ALLOW_SYSTEM_MSF": os.environ.get("VULNMNGSYS_ALLOW_SYSTEM_MSF"),
        }
        os.environ.pop("VULNMNGSYS_MSF_RPCD", None)
        os.environ.pop("VULNMNGSYS_ALLOW_SYSTEM_MSF", None)

    def tearDown(self) -> None:
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_find_msfrpcd_prefers_portable_tools_over_system_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp)
            portable_rpcd = app_root / "Tools" / "metasploit-framework" / "bin" / "msfrpcd.bat"
            portable_rpcd.parent.mkdir(parents=True)
            portable_rpcd.write_text("@echo off\n", encoding="utf-8")

            with (
                patch.object(metasploit_manager, "_app_root", return_value=app_root),
                patch.object(metasploit_manager, "_find_usb_tools_roots", return_value=[]),
                patch.object(metasploit_manager.shutil, "which", return_value=r"C:\metasploit-framework\bin\msfrpcd.bat"),
            ):
                self.assertEqual(MetasploitManager()._find_msfrpcd(), portable_rpcd)

    def test_find_msfrpcd_searches_usb_drives(self) -> None:
        with tempfile.TemporaryDirectory() as app_tmp, tempfile.TemporaryDirectory() as usb_tmp:
            app_root = Path(app_tmp)
            usb_tools = Path(usb_tmp) / "VulnMngApp" / "Tools"
            usb_rpcd = usb_tools / "metasploit-framework" / "bin" / "msfrpcd.bat"
            usb_rpcd.parent.mkdir(parents=True)
            usb_rpcd.write_text("@echo off\n", encoding="utf-8")

            with (
                patch.object(metasploit_manager, "_app_root", return_value=app_root),
                patch.object(metasploit_manager, "_find_usb_tools_roots", return_value=[usb_tools]),
                patch.object(metasploit_manager.shutil, "which", return_value=None),
            ):
                self.assertEqual(MetasploitManager()._find_msfrpcd(), usb_rpcd)

    def test_find_msfrpcd_ignores_system_path_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp)
            with (
                patch.object(metasploit_manager, "_app_root", return_value=app_root),
                patch.object(metasploit_manager, "_find_usb_tools_roots", return_value=[]),
                patch.object(metasploit_manager.shutil, "which", return_value=r"C:\metasploit-framework\bin\msfrpcd.bat"),
            ):
                self.assertIsNone(MetasploitManager()._find_msfrpcd())

    def test_find_msfrpcd_allows_system_path_when_enabled(self) -> None:
        os.environ["VULNMNGSYS_ALLOW_SYSTEM_MSF"] = "1"
        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp)
            with (
                patch.object(metasploit_manager, "_app_root", return_value=app_root),
                patch.object(metasploit_manager, "_find_usb_tools_roots", return_value=[]),
                patch.object(metasploit_manager.shutil, "which", return_value=r"C:\metasploit-framework\bin\msfrpcd.bat"),
            ):
                self.assertEqual(
                    MetasploitManager()._find_msfrpcd(),
                    Path(r"C:\metasploit-framework\bin\msfrpcd.bat"),
                )

    def test_install_metasploit_reports_portable_tools_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp)
            with (
                patch.object(metasploit_manager, "_app_root", return_value=app_root),
                patch.object(metasploit_manager, "_find_usb_tools_roots", return_value=[]),
            ):
                with self.assertRaisesRegex(FileNotFoundError, "USB drive"):
                    MetasploitManager()._install_metasploit()

    def test_find_usb_tools_roots_skips_non_windows(self) -> None:
        with patch.object(metasploit_manager.os, "name", "posix"):
            self.assertEqual(metasploit_manager._find_usb_tools_roots(), [])

    def test_start_msfrpcd_sets_correct_cwd_and_relative_path(self) -> None:
        import subprocess
        with patch("subprocess.Popen") as mock_popen:
            manager = MetasploitManager()

            # Case 1: executable in a "bin" folder
            executable_in_bin = Path(r"C:\metasploit-framework\bin\msfrpcd.bat")
            manager._start_msfrpcd(executable_in_bin)
            mock_popen.assert_called_with(
                ["cmd.exe", "/c", str(Path("bin") / "msfrpcd.bat"), "-P", manager.config.password, "-a", manager.config.host, "-p", str(manager.config.port), "-S"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=mock_popen.call_args[1].get("creationflags"),
                cwd=str(Path(r"C:\metasploit-framework")),
            )

            # Case 2: executable not in a "bin" folder
            executable_direct = Path(r"C:\metasploit-framework\msfrpcd.bat")
            manager._start_msfrpcd(executable_direct)
            mock_popen.assert_called_with(
                ["cmd.exe", "/c", "msfrpcd.bat", "-P", manager.config.password, "-a", manager.config.host, "-p", str(manager.config.port), "-S"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=mock_popen.call_args[1].get("creationflags"),
                cwd=str(Path(r"C:\metasploit-framework")),
            )


if __name__ == "__main__":
    unittest.main()
