from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vulnmngsys_app.services.scanflow.msf_audit.local_warehouse import (
    build_indexes,
    is_windows_server_cve_module,
    parse_module_file,
)


SAMPLE_MODULE = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Windows Server Update Service Deserialization Remote Code Execution',
      'Description' => %q{
        This module checks a Windows Server Update Service endpoint.
      },
      'Platform' => 'win',
      'References' => [
        [ 'CVE', '2025-59287' ],
        [ 'URL', 'https://example.test/wsus' ]
      ],
      'DisclosureDate' => '2025-10-01'
    ))
    register_options([
      Opt::RPORT(8530),
      OptString.new('TARGETURI', [ true, 'Target URI', '/' ])
    ])
  end

  def check
    CheckCode::Appears
  end
end
"""


class LocalMsfWarehouseTests(unittest.TestCase):
    def test_parse_module_file_extracts_windows_server_cve_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            modules_root = Path(tmp) / "modules"
            module_path = modules_root / "exploits" / "windows" / "http" / "wsus_example.rb"
            module_path.parent.mkdir(parents=True)
            module_path.write_text(SAMPLE_MODULE, encoding="utf-8")

            module = parse_module_file(module_path, modules_root)

        self.assertEqual(module["fullname"], "exploit/windows/http/wsus_example")
        self.assertEqual(module["cves"], ["CVE-2025-59287"])
        self.assertIn("WSUS", module["components"])
        self.assertEqual(module["default_datastore"]["RPORT"], 8530)
        self.assertFalse(module["default_datastore"]["SSL"])
        self.assertTrue(module["has_check"])
        self.assertTrue(module["check_supported"])
        self.assertTrue(is_windows_server_cve_module(module))

    def test_build_indexes_maps_cve_component_and_check(self) -> None:
        module = {
            "fullname": "exploit/windows/http/wsus_example",
            "cves": ["CVE-2025-59287"],
            "references": ["CVE-2025-59287"],
            "components": ["WSUS"],
            "tokens": ["windows", "server", "wsus"],
            "check_supported": True,
        }

        indexes = build_indexes([module])

        self.assertEqual(indexes["cve"]["CVE-2025-59287"], ["exploit/windows/http/wsus_example"])
        self.assertEqual(indexes["component"]["WSUS"], ["exploit/windows/http/wsus_example"])
        self.assertEqual(indexes["capability"]["check_supported"], ["exploit/windows/http/wsus_example"])

    def test_non_windows_module_tree_is_not_windows_server_candidate(self) -> None:
        module = {
            "relative_path": "exploits/linux/http/not_windows.rb",
            "windows_server_candidate": True,
        }

        self.assertFalse(is_windows_server_cve_module(module))


if __name__ == "__main__":
    unittest.main()
