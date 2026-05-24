import argparse
import os
import sys
from typing import Tuple


def parse_cli_args() -> Tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description="VulnMngSys Desktop/CLI Scanner")
    parser.add_argument("--cli", action="store_true", help="Force headless CLI mode")
    parser.add_argument("--module-id", default=None, help="Run a specific hardcoded module id")
    parser.add_argument(
        "--service",
        default="windows-server",
        choices=["windows-server"],
        help="Service type in CLI mode",
    )
    parser.add_argument("--os-version", default=None, help="OS version context for CVE evaluation")
    parser.add_argument("--service-version", default=None, help="Service version context for CVE evaluation")
    parser.add_argument("--interactive", action="store_true", help="Interactive CLI step-by-step selection")

    args, unknown_args = parser.parse_known_args()

    filtered_unknown = [
        item for item in unknown_args if item not in {sys.argv[0], os.path.abspath(sys.argv[0])}
    ]
    return args, filtered_unknown
