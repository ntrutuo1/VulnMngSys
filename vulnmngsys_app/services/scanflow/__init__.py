__all__ = ["run_windows_server_scan_flow"]


def __getattr__(name: str):
    if name == "run_windows_server_scan_flow":
        from .orchestrator import run_windows_server_scan_flow

        return run_windows_server_scan_flow
    raise AttributeError(name)
