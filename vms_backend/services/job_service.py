import threading


class JobService:
    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()

    def update_status(self, scan_id: str, **data):
        with self._lock:
            self._jobs.setdefault(scan_id, {}).update(data)

    def get_status(self, scan_id: str):
        with self._lock:
            return dict(self._jobs.get(scan_id, {}))
