class DashboardService:
    def __init__(self, repository):
        self.repository = repository

    def get_dashboard_metrics(self):
        return self.repository.dashboard_metrics()
