class DashboardController:
    def __init__(self, dashboard_service):
        self.dashboard_service = dashboard_service

    def get_dashboard_metrics(self):
        return self.dashboard_service.get_dashboard_metrics()
