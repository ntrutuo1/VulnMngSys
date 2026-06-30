class DashboardController:
    def __init__(self, dashboard_service):
        self.dashboard_service = dashboard_service

    def handle_get_dashboard(self):
        return 200, self.dashboard_service.get_dashboard_metrics()
