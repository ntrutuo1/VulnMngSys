class DashboardView:
    def __init__(self, dashboard_controller):
        self.dashboard_controller = dashboard_controller

    def get_dashboard(self):
        try:
            res = self.dashboard_controller.get_dashboard_metrics()
            return 200, res
        except Exception as e:
            return 500, {"error": str(e)}
