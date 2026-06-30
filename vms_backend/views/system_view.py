class SystemView:
    def __init__(self, system_controller):
        self.system_controller = system_controller

    def get_system_info(self):
        try:
            res = self.system_controller.get_system_info()
            return 200, res
        except Exception as e:
            return 500, {"error": str(e)}
