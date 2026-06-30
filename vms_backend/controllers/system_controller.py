class SystemController:
    def __init__(self, system_service):
        self.system_service = system_service

    def handle_get_system_info(self):
        return 200, self.system_service.get_system_info()
