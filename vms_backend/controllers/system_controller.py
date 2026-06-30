class SystemController:
    def __init__(self, system_service):
        self.system_service = system_service

    def get_system_info(self):
        return self.system_service.get_system_info()
