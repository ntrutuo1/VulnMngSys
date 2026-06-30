class SystemService:
    def __init__(self, repository):
        self.repository = repository

    def get_system_info(self):
        return self.repository.get_system_info()
