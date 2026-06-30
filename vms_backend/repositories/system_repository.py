class SystemRepository:
    def __init__(self, adapter):
        self.adapter = adapter

    def get_system_info(self):
        return self.adapter.execute_json(
            "Get-ComputerInfo | Select CsName,OsName,OsVersion,WindowsProductName,OsArchitecture | ConvertTo-Json",
            {},
        )
