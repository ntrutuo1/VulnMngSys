class SystemRepository:
    def __init__(self, adapter):
        self.adapter = adapter

    def get_system_info(self):
        result = self.adapter.execute_json(
            "Get-ComputerInfo | Select CsName,OsName,OsVersion,WindowsProductName,OsArchitecture | ConvertTo-Json",
            {},
        )
        # ConvertTo-Json on a single object returns a dict wrapped in a list by execute_json
        return result[0] if isinstance(result, list) and result else result
