class MsfRpcAdapter:
    def execute_module(self, module: str, options: dict):
        raise NotImplementedError("MSF RPC adapter is reserved for the Metasploit integration layer.")

    def call_module(self, module: str, target: str):
        return self.execute_module(module, {"RHOSTS": target})
