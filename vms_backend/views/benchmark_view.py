class BenchmarkView:
    def __init__(self, rule_repository):
        self.rule_repository = rule_repository

    def get_benchmarks(self):
        try:
            return 200, self.rule_repository.list_benchmarks()
        except Exception as e:
            return 500, {"error": str(e)}
