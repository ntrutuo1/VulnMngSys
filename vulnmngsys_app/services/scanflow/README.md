# Application Scan Flow

`vulnmngsys_app.services.scanflow` contains scan use cases and rule/report workflows.

- `scanner.py`: runs a selected rule profile and writes merged scan rows.
- `report_builder.py`: builds the JSON report consumed by the UI.
- `json_rule_engine.py`: loads JSON rules, collects Windows snapshots, and evaluates rules.
- `reconfig.py`: previews and applies remediation scripts.
- `progress.py`: tracks live scan progress for controllers.
- `rule_catalog.py`: resolves benchmark profiles and manifests.
- `service_tree.py`: groups scan results by service for the UI.
- `msf_audit/`: IIS Metasploit audit workflow.
- `facades/`: compatibility facade for CLI/desktop callers.

Controllers should call this package through public functions/classes only.
