from dataclasses import dataclass, field


@dataclass
class MetasploitModuleSpec:
    cve_id: str
    module_path: str
    module_type: str
    source_file: str
    required_options: dict = field(default_factory=dict)
    default_options: dict = field(default_factory=dict)
