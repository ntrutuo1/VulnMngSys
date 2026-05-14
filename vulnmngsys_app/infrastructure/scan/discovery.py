from __future__ import annotations

from dataclasses import dataclass

from ...domain.contracts import ConfigReader, PathSelector
from ...domain.models import ModuleDefinition


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    resolved_paths: dict[str, str]
    config_texts: dict[str, str]


class DiscoveryEngine:
    def __init__(self, path_selector: PathSelector, config_reader: ConfigReader) -> None:
        self._path_selector = path_selector
        self._config_reader = config_reader

    def discover(self, module: ModuleDefinition) -> DiscoveryResult:
        resolved_paths = {
            key: self._path_selector.resolve(paths) for key, paths in module.config_paths.items()
        }

        config_texts: dict[str, str] = {}
        for key, path in resolved_paths.items():
            config_texts[key] = self._config_reader.read_text(path)

        return DiscoveryResult(resolved_paths=resolved_paths, config_texts=config_texts)