"""Dynamic plugin discovery (``NN_name.py`` files, sorted by prefix)."""
from __future__ import annotations

import importlib.util
import inspect
import re
from pathlib import Path
from typing import List, Optional

from smbscan.plugins.base import Plugin

_PATTERN = re.compile(r"^(\d+)_.+\.py$")


def discover_plugins(directory: Optional[Path] = None) -> List[Plugin]:
    """Load and instantiate every plugin in ``directory``, in filename order."""
    directory = directory or Path(__file__).parent
    files = sorted((p for p in directory.iterdir() if _PATTERN.match(p.name)),
                   key=lambda p: p.name)
    plugins: List[Plugin] = []
    for path in files:
        spec = importlib.util.spec_from_file_location(f"smbscan.plugins._{path.stem}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load plugin {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if (issubclass(cls, Plugin) and cls is not Plugin
                    and cls.__module__ == module.__name__ and not inspect.isabstract(cls)):
                plugins.append(cls())
    return plugins
