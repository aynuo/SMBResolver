"""Plugin base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class Plugin(ABC):
    """A scan step executed per host.

    ``run`` receives the context accumulated by earlier plugins (it contains
    ``host`` and ``timeout``) and returns a dict that the runner merges into it.
    Returning ``{"abort": True}`` stops further plugins for that host.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short plugin name."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human readable description."""

    @property
    @abstractmethod
    def requires_auth(self) -> bool:
        """Whether the plugin needs credentials."""

    @abstractmethod
    def run(self, host: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Execute against ``host`` and return new context entries."""
