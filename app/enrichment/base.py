"""Common interface for enrichment providers."""
from abc import ABC, abstractmethod
from typing import Iterable


class EnrichmentProvider(ABC):
    name: str = ""
    supported_types: Iterable[str] = ()

    def is_configured(self) -> bool:
        """Return True if the provider can run (e.g., API key present)."""
        return True

    def supports(self, entity_type: str) -> bool:
        return entity_type in self.supported_types

    @abstractmethod
    def enrich(self, entity_type: str, entity_value: str) -> dict:
        """Return a JSON-serializable dict of enrichment results.

        Raise an exception on failure; the runner records the error.
        """
