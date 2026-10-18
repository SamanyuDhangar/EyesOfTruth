from abc import ABC, abstractmethod


class ThreatProvider(ABC):
    """Base interface for optional threat-intelligence providers."""

    name = "Unnamed provider"

    @abstractmethod
    def check_url(self, url):
        """
        Check a URL using a provider.

        Return a dictionary with:
        - available: whether the provider completed a check
        - malicious: True, False, or None if unknown
        - message: a short explanation
        """
        pass
