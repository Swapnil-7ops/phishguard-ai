"""
services/threat_intelligence/base.py - Base Threat Intelligence Provider Abstraction

WHAT: Defines the common interface and normalized data structures for all
      external threat intelligence providers (e.g. VirusTotal, Google Safe Browsing).
WHY:  Ensures that the core detection pipeline consumes uniform, vendor-agnostic
      indicators without coupling to provider-specific JSON schemas.
HOW:  Abstract base class ThreatIntelProvider with lookup_url() method returning
      a standardized dictionary representation.

IMPORTANT:
- No provider is allowed to perform arbitrary HTTP requests to user-submitted websites.
- Providers must normalize all response codes (404, 429, timeout, error) safely.
- Never include sensitive API keys or credentials in normalized results.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class ThreatIntelResult:
    """
    Standardized result structure for a threat intelligence lookup.
    """
    provider: str
    status: str  # 'success' | 'not_configured' | 'rate_limited' | 'timeout' | 'error' | 'not_found'
    queried: bool = False
    malicious: bool = False
    suspicious: bool = False
    detections: int = 0
    suspicious_detections: int = 0
    harmless_detections: int = 0
    undetected: int = 0
    total_engines: int = 0
    reputation: int = 0
    categories: List[str] = field(default_factory=list)
    error: Optional[str] = None
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to serializable dictionary."""
        return asdict(self)


class ThreatIntelProvider(ABC):
    """
    Abstract base class for external threat intelligence providers.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider display name (e.g., 'VirusTotal')."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if provider credentials/configuration are active."""
        pass

    @abstractmethod
    def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        Query provider for reputation intelligence on the specified URL.

        Args:
            url: The normalized URL string to evaluate.

        Returns:
            ThreatIntelResult containing normalized findings.
        """
        pass
