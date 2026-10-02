"""
services/threat_intelligence package

Exposes:
- ThreatIntelService, get_threat_intel_service, reset_threat_intel_service
- ThreatIntelProvider, ThreatIntelResult
- VirusTotalProvider
- SimpleThreatIntelCache
"""
from services.threat_intelligence.base import ThreatIntelProvider, ThreatIntelResult
from services.threat_intelligence.virustotal import VirusTotalProvider
from services.threat_intelligence.cache import SimpleThreatIntelCache
from services.threat_intelligence.service import (
    ThreatIntelService,
    get_threat_intel_service,
    reset_threat_intel_service,
)

__all__ = [
    "ThreatIntelProvider",
    "ThreatIntelResult",
    "VirusTotalProvider",
    "SimpleThreatIntelCache",
    "ThreatIntelService",
    "get_threat_intel_service",
    "reset_threat_intel_service",
]
