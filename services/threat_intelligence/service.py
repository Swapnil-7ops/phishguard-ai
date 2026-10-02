"""
services/threat_intelligence/service.py - Central Threat Intelligence Orchestration Service

WHAT: Central dispatcher that coordinates threat intelligence lookups across
      configured providers (VirusTotal), checks the in-memory TTL cache,
      normalizes provider statuses, and computes bounded risk modifiers.
WHY:  Decouples the core ML/rule detection engines from external network dependencies.
      Ensures that external API failures, timeouts, or unconfigured states NEVER
      disrupt or degrade local phishing analysis.

IMPORTANT:
- The service will NEVER contact destination user URLs.
- Provider errors, timeouts, rate limits, or missing keys contribute exactly 0 risk points.
- Bounded risk adjustment (+8 or +15) is ONLY applied when a provider successfully
  responds with genuine malicious detection counts.
"""
import logging
from typing import Dict, Any, List, Optional

from config import config
from services.threat_intelligence.base import ThreatIntelProvider, ThreatIntelResult
from services.threat_intelligence.virustotal import VirusTotalProvider
from services.threat_intelligence.cache import SimpleThreatIntelCache

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    Orchestration service for external threat intelligence providers.
    """

    def __init__(
        self,
        providers: Optional[List[ThreatIntelProvider]] = None,
        cache: Optional[SimpleThreatIntelCache] = None,
        timeout_sec: Optional[float] = None
    ):
        self._timeout_sec = timeout_sec if timeout_sec is not None else config.THREAT_INTEL_TIMEOUT_SEC
        self._cache = cache if cache is not None else SimpleThreatIntelCache(
            default_ttl_sec=config.THREAT_INTEL_CACHE_TTL_SEC
        )

        if providers is not None:
            self._providers = providers
        else:
            # Auto-register configured providers from environment
            self._providers = []
            if config.VIRUSTOTAL_API_KEY:
                self._providers.append(
                    VirusTotalProvider(config.VIRUSTOTAL_API_KEY, timeout_sec=self._timeout_sec)
                )

    @property
    def is_enabled(self) -> bool:
        """Return True if at least one active provider is configured."""
        return any(p.is_configured() for p in self._providers)

    def get_providers(self) -> List[ThreatIntelProvider]:
        return list(self._providers)

    def lookup_url(self, url: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute reputation lookup across active threat intelligence providers.

        Args:
            url: Normalized target URL.
            use_cache: If True, check memory cache before issuing network calls.

        Returns:
            Structured dictionary containing provider results, aggregate summary,
            and calculated bounded risk points.
        """
        if not self.is_enabled:
            return {
                "enabled": False,
                "queried": False,
                "providers": [
                    {
                        "provider": "VirusTotal",
                        "status": "not_configured",
                        "queried": False,
                        "malicious": False,
                        "suspicious": False,
                        "detections": 0,
                        "total_engines": 0,
                        "reputation": 0,
                        "error": "VirusTotal API key is not configured.",
                        "error_code": "NOT_CONFIGURED"
                    }
                ],
                "summary": {
                    "status": "not_configured",
                    "malicious": False,
                    "suspicious": False,
                    "detections": 0,
                    "total_engines": 0,
                    "reputation": 0,
                    "risk_points": 0,
                    "description": "Threat Intelligence is not configured. Local ML and heuristic detection active."
                }
            }

        # Check Cache
        clean_url = (url or "").strip()
        if use_cache and clean_url:
            cached = self._cache.get(clean_url)
            if cached is not None:
                logger.debug(f"Threat intelligence cache hit for: {clean_url}")
                return self._assemble_response([cached], is_cached=True)

        # Execute Provider Lookups
        provider_results: List[ThreatIntelResult] = []
        for provider in self._providers:
            try:
                res = provider.lookup_url(clean_url)
                provider_results.append(res)
                # Cache successful or definitive responses
                if use_cache and res.status in ("success", "not_found"):
                    self._cache.set(clean_url, res)
            except Exception as e:
                logger.error(f"Unhandled exception in provider {provider.name}: {e}")
                provider_results.append(
                    ThreatIntelResult(
                        provider=provider.name,
                        status="error",
                        queried=False,
                        error=f"Internal provider dispatch failure: {str(e)}",
                        error_code="INTERNAL_DISPATCH_ERROR"
                    )
                )

        return self._assemble_response(provider_results, is_cached=False)

    def _assemble_response(
        self,
        results: List[ThreatIntelResult],
        is_cached: bool = False
    ) -> Dict[str, Any]:
        """Normalize multiple provider results into a unified envelope."""
        provider_dicts = [r.to_dict() for r in results]

        # Determine primary / aggregate statistics
        successful_results = [r for r in results if r.status == "success"]
        max_detections = max((r.detections for r in successful_results), default=0)
        total_engines = max((r.total_engines for r in successful_results), default=0)
        min_reputation = min((r.reputation for r in successful_results), default=0)
        is_malicious = any(r.malicious for r in successful_results)
        is_suspicious = any(r.suspicious for r in successful_results)

        # Primary operational status
        if successful_results:
            overall_status = "success"
            if is_malicious:
                desc = f"Threat intelligence reported {max_detections} malicious detection(s) across {total_engines} security engines."
            else:
                desc = f"No malicious detections reported across {total_engines} queried security engines."
        elif any(r.status == "rate_limited" for r in results):
            overall_status = "rate_limited"
            desc = "External threat intelligence rate limit exceeded. Analysis completed using local ML and rules."
        elif any(r.status == "timeout" for r in results):
            overall_status = "timeout"
            desc = "External threat intelligence provider timed out. Analysis completed using local ML and rules."
        elif any(r.status == "not_found" for r in results):
            overall_status = "not_found"
            desc = "URL is not currently indexed in external threat intelligence repositories."
        elif any(r.status == "connection_error" for r in results):
            overall_status = "connection_error"
            desc = "Could not establish connection to threat intelligence endpoint. Analysis preserved locally."
        elif any(r.status == "not_configured" for r in results):
            overall_status = "not_configured"
            desc = "Threat intelligence provider is not configured."
        else:
            overall_status = "error"
            desc = "Threat intelligence lookup encountered an error. Local detection preserved."

        # Calculate bounded risk points (CRITICAL: 0 for all error/unconfigured/clean states)
        risk_points = self.calculate_ti_risk_points(overall_status, max_detections)

        return {
            "enabled": True,
            "queried": any(r.queried for r in results),
            "cached": is_cached,
            "providers": provider_dicts,
            "summary": {
                "status": overall_status,
                "malicious": is_malicious,
                "suspicious": is_suspicious,
                "detections": max_detections,
                "total_engines": total_engines,
                "reputation": min_reputation,
                "risk_points": risk_points,
                "description": desc
            }
        }

    @staticmethod
    def calculate_ti_risk_points(status: str, detections: int) -> int:
        """
        Determine bounded risk modifier points.

        Strict Rules:
        - Must contribute EXACTLY 0 points for:
          'not_configured', 'timeout', 'connection_error', 'rate_limited',
          'error', 'not_found', or 0 detections.
        - Only applies bounded points for valid 'success' with detections:
          - detections >= 5: +15 points
          - 1 <= detections < 5: +8 points
        """
        if status != "success" or detections <= 0:
            return 0
        if detections >= 5:
            return 15
        elif detections >= 1:
            return 8
        return 0


# Module-level singleton instance for runtime access
_DEFAULT_SERVICE: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    """Retrieve or lazily initialize the default ThreatIntelService."""
    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        _DEFAULT_SERVICE = ThreatIntelService()
    return _DEFAULT_SERVICE


def reset_threat_intel_service() -> None:
    """Reset the singleton instance (useful for unit test isolation)."""
    global _DEFAULT_SERVICE
    _DEFAULT_SERVICE = None
