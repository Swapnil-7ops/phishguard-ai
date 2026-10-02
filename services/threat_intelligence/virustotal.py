"""
services/threat_intelligence/virustotal.py - VirusTotal v3 API Integration

WHAT: Queries VirusTotal v3 API for URL reputation and aggregated AV detections.
WHY:  Enriches local feature-based and ML-based phishing analysis with historical
      threat telemetry from 70+ security vendors and URL blocklists.
HOW:  Encodes URL into VirusTotal's base64 identifier, queries the /urls/{id} endpoint
      using HTTPS, and normalizes the response into ThreatIntelResult.

SECURITY:
- Never contacts user-submitted destination websites.
- Queries strictly the official VirusTotal v3 HTTPS API endpoint.
- Strictly adheres to configured connection/read timeout (default 5.0s).
- Masks API keys; never writes them to logs or persistent scan documents.
"""
import base64
import logging
import requests
from typing import Optional
from services.threat_intelligence.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger(__name__)


def url_to_vt_id(url: str) -> str:
    """
    Encode URL into VirusTotal v3 URL identifier format:
    URL-safe base64 string without trailing padding ('=').
    """
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal v3 URL Threat Intelligence Provider.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, api_key: str, timeout_sec: float = 5.0):
        self._api_key = (api_key or "").strip()
        self._timeout_sec = max(1.0, float(timeout_sec))

    @property
    def name(self) -> str:
        return "VirusTotal"

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        Query VirusTotal v3 API for reputation and analysis statistics on url.
        """
        if not self.is_configured():
            return ThreatIntelResult(
                provider=self.name,
                status="not_configured",
                queried=False,
                error="VirusTotal API key is not configured.",
                error_code="NOT_CONFIGURED"
            )

        if not url or not isinstance(url, str):
            return ThreatIntelResult(
                provider=self.name,
                status="error",
                queried=False,
                error="Invalid URL string provided for Threat Intelligence lookup.",
                error_code="INVALID_URL"
            )

        vt_id = url_to_vt_id(url)
        endpoint = f"{self.BASE_URL}/{vt_id}"
        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(endpoint, headers=headers, timeout=self._timeout_sec)

            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                total = malicious + suspicious + harmless + undetected

                reputation = int(attrs.get("reputation", 0))
                cats = list(attrs.get("categories", {}).values())

                return ThreatIntelResult(
                    provider=self.name,
                    status="success",
                    queried=True,
                    malicious=(malicious > 0),
                    suspicious=(suspicious > 0 and malicious == 0),
                    detections=malicious,
                    suspicious_detections=suspicious,
                    harmless_detections=harmless,
                    undetected=undetected,
                    total_engines=total,
                    reputation=reputation,
                    categories=cats,
                    error=None,
                    error_code=None
                )

            elif response.status_code == 404:
                # URL is not currently indexed in VirusTotal's database
                return ThreatIntelResult(
                    provider=self.name,
                    status="not_found",
                    queried=True,
                    malicious=False,
                    suspicious=False,
                    detections=0,
                    total_engines=0,
                    error="URL not indexed in VirusTotal threat repository.",
                    error_code="NOT_FOUND"
                )

            elif response.status_code == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    status="rate_limited",
                    queried=True,
                    error="VirusTotal API request quota exceeded / rate limited.",
                    error_code="RATE_LIMITED"
                )

            elif response.status_code in (401, 403):
                return ThreatIntelResult(
                    provider=self.name,
                    status="error",
                    queried=True,
                    error="VirusTotal API key is invalid or unauthorized.",
                    error_code="INVALID_API_KEY"
                )

            else:
                return ThreatIntelResult(
                    provider=self.name,
                    status="error",
                    queried=True,
                    error=f"VirusTotal API returned HTTP {response.status_code}.",
                    error_code=f"HTTP_{response.status_code}"
                )

        except requests.exceptions.Timeout:
            logger.warning(f"VirusTotal lookup timed out after {self._timeout_sec}s for URL.")
            return ThreatIntelResult(
                provider=self.name,
                status="timeout",
                queried=True,
                error=f"VirusTotal lookup timed out after {self._timeout_sec}s.",
                error_code="TIMEOUT"
            )

        except requests.exceptions.ConnectionError as ce:
            logger.warning(f"VirusTotal connection error: {ce}")
            return ThreatIntelResult(
                provider=self.name,
                status="connection_error",
                queried=True,
                error="Failed to connect to VirusTotal API endpoint.",
                error_code="CONNECTION_ERROR"
            )

        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal: {e}")
            return ThreatIntelResult(
                provider=self.name,
                status="error",
                queried=True,
                error=f"Threat intelligence parsing error: {str(e)}",
                error_code="MALFORMED_RESPONSE"
            )
