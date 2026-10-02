"""
llm_service.py - Optional LLM-Powered Natural Language Explanation Service

WHAT: Translates technical ML probability distributions and rule telemetry into
     approachable, plain-English educational explanations.
WHY: End users and non-technical stakeholders benefit from conversational context
     explaining *why* a particular URL or message was deemed hazardous.
CRITICAL ARCHITECTURAL PRINCIPLE:
  - The LLM does NOT classify the URL or message.
  - The LLM does NOT override the Machine Learning model or Rule Engine results.
  - The LLM receives ONLY pre-computed structured telemetry (prediction, risk score, triggered rules).
  - The service is strictly OPTIONAL and fails gracefully if no API key is set.
INPUT: Structured analysis result dictionary.
OUTPUT: Plain-language explanation string (or None if unconfigured).
LIMITATIONS:
  - Requires valid OPENAI_API_KEY or GEMINI_API_KEY.
  - Network latency of 1-3 seconds per invocation.
"""
import logging
from typing import Dict, Any, Optional

from config import config

logger = logging.getLogger(__name__)


def is_llm_enabled() -> bool:
    """Check whether an LLM provider and API key are configured."""
    provider = config.LLM_PROVIDER
    if provider == 'gemini' and config.GEMINI_API_KEY:
        return True
    if provider == 'openai' and config.OPENAI_API_KEY:
        return True
    return False


def generate_llm_explanation(analysis_result: Dict[str, Any]) -> Optional[str]:
    """
    Generate plain-language explanation from structured analysis findings.

    Args:
        analysis_result: The completed dictionary from url_analyzer or message_analyzer.

    Returns:
        String explanation or None if unconfigured or failed.
    """
    if not is_llm_enabled():
        return None

    # Construct clean, structured summary payload (do NOT pass unvalidated arbitrary prompts)
    summary_payload = {
        "prediction": analysis_result.get("prediction", "Unknown"),
        "confidence": analysis_result.get("confidence", 0.5),
        "risk_score": analysis_result.get("risk_score", 0),
        "risk_level": analysis_result.get("risk_level", "Unknown"),
        "triggered_indicators": [
            r.get("name") for r in analysis_result.get("triggered_rules", [])
        ] or [
            ind.get("name") for ind in analysis_result.get("detected_indicators", [])
        ]
    }

    prompt = (
        "You are an explainable cybersecurity assistant for PhishGuard AI.\n"
        "Explain the following detection findings to an everyday computer user in 2 to 3 clear, reassuring sentences.\n"
        "Do not invent facts or cite features not present in this telemetry. Remind them of safe next steps.\n\n"
        f"Telemetry:\n{summary_payload}"
    )

    provider = config.LLM_PROVIDER
    try:
        if provider == 'gemini':
            import google.generativeai as genai
            genai.configure(api_key=config.GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash')
            resp = model.generate_content(prompt)
            return resp.text.strip()

        elif provider == 'openai':
            from openai import OpenAI
            client = OpenAI(api_key=config.OPENAI_API_KEY)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=250,
                temperature=0.3
            )
            return resp.choices[0].message.content.strip()

    except Exception as e:
        logger.warning(f"LLM explanation service encountered an error: {e}")
        return None

    return None
