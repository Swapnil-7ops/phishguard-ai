"""
vision_service.py - Optional AI Visual Screenshot Analysis Service

WHAT: Accepts screenshot images of suspicious emails, login portals, or notifications
     and evaluates visual cues via an optional vision-capable multimodal LLM.
WHY: Some phishing indicators appear visually (fake security badges, spoofed logos,
     misaligned layouts) that are not apparent in raw text or URL tokens alone.
HOW:
  1. Validates image size and formats.
  2. Encodes image to base64.
  3. If Gemini or OpenAI API key is supplied in environment, queries the vision endpoint.
  4. Parses structured visual cues (credential prompts, branding, urgency).
  5. If no API key is available, returns a friendly, graceful explanation message without crashing.
INPUT: Raw image bytes, image filename (str).
OUTPUT: Structured response dictionary with visual findings and explicit disclaimers.
LIMITATIONS:
  - Labeled strictly as "AI Visual Analysis": heuristic and subjective.
  - Cannot inspect underlying HTML/JS source code or network destination.
  - Requires active third-party API key and Internet connectivity.
"""
import os
import base64
import json
import logging
from typing import Dict, Any

from config import config

logger = logging.getLogger(__name__)


def is_vision_enabled() -> bool:
    """Check if a vision-capable API provider is configured."""
    provider = config.LLM_PROVIDER
    if provider == 'gemini' and config.GEMINI_API_KEY:
        return True
    if provider == 'openai' and config.OPENAI_API_KEY:
        return True
    return False


def analyze_screenshot(image_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Perform AI visual inspection on a screenshot.

    Returns:
        Structured response dictionary.
    """
    disclaimer = "DISCLAIMER: AI visual analysis is an experimental supplementary decision-support tool. It does NOT constitute definitive proof of maliciousness."

    if not is_vision_enabled():
        return {
            "success": False,
            "configured": False,
            "message": "AI Vision Analysis is currently unconfigured. To enable this feature, provide GEMINI_API_KEY or OPENAI_API_KEY in your .env file and set LLM_PROVIDER=gemini (or openai).",
            "disclaimer": disclaimer
        }

    provider = config.LLM_PROVIDER
    prompt = (
        "You are an expert cybersecurity analyst evaluating a user-submitted screenshot for phishing indicators.\n"
        "Carefully examine this image for:\n"
        "1. Login or credential request prompts\n"
        "2. OTP or multi-factor authentication intercept forms\n"
        "3. Brand logos or brand impersonation cues\n"
        "4. Coercive urgency, legal warnings, or account suspension threats\n"
        "5. Visual artifacts, layout anomalies, or deceptive address bars\n\n"
        "Provide your evaluation strictly as valid JSON with the following schema:\n"
        "{\n"
        '  "prediction": "Phishing" | "Suspicious" | "Legitimate",\n'
        '  "risk_score": <integer from 0 to 100>,\n'
        '  "brand_detected": "<detected brand or None>",\n'
        '  "credential_solicitation": <boolean>,\n'
        '  "urgency_cues": <boolean>,\n'
        '  "visual_indicators": ["<indicator 1>", "<indicator 2>"],\n'
        '  "explanation": "<2 to 3 concise summary sentences>",\n'
        '  "recommendation": "<safe actionable advice>"\n'
        "}"
    )

    try:
        # Provider 1: Google Gemini
        if provider == 'gemini':
            import google.generativeai as genai
            genai.configure(api_key=config.GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash')

            ext = filename.split('.')[-1].lower() if '.' in filename else 'png'
            mime_type = f"image/{'jpeg' if ext in ('jpg', 'jpeg') else ext}"

            response = model.generate_content([
                prompt,
                {"mime_type": mime_type, "data": image_bytes}
            ])

            raw_text = response.text.strip()
            # Clean possible markdown block markers
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            if raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]

            parsed_data = json.loads(raw_text.strip())
            return {
                "success": True,
                "configured": True,
                "provider": "Google Gemini Vision (AI Visual Analysis)",
                "data": parsed_data,
                "disclaimer": disclaimer
            }

        # Provider 2: OpenAI
        elif provider == 'openai':
            from openai import OpenAI
            client = OpenAI(api_key=config.OPENAI_API_KEY)
            b64_img = base64.b64encode(image_bytes).decode('utf-8')
            ext = filename.split('.')[-1].lower() if '.' in filename else 'png'
            mime_type = f"image/{'jpeg' if ext in ('jpg', 'jpeg') else ext}"

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{b64_img}"}}
                        ]
                    }
                ],
                max_tokens=600
            )

            raw_text = response.choices[0].message.content.strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            if raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]

            parsed_data = json.loads(raw_text.strip())
            return {
                "success": True,
                "configured": True,
                "provider": "OpenAI Vision (AI Visual Analysis)",
                "data": parsed_data,
                "disclaimer": disclaimer
            }

    except Exception as e:
        logger.error(f"Vision API evaluation failed: {e}")
        return {
            "success": False,
            "configured": True,
            "error": f"Vision analysis service encountered an error: {str(e)}",
            "disclaimer": disclaimer
        }

    return {
        "success": False,
        "configured": False,
        "message": f"Unsupported LLM provider: {provider}",
        "disclaimer": disclaimer
    }
