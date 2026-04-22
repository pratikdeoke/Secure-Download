"""
Google Safe Browsing API integration.
Checks URLs against Google's threat database.
Optional — system works without a key.
"""

import httpx
from typing import Optional

from config import get_settings
from utils.logger import setup_logger

logger = setup_logger(__name__)
settings = get_settings()

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


async def check_url(url: str) -> Optional[str]:
    """
    Check a URL against Google Safe Browsing.
    Returns the threat type string if flagged, else None.
    """
    if not settings.google_safe_browsing_key:
        return None  # Key not configured — silently skip

    payload = {
        "client": {"clientId": "SecureDownloadAI", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                GSB_URL,
                params={"key": settings.google_safe_browsing_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                return matches[0].get("threatType", "THREAT_DETECTED")
    except Exception as e:
        logger.warning(f"Safe Browsing check failed: {e}")

    return None
