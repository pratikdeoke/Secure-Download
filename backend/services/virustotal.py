"""
VirusTotal API integration.
Handles URL scanning, file scanning, and report retrieval.
Free tier: 4 requests/minute — results are cached to respect this limit.
"""

import asyncio
import base64
from typing import Optional
import httpx

from config import get_settings
from utils.logger import setup_logger
from utils.cache import SimpleCache

logger = setup_logger(__name__)
settings = get_settings()

# In-memory cache to avoid re-scanning identical resources
_cache = SimpleCache(ttl=settings.cache_ttl)

VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": settings.virustotal_api_key}


def _url_id(url: str) -> str:
    """VirusTotal expects URL encoded as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def scan_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal and retrieve its analysis.
    Returns raw VT analysis result dict.
    """
    cache_key = f"url:{url}"
    if cached := _cache.get(cache_key):
        logger.info(f"Cache hit for URL: {url}")
        return {**cached, "cached": True}

    if not settings.virustotal_api_key:
        logger.warning("No VirusTotal API key configured — returning empty result")
        return _error_result("VirusTotal API key not configured")

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                f"{VT_BASE}/urls",
                headers=HEADERS,
                data={"url": url},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"VT URL submit failed: {e.response.status_code}")
            return _error_result("VirusTotal submission failed")

        analysis_id = resp.json()["data"]["id"]
        result = await _poll_analysis(client, analysis_id)

    _cache.set(cache_key, result)
    return result


async def scan_file_hash(md5: str, sha256: str) -> dict:
    """
    Check if a file hash is already known to VirusTotal.
    This avoids uploading the actual file (privacy + speed).
    """
    cache_key = f"hash:{sha256}"
    if cached := _cache.get(cache_key):
        return {**cached, "cached": True}

    if not settings.virustotal_api_key:
        return {"status": "unknown", "positives": 0, "total": 0, "permalink": None}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                f"{VT_BASE}/files/{sha256}",
                headers=HEADERS,
            )
            if resp.status_code == 404:
                return {"status": "unknown", "positives": 0, "total": 0, "permalink": None}
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"VT file hash lookup failed: {e}")
            return _error_result("Hash lookup failed")

        data = resp.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        result = _parse_stats(stats, data.get("permalink"))

    _cache.set(cache_key, result)
    return result


async def upload_file(file_bytes: bytes, filename: str) -> dict:
    """
    Upload a file to VirusTotal for analysis.
    Only called when the hash is not already known.
    """
    if not settings.virustotal_api_key:
        return _error_result("VirusTotal API key not configured")

    async with httpx.AsyncClient(timeout=60) as client:
        try:
            resp = await client.post(
                f"{VT_BASE}/files",
                headers=HEADERS,
                files={"file": (filename, file_bytes)},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"VT file upload failed: {e}")
            return _error_result("File upload failed")

        analysis_id = resp.json()["data"]["id"]
        return await _poll_analysis(client, analysis_id)


async def get_report(resource: str) -> dict:
    """Fetch an existing report by URL or SHA256."""
    async with httpx.AsyncClient(timeout=15) as client:
        for endpoint in [f"{VT_BASE}/files/{resource}", f"{VT_BASE}/urls/{_url_id(resource)}"]:
            try:
                resp = await client.get(endpoint, headers=HEADERS)
                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]
                    stats = data.get("last_analysis_stats", {})
                    return {
                        **_parse_stats(stats, data.get("permalink")),
                        "scan_date": data.get("last_analysis_date"),
                        "details": stats,
                    }
            except Exception:
                continue
    return _error_result("Report not found")


# ─── Private helpers ──────────────────────────────────────────────────────────

async def _poll_analysis(client: httpx.AsyncClient, analysis_id: str, max_attempts: int = 10) -> dict:
    """Poll a VT analysis until it completes or we time out."""
    for attempt in range(max_attempts):
        await asyncio.sleep(3)
        try:
            resp = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=HEADERS)
            resp.raise_for_status()
            data = resp.json()["data"]

            if data["attributes"]["status"] == "completed":
                stats = data["attributes"]["stats"]
                meta = data.get("meta", {}).get("url_info", {})
                permalink = f"https://www.virustotal.com/gui/url/{_url_id(meta.get('url', ''))}"
                return _parse_stats(stats, permalink)
        except Exception as e:
            logger.warning(f"Poll attempt {attempt+1} failed: {e}")

    return _error_result("Analysis timed out")


def _parse_stats(stats: dict, permalink: Optional[str]) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    return {
        "positives": malicious + suspicious,
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "permalink": permalink,
        "cached": False,
    }


def _error_result(message: str) -> dict:
    return {
        "positives": 0,
        "malicious": 0,
        "suspicious": 0,
        "total": 0,
        "permalink": None,
        "error": message,
        "cached": False,
    }
