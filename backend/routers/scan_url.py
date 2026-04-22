"""
/scan-url endpoint
Accepts a URL and returns a full safety report.
"""

import asyncio
from fastapi import APIRouter, HTTPException

from models.schemas import URLScanRequest, URLScanResponse
from services import virustotal, safe_browsing
from services.risk_scorer import compute_url_risk
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger(__name__)


@router.post("/scan-url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """
    Scan a URL for malware, phishing, and other threats.

    - Checks VirusTotal (70+ antivirus engines)
    - Checks Google Safe Browsing (if API key configured)
    - Returns a risk score and SAFE / SUSPICIOUS / MALICIOUS verdict
    """
    url = request.url
    logger.info(f"Scanning URL: {url}")

    try:
        vt_result, gsb_threat = await asyncio.gather(
            virustotal.scan_url(url),
            safe_browsing.check_url(url),
        )
    except Exception as e:
        logger.error(f"Scan failed for {url}: {e}")
        raise HTTPException(status_code=502, detail=f"External API error: {str(e)}")

    score, status, message = compute_url_risk(vt_result, gsb_threat)

    return URLScanResponse(
        url=url,
        status=status,
        risk_score=score,
        positives=vt_result.get("positives", 0),
        total_engines=vt_result.get("total", 0),
        virustotal_permalink=vt_result.get("permalink"),
        google_safe_browsing=gsb_threat,
        cached=vt_result.get("cached", False),
        message=message,
    )
