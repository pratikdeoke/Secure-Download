"""
/get-report endpoint
Fetches an existing VirusTotal report by hash or URL.
"""

from fastapi import APIRouter, HTTPException

from models.schemas import ReportRequest, ReportResponse, SafetyStatus
from services import virustotal
from services.risk_scorer import _score_to_status
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger(__name__)


@router.post("/get-report", response_model=ReportResponse)
async def get_report(request: ReportRequest):
    """
    Fetch an existing VirusTotal report by SHA256 hash or URL.
    Useful for checking previously scanned files without re-scanning.
    """
    resource = request.resource
    logger.info(f"Fetching report for: {resource}")

    try:
        result = await virustotal.get_report(resource)
    except Exception as e:
        logger.error(f"Report fetch failed: {e}")
        raise HTTPException(status_code=502, detail=f"VirusTotal error: {str(e)}")

    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])

    positives = result.get("positives", 0)
    total = result.get("total", 0)
    ratio = positives / max(total, 1)
    score = int(ratio * 80)
    status = _score_to_status(score)

    message = (
        f"{positives}/{total} engines flagged this resource"
        if positives > 0
        else "No threats detected"
    )

    return ReportResponse(
        resource=resource,
        status=status,
        positives=positives,
        total_engines=total,
        scan_date=str(result.get("scan_date", "")),
        virustotal_permalink=result.get("permalink"),
        details=result.get("details"),
        message=message,
    )
