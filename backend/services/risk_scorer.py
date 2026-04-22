"""
Risk Scoring Engine
Combines signals from VirusTotal, Google Safe Browsing, and ML model
into a single risk score (0–100) and SafetyStatus.
"""

from models.schemas import SafetyStatus
from config import get_settings
from utils.logger import setup_logger

settings = get_settings()
logger = setup_logger(__name__)


def compute_url_risk(vt_result: dict, gsb_threat: str | None) -> tuple[int, SafetyStatus, str]:
    score = 0
    reasons = []

    total = vt_result.get("total", 1) or 1
    positives = vt_result.get("positives", 0)
    malicious = vt_result.get("malicious", 0)

    vt_ratio = positives / total
    vt_score = int(vt_ratio * 70)

    # Make sure any non-zero VT detections move the score meaningfully.
    if positives > 0:
        vt_score = max(vt_score, 12)

    # Apply stronger penalties as detections increase.
    if positives >= 3:
        vt_score += 12
    if positives >= 5:
        vt_score += 20

    if malicious >= 3:
        vt_score += 10
        reasons.append(f"{malicious} antivirus engines flagged this URL as malicious")
    elif positives > 0:
        reasons.append(f"{positives} out of {total} engines flagged this URL")

    score += min(vt_score, 90)

    if gsb_threat:
        score = min(score + 20, 100)
        reasons.append(f"Google Safe Browsing: {gsb_threat.replace('_', ' ').title()}")

    score = max(0, min(score, 100))

    if not reasons:
        reasons.append("No threats detected by any engine")

    status = _score_to_status(score)

    # Hard safety rules: detections override score-based classification.
    if positives >= 5:
        status = SafetyStatus.MALICIOUS
    elif positives >= 1 and status == SafetyStatus.SAFE:
        status = SafetyStatus.SUSPICIOUS

    if malicious >= 3:
        status = SafetyStatus.MALICIOUS

    if gsb_threat and status == SafetyStatus.SAFE:
        status = SafetyStatus.SUSPICIOUS

    if any("flagged as malicious" in reason.lower() for reason in reasons) and status == SafetyStatus.SAFE:
        status = SafetyStatus.SUSPICIOUS

    if status == SafetyStatus.SAFE:
        message = "No threats detected by any engine"
    else:
        message = " | ".join(reasons)

    logger.info(
        "URL risk decision | positives=%s total_engines=%s malicious=%s score=%s status=%s",
        positives,
        total,
        malicious,
        score,
        status.value,
    )
    return score, status, message


def compute_file_risk(
    vt_result: dict,
    ml_prediction: str,
    ml_confidence: float,
    entropy: float,
    extension: str,
) -> tuple[int, SafetyStatus, str]:
    score = 0
    reasons = []

    total = vt_result.get("total", 1) or 1
    positives = vt_result.get("positives", 0)
    vt_ratio = positives / total
    vt_score = int(vt_ratio * 60)
    if positives > 0:
        score += vt_score
        reasons.append(f"VirusTotal: {positives}/{total} engines flagged")

    if ml_prediction == "malicious":
        ml_score = int(ml_confidence * 25)
        score += ml_score
        reasons.append(f"ML model: malicious ({ml_confidence:.0%} confidence)")

    if entropy > 7.5:
        score += 10
        reasons.append(f"High file entropy ({entropy:.2f}) — possibly packed")
    elif entropy > 7.0:
        score += 5

    HIGH_RISK_EXTENSIONS = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".jar", ".apk"}
    MEDIUM_RISK_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".dmg", ".msi"}

    if extension.lower() in HIGH_RISK_EXTENSIONS:
        score += 5
        reasons.append(f"High-risk file extension: {extension}")
    elif extension.lower() in MEDIUM_RISK_EXTENSIONS:
        score += 2

    score = max(0, min(score, 100))

    if not reasons:
        reasons.append("No threats detected")

    status = _score_to_status(score)
    message = " | ".join(reasons)
    return score, status, message


def _score_to_status(score: int) -> SafetyStatus:
    if score >= settings.malicious_threshold:
        return SafetyStatus.MALICIOUS
    elif score >= settings.suspicious_threshold:
        return SafetyStatus.SUSPICIOUS
    else:
        return SafetyStatus.SAFE
