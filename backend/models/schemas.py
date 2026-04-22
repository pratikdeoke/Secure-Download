"""
Pydantic request / response schemas.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl


class SafetyStatus(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


# ─── Request models ───────────────────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str
    filename: Optional[str] = None


class ReportRequest(BaseModel):
    resource: str  # SHA256 hash or URL


class FileScanBase64Request(BaseModel):
    filename: str = Field(..., min_length=1, description="Original file name, including extension")
    content_base64: str = Field(..., min_length=1, description="Base64-encoded file content")


# ─── Response models ──────────────────────────────────────────────────────────

class URLScanResponse(BaseModel):
    url: str
    status: SafetyStatus
    risk_score: int
    positives: int
    total_engines: int
    virustotal_permalink: Optional[str] = None
    google_safe_browsing: Optional[str] = None
    cached: bool = False
    message: str


class FileScanResponse(BaseModel):
    filename: str
    file_size: int
    md5: str
    sha256: str
    status: SafetyStatus
    risk_score: int
    positives: int
    total_engines: int
    ml_prediction: str
    ml_confidence: float
    virustotal_permalink: Optional[str] = None
    entropy: float
    extension: str
    message: str


class ReportResponse(BaseModel):
    resource: str
    status: SafetyStatus
    positives: int
    total_engines: int
    scan_date: Optional[str] = None
    virustotal_permalink: Optional[str] = None
    details: Optional[dict] = None
    message: str
