"""
/scan-file endpoint
Accepts an uploaded file and returns a full safety report.
"""

import asyncio
import base64
import binascii
import hashlib
import os
from fastapi import APIRouter, UploadFile, File, HTTPException

from models.schemas import FileScanBase64Request, FileScanResponse
from services import virustotal, ml_service
from services.risk_scorer import compute_file_risk
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger(__name__)

MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB (VT free tier limit)
READ_CHUNK_SIZE = 1024 * 1024


class InvalidUploadError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def _http_upload_error(status_code: int, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": "invalid_upload", "message": message})


async def _read_upload_bytes(upload: UploadFile) -> bytes:
    if upload is None:
        raise InvalidUploadError(400, "No file was provided")

    try:
        await upload.seek(0)
    except Exception:
        logger.warning("Upload stream is not seekable for file: %s", getattr(upload, "filename", "unknown"))

    data = bytearray()
    try:
        while True:
            chunk = await upload.read(READ_CHUNK_SIZE)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_FILE_SIZE:
                raise InvalidUploadError(
                    413,
                    f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB",
                )
    except InvalidUploadError:
        raise
    except Exception as exc:
        logger.exception("Failed to read multipart upload for file: %s", upload.filename)
        raise InvalidUploadError(400, f"Could not read uploaded file stream: {exc}") from exc

    if not data:
        raise InvalidUploadError(400, "Empty file")

    return bytes(data)


def _decode_base64_payload(content_base64: str) -> bytes:
    try:
        return base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidUploadError(400, "Invalid base64 payload") from exc


async def _scan_file_bytes(file_bytes: bytes, filename: str) -> FileScanResponse:
    ext = os.path.splitext(filename)[-1] or ".unknown"

    md5 = hashlib.md5(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    logger.info(f"File hashes — MD5: {md5} | SHA256: {sha256}")

    vt_result, (ml_prediction, ml_confidence) = await asyncio.gather(
        virustotal.scan_file_hash(md5, sha256),
        asyncio.to_thread(ml_service.predict, file_bytes, filename),
    )

    if vt_result.get("status") == "unknown" and not vt_result.get("error"):
        logger.info(f"Unknown hash — uploading to VirusTotal: {filename}")
        vt_result = await virustotal.upload_file(file_bytes, filename)

    entropy = ml_service.calculate_entropy(file_bytes)

    score, status, message = compute_file_risk(
        vt_result=vt_result,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        entropy=entropy,
        extension=ext,
    )

    return FileScanResponse(
        filename=filename,
        file_size=len(file_bytes),
        md5=md5,
        sha256=sha256,
        status=status,
        risk_score=score,
        positives=vt_result.get("positives", 0),
        total_engines=vt_result.get("total", 0),
        ml_prediction=ml_prediction,
        ml_confidence=round(ml_confidence, 4),
        virustotal_permalink=vt_result.get("permalink"),
        entropy=entropy,
        extension=ext,
        message=message,
    )


@router.post("/scan-file", response_model=FileScanResponse)
async def scan_file(file: UploadFile = File(...)):
    """
    Scan an uploaded file for malware.

    - Extracts MD5 + SHA256 hash
    - Checks hash against VirusTotal (no upload if already known)
    - Runs local ML model for additional classification
    - Calculates Shannon entropy (packed/encrypted = suspicious)
    - Returns a risk score and verdict

    Developer note:
    On Windows Git Bash, `curl -F` may fail with `curl: (26) read error getting mime data`.
    If this happens, use PowerShell/Postman, or call `/scan-file-base64`.
    """
    filename = (file.filename or "unknown").strip() or "unknown"
    logger.info("Scanning file (multipart): %s", filename)

    try:
        file_bytes = await _read_upload_bytes(file)
        return await _scan_file_bytes(file_bytes, filename)
    except InvalidUploadError as exc:
        logger.warning("Invalid multipart upload for %s: %s", filename, exc.message)
        raise _http_upload_error(exc.status_code, exc.message)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("File scan failed for multipart upload: %s", filename)
        raise HTTPException(
            status_code=500,
            detail={"error": "scan_failed", "message": f"File scanning failed: {exc}"},
        )
    finally:
        await file.close()


@router.post("/scan-file-base64", response_model=FileScanResponse)
async def scan_file_base64(request: FileScanBase64Request):
    """
    Scan a file from base64-encoded content.

    Recommended for cross-platform test automation when multipart uploads are flaky.
    """
    filename = request.filename.strip() or "unknown"
    logger.info("Scanning file (base64): %s", filename)

    try:
        file_bytes = _decode_base64_payload(request.content_base64)
        if not file_bytes:
            raise InvalidUploadError(400, "Empty file")
        if len(file_bytes) > MAX_FILE_SIZE:
            raise InvalidUploadError(
                413,
                f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB",
            )
        return await _scan_file_bytes(file_bytes, filename)
    except InvalidUploadError as exc:
        logger.warning("Invalid base64 upload for %s: %s", filename, exc.message)
        raise _http_upload_error(exc.status_code, exc.message)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("File scan failed for base64 upload: %s", filename)
        raise HTTPException(
            status_code=500,
            detail={"error": "scan_failed", "message": f"File scanning failed: {exc}"},
        )
