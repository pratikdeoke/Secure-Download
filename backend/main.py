"""
SecureDownload AI - FastAPI Backend
Entry point for the malware detection API service.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from routers import scan_url, scan_file, report
from utils.logger import setup_logger

logger = setup_logger(__name__)

app = FastAPI(
    title="SecureDownload AI",
    description="Real-time malware detection API for safe file downloads",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Allow Chrome extension and local frontend to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Lock this down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route groups
app.include_router(scan_url.router, prefix="/api/v1", tags=["URL Scanning"])
app.include_router(scan_file.router, prefix="/api/v1", tags=["File Scanning"])
app.include_router(report.router, prefix="/api/v1", tags=["Reports"])


@app.get("/", tags=["Health"])
async def root():
    return {"status": "ok", "service": "SecureDownload AI", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
