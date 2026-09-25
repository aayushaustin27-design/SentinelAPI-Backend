from fastapi import FastAPI, UploadFile, File, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from .models.security import (
    SpecParseRequest,
    SpecParseResponse,
    ScanRequest,
    ScanResponse
)
from .parser.openapi_parser import parse_spec_string, extract_endpoints_from_spec
from .scanner.engine import ScannerEngine
from .sandbox.target_api import sandbox_app

app = FastAPI(
    title="SentinelAPI - Zero-Trust API Vulnerability Scanner",
    description="Backend service for automated OpenAPI parsing, dynamic security fuzzing, and vulnerability remediation.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# -----------------------------------------------------------------------------
# CORS Configuration for React Frontend
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner_engine = ScannerEngine()

# Mount the vulnerable sandbox API as a sub-application for unified execution
app.mount("/sandbox", sandbox_app)

# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------
@app.get("/", tags=["System"])
def root():
    return {
        "service": "SentinelAPI Backend",
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs",
        "sandbox_docs": "/sandbox/docs"
    }

@app.get("/api/v1/health", tags=["System"])
def health():
    return {
        "status": "healthy",
        "engine": "active",
        "security_checks": [
            "authentication_configuration",
            "excessive_data_exposure",
            "rate_limit_burst",
            "bola_idor_testing"
        ]
    }

@app.post("/api/v1/spec/parse", response_model=SpecParseResponse, tags=["Specification"])
def parse_spec_endpoint(request: SpecParseRequest):
    """
    Parse an OpenAPI 3.0 / Swagger 2.0 specification provided as JSON or YAML raw string.
    Returns discovered endpoints, parameters, and authentication requirements.
    """
    try:
        spec_dict = parse_spec_string(request.specContent)
        response, _ = extract_endpoints_from_spec(spec_dict)
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse OpenAPI specification: {str(e)}"
        )

@app.post("/api/v1/spec/upload", response_model=SpecParseResponse, tags=["Specification"])
async def upload_spec_file(file: UploadFile = File(...)):
    """
    Upload an OpenAPI/Swagger JSON or YAML file from disk.
    Parses and returns discovered endpoints and metadata.
    """
    try:
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8", errors="replace")
        spec_dict = parse_spec_string(content_str)
        response, _ = extract_endpoints_from_spec(spec_dict)
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error reading uploaded file '{file.filename}': {str(e)}"
        )

@app.post("/api/v1/scan/execute", response_model=ScanResponse, tags=["Scanner"])
async def execute_scan_endpoint(request: ScanRequest):
    """
    Execute automated security checks against an authorized local sandbox API.
    Performs authentication audits, excessive data exposure checks, rate-limit testing,
    and BOLA/IDOR verification.
    """
    try:
        result = await scanner_engine.execute_scan(request)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution encountered an unexpected error: {str(e)}"
        )

@app.get("/api/v1/sandbox/sample-spec", tags=["Specification"])
def get_sample_sandbox_spec():
    """
    Returns the ready-to-use OpenAPI 3.0 specification for the local sandbox API.
    """
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SentinelAPI Vulnerable Sandbox Test Target",
            "version": "1.0.0",
            "description": "Local testbed for auditing BOLA, Data Exposure, and Rate Limiting."
        },
        "servers": [
            {"url": "http://127.0.0.1:8000/sandbox"}
        ],
        "paths": {
            "/api/v1/health": {
                "get": {
                    "summary": "Health check probe",
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/api/v1/public/debug": {
                "get": {
                    "summary": "Public debug configuration",
                    "responses": {"200": {"description": "Diagnostic data"}}
                }
            },
            "/auth/login": {
                "post": {
                    "summary": "User authentication",
                    "responses": {"200": {"description": "Bearer token"}}
                }
            },
            "/api/v1/users/{user_id}/profile": {
                "get": {
                    "summary": "Fetch user profile (BOLA Vulnerable)",
                    "parameters": [
                        {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "Profile data"}}
                }
            },
            "/api/v1/orders/{order_id}": {
                "get": {
                    "summary": "Fetch order details (Excessive Data Exposure)",
                    "parameters": [
                        {"name": "order_id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "Order records"}}
                }
            },
            "/api/v1/transfers/quick": {
                "post": {
                    "summary": "Quick credit transfer (Missing Rate Limit)",
                    "responses": {"200": {"description": "Transfer receipt"}}
                }
            }
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
