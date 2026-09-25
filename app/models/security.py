from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low"]
HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
FindingStatus = Literal["Open", "In Review", "Remediated", "False Positive"]
ConfidenceLevel = Literal["High", "Medium", "Low"]

class ReproductionRequest(BaseModel):
    rawHttp: str
    curl: str
    notes: Optional[str] = None

class CodeExample(BaseModel):
    language: str
    title: str
    code: str

class ReferenceItem(BaseModel):
    title: str
    url: str

class RemediationInfo(BaseModel):
    summary: str
    steps: List[str]
    codeExample: Optional[CodeExample] = None
    references: Optional[List[ReferenceItem]] = None

class FindingEvidence(BaseModel):
    requestPayload: Optional[str] = None
    responseStatus: int
    responseBody: str
    headers: Optional[Dict[str, str]] = None
    highlightSnippet: Optional[str] = None

class Finding(BaseModel):
    id: str
    title: str
    cwe: str
    cve: Optional[str] = None
    owaspCategory: str
    severity: Severity
    endpoint: str
    method: HttpMethod
    vulnerabilityType: str
    confidence: ConfidenceLevel
    status: FindingStatus = "Open"
    timestamp: str
    description: str
    explanation: str
    evidence: FindingEvidence
    reproduction: ReproductionRequest
    remediation: RemediationInfo

class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

class ScanSummary(BaseModel):
    id: str
    targetName: str
    targetUrl: str
    specType: str = "OpenAPI 3.0"
    status: Literal["Completed", "In Progress", "Failed", "Queued"] = "Completed"
    startTime: str
    duration: str
    totalEndpoints: int
    testedEndpoints: int
    securityScore: float
    severityCounts: SeverityCounts

class DiscoveredEndpoint(BaseModel):
    path: str
    method: HttpMethod
    summary: Optional[str] = None
    operationId: Optional[str] = None
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    authRequired: bool = False
    securitySchemes: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

class SpecParseResponse(BaseModel):
    title: str
    version: str
    description: Optional[str] = None
    servers: List[str] = Field(default_factory=list)
    totalEndpoints: int
    endpoints: List[DiscoveredEndpoint]
    rawSpecSample: Optional[str] = None

class SpecParseRequest(BaseModel):
    specContent: str = Field(..., description="OpenAPI / Swagger spec in JSON or YAML string format")

class ScanRequest(BaseModel):
    targetUrl: str = Field(..., description="Target URL of the authorized local sandbox API under test")
    specContent: Optional[str] = Field(None, description="OpenAPI specification content (JSON/YAML)")
    checkAuth: bool = Field(True, description="Enable Authentication Misconfiguration checks")
    checkDataExposure: bool = Field(True, description="Enable Excessive Data Exposure checks")
    checkRateLimit: bool = Field(True, description="Enable Rate Limit / Burst testing")
    checkBola: bool = Field(True, description="Enable BOLA / IDOR cross-object boundary testing")
    isSandboxConfirmed: bool = Field(True, description="User confirmation that target is an authorized sandbox")

class ScanResponse(BaseModel):
    summary: ScanSummary
    findings: List[Finding]
    logs: List[str] = Field(default_factory=list)
