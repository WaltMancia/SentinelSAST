from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(BaseModel):
    rule_id: str
    title: str
    category: str
    owasp: str
    cwe: str
    severity: Severity
    cvss_score: float
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    remediation: str


class ScanSummary(BaseModel):
    total_files_scanned: int
    total_lines_scanned: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: int


class ScanReport(BaseModel):
    scan_id: str
    target_name: str
    scan_type: str
    timestamp: str
    summary: ScanSummary
    findings: List[Finding]


class SnippetScanRequest(BaseModel):
    filename: str = Field(default="snippet.py", description="Nombre virtual del archivo")
    code: str = Field(..., min_length=1, description="Código fuente a analizar")


class GitRepoScanRequest(BaseModel):
    repo_url: str = Field(..., description="URL pública de GitHub/GitLab (https://...)")
