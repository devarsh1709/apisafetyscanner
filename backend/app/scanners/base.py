from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_SCORES = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


@dataclass
class Vulnerability:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss_score: float = 0.0
    endpoint: str = ""
    method: str = ""
    request_details: dict = field(default_factory=dict)
    response_details: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    false_positive_likelihood: str = "low"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "endpoint": self.endpoint,
            "method": self.method,
            "request_details": self.request_details,
            "response_details": self.response_details,
            "references": self.references,
            "false_positive_likelihood": self.false_positive_likelihood,
        }


@dataclass
class ScanContext:
    target_url: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    auth_token: str = ""
    timeout: int = 10
    scan_id: str = ""
