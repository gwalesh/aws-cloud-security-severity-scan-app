from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ResourceType(str, Enum):
    S3 = "s3"
    IAM_USER = "iam_user"
    SECURITY_GROUP = "security_group"
    RDS = "rds"
    EC2 = "ec2"

# Model for an incoming AWS resource from the JSON file
class InputResource(BaseModel):
    type: str
    name: str
    account_id: str
    properties: Dict[str, Any]

# Model for a security finding to be stored and returned by the API
class Finding(BaseModel):
    id: str
    rule_id: str
    severity: SeverityLevel
    resource: Dict[str, str]
    evidence: Dict[str, Any]
    ai_explanation: str
    ai_remediation: List[str]
    timestamp: str

# Model for scan request
class ScanRequest(BaseModel):
    resources: List[InputResource]

# Model for scan response
class ScanResponse(BaseModel):
    count: int
    message: str

# Model for findings list response with pagination
class FindingsListResponse(BaseModel):
    findings: List[Finding]
    total: int
    page: int
    page_size: int
