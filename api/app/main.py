from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import datetime
import json

from .models import InputResource, Finding, ScanRequest, ScanResponse, FindingsListResponse
from .detector import SecurityDetector
from .generator import AIGenerator
from .database import get_db, save_finding, get_findings, get_finding_by_id, clear_findings

app = FastAPI(
    title="AWS Cloud Security/Severity/Finding Monitoring APP",
    description="API for detecting and analyzing AWS security misconfigurations",
    version="1.0.0"
)

# Add CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan", response_model=ScanResponse)
def scan_resources(request: ScanRequest, db: Session = Depends(get_db)):
    """Ingest JSON resources, analyze for security issues, and persist findings."""
    # Clear previous scan results
    clear_findings(db)
    
    findings_count = 0
    
    for resource_data in request.resources:
        # Convert dict to InputResource model
        resource = InputResource(
            type=resource_data.type,
            name=resource_data.name,
            account_id=resource_data.account_id,
            properties=resource_data.properties
        )
        
        # Run security detection
        detection_results = SecurityDetector.scan_resource(resource)
        
        # Process each finding
        for detection in detection_results:
            # Get AI-generated explanation and remediation
            ai_content = AIGenerator.get_ai_assistance(detection["rule_id"], resource)
            
            # Create finding object
            finding_data = {
                "id": str(uuid.uuid4()),
                "rule_id": detection["rule_id"],
                "severity": detection["severity"],
                "resource": {
                    "type": resource.type,
                    "name": resource.name,
                    "account_id": resource.account_id
                },
                "evidence": detection["evidence"],
                "ai_explanation": ai_content["explanation"],
                "ai_remediation": ai_content["remediation"],
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            }
            
            # Save to database
            save_finding(db, finding_data)
            findings_count += 1
    
    return ScanResponse(
        count=findings_count,
        message=f"Scan completed. Found {findings_count} security issues."
    )

@app.get("/findings", response_model=FindingsListResponse)
def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List findings with optional filters and pagination."""
    skip = (page - 1) * page_size
    
    findings_db, total = get_findings(
        db, 
        skip=skip, 
        limit=page_size, 
        severity=severity, 
        resource_type=resource_type, 
        account_id=account_id
    )
    
    # Convert database objects to Pydantic models
    findings = []
    for finding_db in findings_db:
        finding = Finding(
            id=finding_db.id,
            rule_id=finding_db.rule_id,
            severity=finding_db.severity,
            resource={
                "type": finding_db.resource_type,
                "name": finding_db.resource_name,
                "account_id": finding_db.resource_account_id
            },
            evidence=json.loads(finding_db.evidence),
            ai_explanation=finding_db.ai_explanation,
            ai_remediation=json.loads(finding_db.ai_remediation),
            timestamp=finding_db.timestamp.isoformat() + "Z"
        )
        findings.append(finding)
    
    return FindingsListResponse(
        findings=findings,
        total=total,
        page=page,
        page_size=page_size
    )

@app.get("/findings/{finding_id}", response_model=Finding)
def get_finding_details(finding_id: str, db: Session = Depends(get_db)):
    """Get a single finding by its ID."""
    finding_db = get_finding_by_id(db, finding_id)
    
    if not finding_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding = Finding(
        id=finding_db.id,
        rule_id=finding_db.rule_id,
        severity=finding_db.severity,
        resource={
            "type": finding_db.resource_type,
            "name": finding_db.resource_name,
            "account_id": finding_db.resource_account_id
        },
        evidence=json.loads(finding_db.evidence),
        ai_explanation=finding_db.ai_explanation,
        ai_remediation=json.loads(finding_db.ai_remediation),
        timestamp=finding_db.timestamp.isoformat() + "Z"
    )
    
    return finding

@app.get("/findings/summary/stats")
def get_findings_summary(db: Session = Depends(get_db)):
    """Get summary statistics of findings."""
    all_findings, total = get_findings(db, skip=0, limit=1000)
    
    # Count by severity
    severity_counts = {}
    resource_type_counts = {}
    
    for finding in all_findings:
        # Count by severity
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by resource type
        resource_type = finding.resource_type
        resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1
    
    return {
        "total_findings": total,
        "severity_breakdown": severity_counts,
        "resource_type_breakdown": resource_type_counts
    }

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat() + "Z"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
