import pytest
import sys
import os
from fastapi.testclient import TestClient

# Add the api directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from app.main import app

client = TestClient(app)

class TestAPI:
    """Test cases for the FastAPI endpoints."""
    
    def test_health_check(self):
        """Test the health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
    
    def test_scan_empty_resources(self):
        """Test scanning with empty resource list."""
        response = client.post("/scan", json={"resources": []})
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 0
        assert "Scan completed" in data["message"]
    
    def test_scan_s3_public_resource(self):
        """Test scanning with a public S3 bucket."""
        resources = [
            {
                "type": "s3",
                "name": "test-bucket",
                "account_id": "123456789012",
                "properties": {
                    "public": True,
                    "tags": {"Environment": "prod"}
                }
            }
        ]
        
        response = client.post("/scan", json={"resources": resources})
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 1
        assert "Found 1 security issues" in data["message"]
    
    def test_scan_multiple_issues(self):
        """Test scanning with multiple security issues."""
        resources = [
            {
                "type": "s3",
                "name": "public-bucket",
                "account_id": "123456789012",
                "properties": {"public": True}
            },
            {
                "type": "iam_user",
                "name": "old-user",
                "account_id": "123456789012",
                "properties": {"access_key_age_days": 120}
            },
            {
                "type": "rds",
                "name": "public-db",
                "account_id": "123456789012",
                "properties": {"publicly_accessible": True}
            }
        ]
        
        response = client.post("/scan", json={"resources": resources})
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
    
    def test_list_findings_empty(self):
        """Test listing findings when none exist."""
        response = client.get("/findings")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert len(data["findings"]) == 0
        assert data["page"] == 1
        assert data["page_size"] == 10
    
    def test_list_findings_with_data(self):
        """Test listing findings after scanning."""
        # First, create some findings
        resources = [
            {
                "type": "s3",
                "name": "test-bucket",
                "account_id": "123456789012",
                "properties": {"public": True}
            }
        ]
        
        client.post("/scan", json={"resources": resources})
        
        # Then list findings
        response = client.get("/findings")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert len(data["findings"]) >= 1
        
        finding = data["findings"][0]
        assert "id" in finding
        assert "rule_id" in finding
        assert "severity" in finding
        assert "resource" in finding
        assert "evidence" in finding
        assert "ai_explanation" in finding
        assert "ai_remediation" in finding
        assert "timestamp" in finding
    
    def test_list_findings_with_filters(self):
        """Test listing findings with severity filter."""
        # Create findings first
        resources = [
            {
                "type": "s3",
                "name": "test-bucket",
                "account_id": "123456789012",
                "properties": {"public": True}
            }
        ]
        
        client.post("/scan", json={"resources": resources})
        
        # Filter by severity
        response = client.get("/findings?severity=HIGH")
        assert response.status_code == 200
        data = response.json()
        
        # All returned findings should be HIGH severity
        for finding in data["findings"]:
            assert finding["severity"] == "HIGH"
    
    def test_list_findings_pagination(self):
        """Test findings pagination."""
        response = client.get("/findings?page=1&page_size=5")
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 5
        assert len(data["findings"]) <= 5
    
    def test_get_finding_details_not_found(self):
        """Test getting details for non-existent finding."""
        response = client.get("/findings/non-existent-id")
        assert response.status_code == 404
        data = response.json()
        assert "Finding not found" in data["detail"]
    
    def test_get_finding_details_success(self):
        """Test getting details for existing finding."""
        # Create a finding first
        resources = [
            {
                "type": "s3",
                "name": "test-bucket",
                "account_id": "123456789012",
                "properties": {"public": True}
            }
        ]
        
        client.post("/scan", json={"resources": resources})
        
        # Get the finding ID
        response = client.get("/findings")
        finding_id = response.json()["findings"][0]["id"]
        
        # Get details
        response = client.get(f"/findings/{finding_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == finding_id
        assert "ai_explanation" in data
        assert "ai_remediation" in data
    
    def test_get_findings_summary_stats(self):
        """Test getting findings summary statistics."""
        response = client.get("/findings/summary/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_findings" in data
        assert "severity_breakdown" in data
        assert "resource_type_breakdown" in data
        assert isinstance(data["severity_breakdown"], dict)
        assert isinstance(data["resource_type_breakdown"], dict)
    
    def test_scan_invalid_json(self):
        """Test scanning with invalid JSON structure."""
        response = client.post("/scan", json={"invalid": "data"})
        assert response.status_code == 422  # Validation error
    
    def test_scan_malformed_resource(self):
        """Test scanning with malformed resource data."""
        resources = [
            {
                "type": "s3",
                # Missing required fields
            }
        ]
        
        response = client.post("/scan", json={"resources": resources})
        assert response.status_code == 422  # Validation error
