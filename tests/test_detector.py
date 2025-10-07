import pytest
import sys
import os

# Add the api directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from app.detector import SecurityDetector
from app.models import InputResource

class TestSecurityDetector:
    """Test cases for the SecurityDetector class."""
    
    def test_check_s3_public_positive(self):
        """Test detection of public S3 bucket without PublicAllowed tag."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={
                "public": True,
                "tags": {"Environment": "prod"}
            }
        )
        
        result = SecurityDetector.check_s3_public(resource)
        
        assert result is not None
        assert result["rule_id"] == "AWS-S3-PUBLIC"
        assert result["severity"] == "HIGH"
        assert result["evidence"]["field"] == "public"
        assert result["evidence"]["value"] is True
    
    def test_check_s3_public_negative(self):
        """Test that S3 bucket with PublicAllowed tag is not flagged."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={
                "public": True,
                "tags": {"PublicAllowed": "true"}
            }
        )
        
        result = SecurityDetector.check_s3_public(resource)
        assert result is None
    
    def test_check_s3_public_wrong_type(self):
        """Test that non-S3 resources are not checked."""
        resource = InputResource(
            type="ec2",
            name="test-instance",
            account_id="123456789012",
            properties={"public": True}
        )
        
        result = SecurityDetector.check_s3_public(resource)
        assert result is None
    
    def test_check_iam_key_age_positive(self):
        """Test detection of old IAM access key."""
        resource = InputResource(
            type="iam_user",
            name="test-user",
            account_id="123456789012",
            properties={
                "access_key_age_days": 120
            }
        )
        
        result = SecurityDetector.check_iam_key_age(resource)
        
        assert result is not None
        assert result["rule_id"] == "AWS-IAM-OLD-KEY"
        assert result["severity"] == "HIGH"
        assert result["evidence"]["value"] == 120
    
    def test_check_iam_key_age_critical(self):
        """Test that very old keys are marked as critical."""
        resource = InputResource(
            type="iam_user",
            name="test-user",
            account_id="123456789012",
            properties={
                "access_key_age_days": 200
            }
        )
        
        result = SecurityDetector.check_iam_key_age(resource)
        
        assert result is not None
        assert result["severity"] == "CRITICAL"
    
    def test_check_iam_key_age_negative(self):
        """Test that new keys are not flagged."""
        resource = InputResource(
            type="iam_user",
            name="test-user",
            account_id="123456789012",
            properties={
                "access_key_age_days": 30
            }
        )
        
        result = SecurityDetector.check_iam_key_age(resource)
        assert result is None
    
    def test_check_security_group_open_ports_positive(self):
        """Test detection of security group with open SSH port."""
        resource = InputResource(
            type="security_group",
            name="test-sg",
            account_id="123456789012",
            properties={
                "ingress_rules": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                ]
            }
        )
        
        result = SecurityDetector.check_security_group_open_ports(resource)
        
        assert result is not None
        assert result["rule_id"] == "AWS-SG-OPEN-PORTS"
        assert result["severity"] == "HIGH"
        assert len(result["evidence"]["dangerous_ports"]) > 0
    
    def test_check_security_group_open_ports_negative(self):
        """Test that restricted security groups are not flagged."""
        resource = InputResource(
            type="security_group",
            name="test-sg",
            account_id="123456789012",
            properties={
                "ingress_rules": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/8"]
                    }
                ]
            }
        )
        
        result = SecurityDetector.check_security_group_open_ports(resource)
        assert result is None
    
    def test_check_rds_public_access_positive(self):
        """Test detection of publicly accessible RDS instance."""
        resource = InputResource(
            type="rds",
            name="test-db",
            account_id="123456789012",
            properties={
                "publicly_accessible": True
            }
        )
        
        result = SecurityDetector.check_rds_public_access(resource)
        
        assert result is not None
        assert result["rule_id"] == "AWS-RDS-PUBLIC"
        assert result["severity"] == "MEDIUM"
        assert result["evidence"]["value"] is True
    
    def test_check_rds_public_access_negative(self):
        """Test that private RDS instances are not flagged."""
        resource = InputResource(
            type="rds",
            name="test-db",
            account_id="123456789012",
            properties={
                "publicly_accessible": False
            }
        )
        
        result = SecurityDetector.check_rds_public_access(resource)
        assert result is None
    
    def test_check_ec2_unencrypted_volumes_positive(self):
        """Test detection of EC2 instance with unencrypted volumes."""
        resource = InputResource(
            type="ec2",
            name="test-instance",
            account_id="123456789012",
            properties={
                "volumes": [
                    {
                        "volume_id": "vol-123",
                        "size": 20,
                        "encrypted": False
                    }
                ]
            }
        )
        
        result = SecurityDetector.check_ec2_unencrypted_volumes(resource)
        
        assert result is not None
        assert result["rule_id"] == "AWS-EC2-UNENCRYPTED"
        assert result["severity"] == "MEDIUM"
        assert len(result["evidence"]["unencrypted_volumes"]) > 0
    
    def test_check_ec2_unencrypted_volumes_negative(self):
        """Test that encrypted volumes are not flagged."""
        resource = InputResource(
            type="ec2",
            name="test-instance",
            account_id="123456789012",
            properties={
                "volumes": [
                    {
                        "volume_id": "vol-123",
                        "size": 20,
                        "encrypted": True
                    }
                ]
            }
        )
        
        result = SecurityDetector.check_ec2_unencrypted_volumes(resource)
        assert result is None
    
    def test_scan_resource_multiple_findings(self):
        """Test that scan_resource returns multiple findings when applicable."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={
                "public": True,
                "tags": {"Environment": "prod"}
            }
        )
        
        findings = SecurityDetector.scan_resource(resource)
        
        # Should find the S3 public issue
        assert len(findings) >= 1
        assert any(f["rule_id"] == "AWS-S3-PUBLIC" for f in findings)
    
    def test_scan_resource_no_findings(self):
        """Test that scan_resource returns empty list for clean resources."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={
                "public": False
            }
        )
        
        findings = SecurityDetector.scan_resource(resource)
        assert len(findings) == 0
