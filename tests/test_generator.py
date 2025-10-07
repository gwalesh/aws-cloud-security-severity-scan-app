import pytest
import sys
import os

# Add the api directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from app.generator import AIGenerator
from app.models import InputResource

class TestAIGenerator:
    """Test cases for the AIGenerator class."""
    
    def test_generate_s3_public_explanation(self):
        """Test S3 public bucket explanation generation."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={"public": True}
        )
        
        result = AIGenerator.generate_s3_public_explanation(resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) == 3
        assert "test-bucket" in result["explanation"]
        assert "123456789012" in result["explanation"]
        assert "publicly accessible" in result["explanation"].lower()
    
    def test_generate_iam_old_key_explanation(self):
        """Test IAM old key explanation generation."""
        resource = InputResource(
            type="iam_user",
            name="test-user",
            account_id="123456789012",
            properties={"access_key_age_days": 120}
        )
        
        result = AIGenerator.generate_iam_old_key_explanation(resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) == 3
        assert "test-user" in result["explanation"]
        assert "120 days old" in result["explanation"]
        assert "90 days" in result["explanation"]
    
    def test_generate_sg_open_ports_explanation(self):
        """Test security group open ports explanation generation."""
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
        
        result = AIGenerator.generate_sg_open_ports_explanation(resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) == 3
        assert "test-sg" in result["explanation"]
        assert "0.0.0.0/0" in result["explanation"]
        assert "unrestricted access" in result["explanation"].lower()
    
    def test_generate_rds_public_explanation(self):
        """Test RDS public access explanation generation."""
        resource = InputResource(
            type="rds",
            name="test-db",
            account_id="123456789012",
            properties={"publicly_accessible": True}
        )
        
        result = AIGenerator.generate_rds_public_explanation(resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) == 3
        assert "test-db" in result["explanation"]
        assert "public access" in result["explanation"].lower()
        assert "internet" in result["explanation"].lower()
    
    def test_generate_ec2_unencrypted_explanation(self):
        """Test EC2 unencrypted volumes explanation generation."""
        resource = InputResource(
            type="ec2",
            name="test-instance",
            account_id="123456789012",
            properties={
                "volumes": [
                    {"volume_id": "vol-123", "size": 20, "encrypted": False},
                    {"volume_id": "vol-456", "size": 50, "encrypted": False}
                ]
            }
        )
        
        result = AIGenerator.generate_ec2_unencrypted_explanation(resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) == 3
        assert "test-instance" in result["explanation"]
        assert "2 unencrypted" in result["explanation"]
        assert "data at rest" in result["explanation"].lower()
    
    def test_get_ai_assistance_valid_rule(self):
        """Test getting AI assistance for a valid rule ID."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={"public": True}
        )
        
        result = AIGenerator.get_ai_assistance("AWS-S3-PUBLIC", resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert len(result["remediation"]) > 0
    
    def test_get_ai_assistance_invalid_rule(self):
        """Test getting AI assistance for an invalid rule ID."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={"public": True}
        )
        
        result = AIGenerator.get_ai_assistance("INVALID-RULE", resource)
        
        assert "explanation" in result
        assert "remediation" in result
        assert isinstance(result["remediation"], list)
        assert "No explanation available" in result["explanation"]
        assert "Contact your security team" in result["remediation"][0]
    
    def test_all_generators_available(self):
        """Test that all expected generators are available."""
        expected_rules = [
            "AWS-S3-PUBLIC",
            "AWS-IAM-OLD-KEY", 
            "AWS-SG-OPEN-PORTS",
            "AWS-RDS-PUBLIC",
            "AWS-EC2-UNENCRYPTED"
        ]
        
        for rule_id in expected_rules:
            assert rule_id in AIGenerator.GENERATORS
            assert callable(AIGenerator.GENERATORS[rule_id])
    
    def test_remediation_steps_format(self):
        """Test that remediation steps follow the expected format."""
        resource = InputResource(
            type="s3",
            name="test-bucket",
            account_id="123456789012",
            properties={"public": True}
        )
        
        result = AIGenerator.get_ai_assistance("AWS-S3-PUBLIC", resource)
        
        # Check that remediation steps are numbered
        for i, step in enumerate(result["remediation"], 1):
            assert step.startswith(f"{i}.")
            assert len(step) > 10  # Should be substantial content
    
    def test_explanation_contains_resource_info(self):
        """Test that explanations contain relevant resource information."""
        resource = InputResource(
            type="iam_user",
            name="john-doe",
            account_id="987654321098",
            properties={"access_key_age_days": 150}
        )
        
        result = AIGenerator.get_ai_assistance("AWS-IAM-OLD-KEY", resource)
        
        assert "john-doe" in result["explanation"]
        assert "987654321098" in result["explanation"]
        assert "150 days" in result["explanation"]
