from typing import List, Dict, Any, Optional
from .models import InputResource, SeverityLevel

class SecurityDetector:
    """Detects security misconfigurations in AWS resources."""
    
    @staticmethod
    def check_s3_public(resource: InputResource) -> Optional[Dict[str, Any]]:
        """Check if S3 bucket is publicly accessible without proper justification."""
        if resource.type != "s3":
            return None
            
        properties = resource.properties
        
        # Check if bucket is public
        is_public = properties.get("public", False)
        public_allowed = properties.get("tags", {}).get("PublicAllowed", "false").lower() == "true"
        
        if is_public and not public_allowed:
            return {
                "rule_id": "AWS-S3-PUBLIC",
                "severity": SeverityLevel.HIGH,
                "evidence": {
                    "field": "public",
                    "value": is_public,
                    "public_allowed_tag": public_allowed
                }
            }
        return None
    
    @staticmethod
    def check_iam_key_age(resource: InputResource) -> Optional[Dict[str, Any]]:
        """Check if IAM user access key is older than 90 days."""
        if resource.type != "iam_user":
            return None
            
        properties = resource.properties
        key_age_days = properties.get("access_key_age_days", 0)
        
        if key_age_days > 90:
            severity = SeverityLevel.CRITICAL if key_age_days > 180 else SeverityLevel.HIGH
            return {
                "rule_id": "AWS-IAM-OLD-KEY",
                "severity": severity,
                "evidence": {
                    "field": "access_key_age_days",
                    "value": key_age_days,
                    "threshold": 90
                }
            }
        return None
    
    @staticmethod
    def check_security_group_open_ports(resource: InputResource) -> Optional[Dict[str, Any]]:
        """Check for security groups with overly permissive rules."""
        if resource.type != "security_group":
            return None
            
        properties = resource.properties
        ingress_rules = properties.get("ingress_rules", [])
        
        dangerous_ports = []
        for rule in ingress_rules:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            cidr = rule.get("cidr_blocks", [])
            
            # Check for 0.0.0.0/0 access to dangerous ports
            if "0.0.0.0/0" in cidr:
                if from_port == 22 or to_port == 22:  # SSH
                    dangerous_ports.append({"port": 22, "protocol": "SSH"})
                elif from_port == 3389 or to_port == 3389:  # RDP
                    dangerous_ports.append({"port": 3389, "protocol": "RDP"})
                elif from_port == 0 and to_port == 65535:  # All ports
                    dangerous_ports.append({"port": "0-65535", "protocol": "ALL"})
        
        if dangerous_ports:
            return {
                "rule_id": "AWS-SG-OPEN-PORTS",
                "severity": SeverityLevel.HIGH,
                "evidence": {
                    "field": "ingress_rules",
                    "dangerous_ports": dangerous_ports,
                    "open_to_world": True
                }
            }
        return None
    
    @staticmethod
    def check_rds_public_access(resource: InputResource) -> Optional[Dict[str, Any]]:
        """Check if RDS instance is publicly accessible."""
        if resource.type != "rds":
            return None
            
        properties = resource.properties
        publicly_accessible = properties.get("publicly_accessible", False)
        
        if publicly_accessible:
            return {
                "rule_id": "AWS-RDS-PUBLIC",
                "severity": SeverityLevel.MEDIUM,
                "evidence": {
                    "field": "publicly_accessible",
                    "value": publicly_accessible
                }
            }
        return None
    
    @staticmethod
    def check_ec2_unencrypted_volumes(resource: InputResource) -> Optional[Dict[str, Any]]:
        """Check if EC2 instance has unencrypted EBS volumes."""
        if resource.type != "ec2":
            return None
            
        properties = resource.properties
        volumes = properties.get("volumes", [])
        
        unencrypted_volumes = []
        for volume in volumes:
            if not volume.get("encrypted", False):
                unencrypted_volumes.append({
                    "volume_id": volume.get("volume_id", "unknown"),
                    "size": volume.get("size", 0)
                })
        
        if unencrypted_volumes:
            return {
                "rule_id": "AWS-EC2-UNENCRYPTED",
                "severity": SeverityLevel.MEDIUM,
                "evidence": {
                    "field": "volumes",
                    "unencrypted_volumes": unencrypted_volumes
                }
            }
        return None
    
    @classmethod
    def scan_resource(cls, resource: InputResource) -> List[Dict[str, Any]]:
        """Run all security checks on a single resource."""
        findings = []
        
        # Run all detection methods
        checks = [
            cls.check_s3_public,
            cls.check_iam_key_age,
            cls.check_security_group_open_ports,
            cls.check_rds_public_access,
            cls.check_ec2_unencrypted_volumes
        ]
        
        for check in checks:
            result = check(resource)
            if result:
                findings.append(result)
        
        return findings
