from typing import Dict, List
from .models import InputResource

class AIGenerator:
    """Mock AI generator for security explanations and remediation steps."""
    
    @staticmethod
    def generate_s3_public_explanation(resource: InputResource) -> Dict[str, str]:
        """Generate explanation and remediation for public S3 bucket."""
        explanation = (
            f"This S3 bucket '{resource.name}' in account '{resource.account_id}' is publicly accessible. "
            "This means anyone on the internet can potentially read, write, or delete objects, leading to "
            "data breaches, unauthorized access, or service disruption. Public access should be restricted "
            "unless absolutely necessary for a specific purpose like website hosting."
        )
        
        remediation = [
            f"1. Navigate to the S3 console and select the bucket '{resource.name}'",
            "2. Go to the 'Permissions' tab and edit the 'Block public access (bucket settings)'",
            "3. Enable all four 'Block all public access' settings and save the changes"
        ]
        
        return {"explanation": explanation, "remediation": remediation}
    
    @staticmethod
    def generate_iam_old_key_explanation(resource: InputResource) -> Dict[str, str]:
        """Generate explanation and remediation for old IAM access keys."""
        key_age = resource.properties.get("access_key_age_days", 0)
        explanation = (
            f"IAM user '{resource.name}' has an access key that is {key_age} days old. "
            "Old access keys pose a significant security risk as they may have been compromised "
            "over time or shared with unauthorized parties. AWS recommends rotating access keys "
            "every 90 days to maintain security."
        )
        
        remediation = [
            f"1. Create a new access key for user '{resource.name}' in the IAM console",
            "2. Update all applications and services to use the new access key",
            "3. Delete the old access key after confirming the new key works properly"
        ]
        
        return {"explanation": explanation, "remediation": remediation}
    
    @staticmethod
    def generate_sg_open_ports_explanation(resource: InputResource) -> Dict[str, str]:
        """Generate explanation and remediation for open security group ports."""
        dangerous_ports = resource.properties.get("ingress_rules", [])
        port_list = []
        for rule in dangerous_ports:
            if "0.0.0.0/0" in rule.get("cidr_blocks", []):
                port_list.append(f"{rule.get('from_port', 0)}-{rule.get('to_port', 0)}")
        
        explanation = (
            f"Security group '{resource.name}' allows unrestricted access (0.0.0.0/0) to ports {', '.join(port_list)}. "
            "This creates a significant security risk as it allows anyone on the internet to attempt "
            "connections to these ports, potentially leading to brute force attacks or unauthorized access."
        )
        
        remediation = [
            f"1. Review the security group '{resource.name}' rules in the EC2 console",
            "2. Restrict CIDR blocks to specific IP ranges or security groups instead of 0.0.0.0/0",
            "3. Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP access"
        ]
        
        return {"explanation": explanation, "remediation": remediation}
    
    @staticmethod
    def generate_rds_public_explanation(resource: InputResource) -> Dict[str, str]:
        """Generate explanation and remediation for publicly accessible RDS."""
        explanation = (
            f"RDS instance '{resource.name}' is configured for public access. This means the database "
            "is accessible from the internet, which significantly increases the attack surface. "
            "Database instances should typically be placed in private subnets and accessed through "
            "secure methods like VPN or bastion hosts."
        )
        
        remediation = [
            f"1. Navigate to the RDS console and select instance '{resource.name}'",
            "2. Click 'Modify' and change 'Publicly accessible' to 'No'",
            "3. Ensure the instance is in a private subnet and configure proper security groups"
        ]
        
        return {"explanation": explanation, "remediation": remediation}
    
    @staticmethod
    def generate_ec2_unencrypted_explanation(resource: InputResource) -> Dict[str, str]:
        """Generate explanation and remediation for unencrypted EC2 volumes."""
        volumes = resource.properties.get("volumes", [])
        unencrypted_count = sum(1 for v in volumes if not v.get("encrypted", False))
        
        explanation = (
            f"EC2 instance '{resource.name}' has {unencrypted_count} unencrypted EBS volume(s). "
            "Unencrypted volumes pose a data security risk as data at rest is not protected. "
            "If the instance is compromised or the volume is detached, sensitive data could be "
            "accessed by unauthorized parties."
        )
        
        remediation = [
            f"1. Create snapshots of the unencrypted volumes for instance '{resource.name}'",
            "2. Create new encrypted volumes from the snapshots",
            "3. Attach the new encrypted volumes and detach the old unencrypted ones"
        ]
        
        return {"explanation": explanation, "remediation": remediation}
    
    # Dictionary mapping rule IDs to their generator functions
    GENERATORS = {
        "AWS-S3-PUBLIC": generate_s3_public_explanation,
        "AWS-IAM-OLD-KEY": generate_iam_old_key_explanation,
        "AWS-SG-OPEN-PORTS": generate_sg_open_ports_explanation,
        "AWS-RDS-PUBLIC": generate_rds_public_explanation,
        "AWS-EC2-UNENCRYPTED": generate_ec2_unencrypted_explanation
    }
    
    @classmethod
    def get_ai_assistance(cls, rule_id: str, resource: InputResource) -> Dict[str, str]:
        """Get AI-generated explanation and remediation for a given rule."""
        generator_func = cls.GENERATORS.get(rule_id)
        if generator_func:
            return generator_func(resource)
        return {
            "explanation": "No explanation available for this security issue.",
            "remediation": ["Contact your security team for assistance with this issue."]
        }
