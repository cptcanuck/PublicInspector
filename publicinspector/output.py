"""Output formatting utilities."""

import json
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class OutputFormatter:
    """
    Formats and displays scan results.
    
    Supports multiple output formats: table, json, csv, audit
    """
    
    def __init__(self, format_type='table'):
        """
        Initialize the formatter.
        
        Args:
            format_type: Output format ('table', 'json', 'csv', 'audit')
        """
        self.format_type = format_type
    
    def format_findings(self, findings):
        """
        Format findings according to the specified format.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Formatted string
        """
        if self.format_type == 'json':
            return self._format_json(findings)
        elif self.format_type == 'csv':
            return self._format_csv(findings)
        elif self.format_type == 'audit':
            return self._format_audit(findings)
        else:
            return self._format_table(findings)
    
    def _format_table(self, findings):
        """Format findings as a colored table."""
        if not findings:
            return "No public resources found!"
        
        # Prepare table data
        table_data = []
        for finding in findings:
            # Color code based on severity
            severity = finding.get('severity', 'info')
            severity_colored = self._color_severity(severity)
            
            # Get resource details
            details = finding.get('details', {})
            tags = details.get('tags', {})
            
            # Format tags for display
            tag_str = ''
            if tags:
                tag_items = [f"{k}={v}" for k, v in list(tags.items())[:2]]  # Show first 2 tags
                tag_str = ', '.join(tag_items)
                if len(tags) > 2:
                    tag_str += '...'
            
            # Check if this is an exception
            public_access = finding.get('public_access', 'unknown')
            if finding.get('exception_expired'):
                public_access = f"{public_access} [EXCEPTION EXPIRED]"
            elif finding.get('is_exception'):
                public_access = f"{public_access} [APPROVED EXCEPTION]"
            
            row = [
                finding.get('account_id', 'unknown'),
                finding.get('region', 'unknown'),
                finding.get('resource_type', 'unknown'),
                finding.get('resource_name', 'unknown'),
                severity_colored,
                public_access,
                tag_str
            ]
            table_data.append(row)
        
        headers = ['Account', 'Region', 'Type', 'Resource', 'Severity', 'Public Access', 'Tags']
        
        return tabulate(table_data, headers=headers, tablefmt='grid')
    
    def _format_json(self, findings):
        """Format findings as JSON."""
        return json.dumps(findings, indent=2, default=str)
    
    def _format_csv(self, findings):
        """Format findings as CSV."""
        if not findings:
            return ""
        
        # CSV header
        headers = ['Account ID', 'Region', 'Resource Type', 'Resource Name', 'Resource ID', 
                   'Severity', 'Public Access', 'Tags', 'Details']
        lines = [','.join(headers)]
        
        # CSV rows
        for finding in findings:
            details = finding.get('details', {})
            tags = details.get('tags', {})
            
            # Format tags
            tag_str = '; '.join([f"{k}={v}" for k, v in tags.items()]) if tags else ''
            
            # Format additional details (exclude tags)
            detail_items = []
            for key, value in details.items():
                if key != 'tags' and value:
                    detail_items.append(f"{key}={value}")
            detail_str = '; '.join(detail_items)
            
            row = [
                finding.get('account_id', 'unknown'),
                finding.get('region', 'unknown'),
                finding.get('resource_type', 'unknown'),
                finding.get('resource_name', 'unknown'),
                finding.get('resource_id', 'unknown'),
                finding.get('severity', 'unknown'),
                finding.get('public_access', 'unknown'),
                tag_str,
                detail_str
            ]
            # Escape commas and quotes in fields
            row = [f'"{str(field).replace('"', '""')}"' for field in row]
            lines.append(','.join(row))
        
        return '\n'.join(lines)
    
    def _format_audit(self, findings):
        """
        Format findings as standardized audit JSON.
        
        Converts findings to a standardized audit format with fields:
        - resource_arn
        - account_id
        - region
        - edge_type (network | identity | service | composite)
        - exposure_vector
        - public_endpoint
        - auth_required (none | aws_iam | custom)
        - evidence_source
        - last_verified
        """
        audit_findings = []
        current_time = datetime.utcnow().isoformat() + 'Z'
        
        for finding in findings:
            audit_finding = self._convert_to_audit_format(finding, current_time)
            audit_findings.append(audit_finding)
        
        audit_report = {
            "version": "1.0",
            "scan_timestamp": current_time,
            "finding_count": len(audit_findings),
            "findings": audit_findings
        }
        
        return json.dumps(audit_report, indent=2, default=str)
    
    def _convert_to_audit_format(self, finding, scan_time):
        """
        Convert a finding to standardized audit format.
        
        Args:
            finding: Original finding dictionary
            scan_time: ISO timestamp of scan
            
        Returns:
            Audit-formatted finding dictionary
        """
        resource_type = finding.get('resource_type', 'unknown')
        resource_id = finding.get('resource_id', 'unknown')
        resource_name = finding.get('resource_name', resource_id)
        account_id = finding.get('account_id', 'unknown')
        region = finding.get('region', 'unknown')
        
        # Build resource ARN if not provided
        resource_arn = finding.get('resource_arn')
        if not resource_arn:
            resource_arn = self._build_resource_arn(
                account_id, region, resource_type, resource_id
            )
        
        # Determine edge type based on resource type
        edge_type = self._determine_edge_type(resource_type, finding)
        
        # Determine exposure vector - return None if can't determine
        exposure_vector = self._determine_exposure_vector(resource_type, finding)
        
        # Determine public endpoint - return None if not available
        public_endpoint = self._determine_public_endpoint(resource_type, finding)
        
        # Determine authentication requirements - return None if uncertain
        auth_required = self._determine_auth_required(resource_type, finding)
        
        # Determine evidence source
        evidence_source = self._determine_evidence_source(resource_type, finding)
        
        audit_finding = {
            "resource_arn": resource_arn,
            "account_id": account_id,
            "region": region,
            "edge_type": edge_type,
            "exposure_vector": exposure_vector,
            "public_endpoint": public_endpoint,
            "auth_required": auth_required,
            "evidence_source": evidence_source,
            "last_verified": scan_time,
            # Additional context
            "resource_type": resource_type,
            "resource_name": resource_name,
            "resource_id": resource_id,
            "severity": finding.get('severity', 'info'),
            "is_exception": finding.get('is_exception', False),
            "exception_expired": finding.get('exception_expired', False),
            "tags": finding.get('tags', {}),
            "details": finding.get('details', '')
        }
        
        return audit_finding
    
    def _build_resource_arn(self, account_id, region, resource_type, resource_id):
        """Build an ARN for a resource."""
        # Map resource types to ARN formats
        if resource_type == 's3_bucket':
            return f"arn:aws:s3:::{resource_id}"
        elif resource_type == 'cloudfront':
            return f"arn:aws:cloudfront::{account_id}:distribution/{resource_id}"
        elif resource_type == 'security_group':
            return f"arn:aws:ec2:{region}:{account_id}:security-group/{resource_id}"
        elif 'load_balancer' in resource_type or 'elb' in resource_type:
            return f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{resource_id}"
        elif resource_type == 'api_gateway':
            return f"arn:aws:apigateway:{region}::/restapis/{resource_id}"
        elif resource_type == 'route53':
            return f"arn:aws:route53:::hostedzone/{resource_id}"
        elif resource_type == 'elastic_ip':
            return f"arn:aws:ec2:{region}:{account_id}:eip/{resource_id}"
        elif resource_type == 'ec2_instance':
            return f"arn:aws:ec2:{region}:{account_id}:instance/{resource_id}"
        elif resource_type == 'lambda':
            return f"arn:aws:lambda:{region}:{account_id}:function:{resource_id}"
        elif resource_type == 'rds':
            return f"arn:aws:rds:{region}:{account_id}:db:{resource_id}"
        elif resource_type == 'dynamodb':
            return f"arn:aws:dynamodb:{region}:{account_id}:table/{resource_id}"
        elif resource_type == 'sns':
            return f"arn:aws:sns:{region}:{account_id}:{resource_id}"
        elif resource_type == 'sqs':
            return f"arn:aws:sqs:{region}:{account_id}:{resource_id}"
        elif 'iam' in resource_type:
            return f"arn:aws:iam::{account_id}:role/{resource_id}"
        else:
            # Generic ARN format
            service = resource_type.replace('_', '-')
            return f"arn:aws:{service}:{region}:{account_id}:resource/{resource_id}"
    
    def _determine_edge_type(self, resource_type, finding):
        """
        Determine the edge type of exposure.
        
        Returns: network | identity | service | composite
        """
        # Identity-based
        if 'iam' in resource_type.lower():
            return "identity"
        
        # Network-based
        if resource_type in ['security_group', 'elastic_ip', 'ec2_instance']:
            return "network"
        
        # Service-based (API/application layer)
        if resource_type in ['s3_bucket', 'lambda', 'api_gateway', 'dynamodb', 
                              'sns', 'sqs', 'rds', 'opensearch', 'redshift',
                              'ecr', 'efs', 'ebs_snapshot', 'ami']:
            return "service"
        
        # Composite (multiple exposure types)
        if resource_type in ['cloudfront', 'load_balancer', 'elb', 
                              'elasticbeanstalk', 'apprunner', 'route53']:
            return "composite"
        
        return "service"  # Default
    
    def _determine_exposure_vector(self, resource_type, finding):
        """
        Determine how the resource is exposed.
        Returns None if cannot determine with confidence.
        """
        details = finding.get('details', '')
        
        # Only return exposure vectors we're confident about
        if resource_type == 's3_bucket':
            details_str = str(details).lower()
            if 'public acl' in details_str or 'acl' in details_str:
                return "s3_bucket_acl"
            elif 'bucket policy' in details_str or 'policy' in details_str:
                return "s3_bucket_policy"
            # If we have details but can't determine specific vector
            return "s3_public_access" if details else None
        
        elif resource_type == 'security_group':
            return "security_group_ingress_rule"
        
        elif resource_type == 'cloudfront':
            return "cloudfront_distribution"
        
        elif 'iam' in resource_type and 'access_analyzer' in resource_type:
            return "iam_trust_policy"
        
        # For other types, return None if we're not certain
        return None
    
    def _determine_public_endpoint(self, resource_type, finding):
        """
        Determine the public endpoint if available.
        Returns None if endpoint cannot be determined.
        """
        details = finding.get('details', '')
        resource_name = finding.get('resource_name', '')
        
        # Extract endpoint from details if explicitly available
        if isinstance(details, dict):
            if 'endpoint' in details:
                return details['endpoint']
            if 'url' in details:
                return details['url']
            if 'dns_name' in details:
                return details['dns_name']
            if 'domain_name' in details:
                return details['domain_name']
        
        # Only construct endpoints for resources where we're confident
        if resource_type == 's3_bucket' and resource_name:
            return f"https://{resource_name}.s3.amazonaws.com"
        
        elif resource_type == 'elastic_ip':
            # IP address is usually in resource_name or resource_id
            if resource_name and '.' in resource_name:
                return resource_name
            resource_id = finding.get('resource_id', '')
            if resource_id and '.' in resource_id:
                return resource_id
        
        # For all other cases, return None if we don't have explicit info
        return None
    
    def _determine_auth_required(self, resource_type, finding):
        """
        Determine authentication requirements.
        Returns: none | aws_iam | custom | None (if uncertain)
        """
        details = str(finding.get('details', '')).lower()
        
        # Only return values we're confident about
        
        # Check for explicit authentication info in details
        if 'no authentication' in details or 'anonymous access' in details:
            return "none"
        
        if 'iam authentication' in details or 'sigv4' in details:
            return "aws_iam"
        
        if 'api key' in details or 'custom auth' in details:
            return "custom"
        
        # For security groups and network-level access, no app-level auth
        if resource_type in ['security_group', 'elastic_ip']:
            return "none"
        
        # For S3 with explicit public access indicators
        if resource_type == 's3_bucket':
            if 'public read' in details or 'alluser' in details or 'anonymous' in details:
                return "none"
        
        # For IAM Access Analyzer findings with public access
        if 'iam' in resource_type and finding.get('is_public'):
            return "none"
        
        # For all other cases, return None if we're not certain
        return None
    
    def _determine_evidence_source(self, resource_type, finding):
        """Determine the source of evidence for this finding."""
        if 'iam_access_analyzer' in resource_type:
            return "aws_iam_access_analyzer"
        
        elif resource_type == 's3_bucket':
            return "aws_s3_api"
        
        elif resource_type == 'security_group':
            return "aws_ec2_api"
        
        elif resource_type == 'cloudfront':
            return "aws_cloudfront_api"
        
        elif 'load_balancer' in resource_type or resource_type == 'elb':
            return "aws_elb_api"
        
        elif resource_type == 'api_gateway':
            return "aws_apigateway_api"
        
        elif resource_type == 'route53':
            return "aws_route53_api"
        
        elif resource_type == 'lambda':
            return "aws_lambda_api"
        
        elif resource_type == 'rds':
            return "aws_rds_api"
        
        elif resource_type == 'dynamodb':
            return "aws_dynamodb_api"
        
        elif resource_type == 'opensearch':
            return "aws_opensearch_api"
        
        else:
            # Generic AWS API
            service = resource_type.replace('_', '')
            return f"aws_{service}_api"
    
    
    def _color_severity(self, severity):
        """
        Add color to severity level.
        
        Args:
            severity: Severity string
            
        Returns:
            Colored severity string
        """
        severity_lower = severity.lower()
        
        if severity_lower == 'critical':
            return f"{Fore.RED}{Style.BRIGHT}{severity.upper()}{Style.RESET_ALL}"
        elif severity_lower == 'high':
            return f"{Fore.RED}{severity.upper()}{Style.RESET_ALL}"
        elif severity_lower == 'medium':
            return f"{Fore.YELLOW}{severity.upper()}{Style.RESET_ALL}"
        elif severity_lower == 'low':
            return f"{Fore.BLUE}{severity.upper()}{Style.RESET_ALL}"
        else:
            return f"{Fore.GREEN}{severity.upper()}{Style.RESET_ALL}"
    
    def print_summary(self, findings):
        """
        Print a summary of findings.
        
        Args:
            findings: List of findings
        """
        print(f"\n{Style.BRIGHT}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Total findings: {len(findings)}")
        
        if findings:
            # Count by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\nFindings by severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    colored_severity = self._color_severity(severity)
                    print(f"  {colored_severity}: {count}")
