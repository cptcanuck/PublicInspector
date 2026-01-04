"""CloudFront distribution public access scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class CloudFrontPlugin(AWSBasePlugin):
    """Scans CloudFront distributions for public access."""
    
    def get_name(self):
        """Return plugin name."""
        return "CloudFront Distribution Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "cloudfront"
    
    def scan(self):
        """
        Scan CloudFront distributions for public access.
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # CloudFront is a global service, use us-east-1
            cloudfront = self.session.client('cloudfront', region_name='us-east-1')
            
            # List all distributions
            paginator = cloudfront.get_paginator('list_distributions')
            
            for page in paginator.paginate():
                distribution_list = page.get('DistributionList', {})
                items = distribution_list.get('Items', [])
                
                for distribution in items:
                    finding = self._check_distribution(distribution)
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            print(f"Error scanning CloudFront distributions: {e}")
        
        return findings
    
    def _check_distribution(self, distribution):
        """
        Check a CloudFront distribution for public access.
        
        Args:
            distribution: Distribution details from API
            
        Returns:
            Finding dictionary or None
        """
        dist_id = distribution.get('Id', 'unknown')
        domain_name = distribution.get('DomainName', 'unknown')
        enabled = distribution.get('Enabled', False)
        
        # CloudFront distributions are inherently public-facing
        # We report all enabled distributions
        if enabled:
            origins = distribution.get('Origins', {}).get('Items', [])
            origin_info = []
            
            for origin in origins:
                origin_domain = origin.get('DomainName', 'unknown')
                origin_info.append(origin_domain)
            
            finding = {
                'resource_type': 'cloudfront_distribution',
                'resource_id': dist_id,
                'resource_name': domain_name,
                'public_access': 'CloudFront distribution is publicly accessible',
                'region': 'global',
                'account_id': self.account_id,
                'severity': 'info',
                'details': {
                    'distribution_id': dist_id,
                    'domain_name': domain_name,
                    'origins': origin_info,
                    'enabled': enabled
                }
            }
            
            return finding
        
        return None
