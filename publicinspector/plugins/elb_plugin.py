"""Classic Elastic Load Balancer (ELB) public access scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class ELBPlugin(AWSBasePlugin):
    """Scans Classic Load Balancers for public access."""
    
    def get_name(self):
        """Return plugin name."""
        return "Classic ELB Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "elb"
    
    def scan(self):
        """
        Scan Classic ELBs for public access.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get all regions to scan
        regions = self.get_all_regions()
        
        for region in regions:
            try:
                region_findings = self._scan_region(region)
                findings.extend(region_findings)
            except Exception as e:
                print(f"Error scanning ELBs in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan ELBs in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            elb = self.session.client('elb', region_name=region)
            
            # Get all load balancers
            paginator = elb.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                load_balancers = page.get('LoadBalancerDescriptions', [])
                
                for lb in load_balancers:
                    finding = self._check_load_balancer(lb, region, elb)
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            # Skip regions we can't access
            pass
        
        return findings
    
    def _check_load_balancer(self, lb, region, elb_client):
        """
        Check a Classic ELB for public access.
        
        Args:
            lb: Load balancer details
            region: AWS region
            elb_client: boto3 ELB client
            
        Returns:
            Finding dictionary or None
        """
        lb_name = lb.get('LoadBalancerName', 'unknown')
        scheme = lb.get('Scheme', 'unknown')
        dns_name = lb.get('DNSName', 'unknown')
        
        # Get tags
        tags = {}
        try:
            tag_response = elb_client.describe_tags(LoadBalancerNames=[lb_name])
            tag_descriptions = tag_response.get('TagDescriptions', [])
            if tag_descriptions:
                for tag in tag_descriptions[0].get('Tags', []):
                    tags[tag['Key']] = tag['Value']
        except Exception:
            pass
        
        # Check if load balancer is internet-facing
        if scheme == 'internet-facing':
            finding = {
                'resource_type': 'classic_load_balancer',
                'resource_id': lb_name,
                'resource_name': lb_name,
                'public_access': 'Classic load balancer is internet-facing',
                'region': region,
                'account_id': self.account_id,
                'severity': 'medium',
                'details': {
                    'load_balancer_name': lb_name,
                    'dns_name': dns_name,
                    'scheme': scheme,
                    'tags': tags
                }
            }
            
            return finding
        
        return None
