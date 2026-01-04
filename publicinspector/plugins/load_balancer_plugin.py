"""Load Balancer public access scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class LoadBalancerPlugin(AWSBasePlugin):
    """Scans Application and Network Load Balancers for public access."""
    
    def get_name(self):
        """Return plugin name."""
        return "Load Balancer Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "load_balancers"
    
    def scan(self):
        """
        Scan load balancers for public access.
        
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
                print(f"Error scanning load balancers in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan load balancers in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            elbv2 = self.session.client('elbv2', region_name=region)
            
            # Get all load balancers (ALB and NLB)
            paginator = elbv2.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                load_balancers = page.get('LoadBalancers', [])
                
                for lb in load_balancers:
                    finding = self._check_load_balancer(lb, region)
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            # Skip regions we can't access
            pass
        
        return findings
    
    def _check_load_balancer(self, lb, region):
        """
        Check a load balancer for public access.
        
        Args:
            lb: Load balancer details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        lb_arn = lb.get('LoadBalancerArn', 'unknown')
        lb_name = lb.get('LoadBalancerName', 'unknown')
        lb_type = lb.get('Type', 'unknown')
        scheme = lb.get('Scheme', 'unknown')
        dns_name = lb.get('DNSName', 'unknown')
        
        # Check if load balancer is internet-facing
        if scheme == 'internet-facing':
            finding = {
                'resource_type': 'load_balancer',
                'resource_id': lb_arn,
                'resource_name': lb_name,
                'public_access': 'Load balancer is internet-facing',
                'region': region,
                'account_id': self.account_id,
                'severity': 'medium',
                'details': {
                    'load_balancer_name': lb_name,
                    'load_balancer_type': lb_type,
                    'dns_name': dns_name,
                    'scheme': scheme
                }
            }
            
            return finding
        
        return None
