"""Route53 public hosted zones scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class Route53Plugin(AWSBasePlugin):
    """Scans Route53 public hosted zones."""
    
    def get_name(self):
        """Return plugin name."""
        return "Route53 Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "route53"
    
    def scan(self):
        """
        Scan Route53 hosted zones for public zones.
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Route53 is a global service
            route53 = self.session.client('route53', region_name='us-east-1')
            
            # List all hosted zones
            paginator = route53.get_paginator('list_hosted_zones')
            
            for page in paginator.paginate():
                zones = page.get('HostedZones', [])
                
                for zone in zones:
                    # Only report public hosted zones
                    if not zone.get('Config', {}).get('PrivateZone', False):
                        finding = self._check_hosted_zone(zone, route53)
                        if finding:
                            findings.append(finding)
                            
        except Exception as e:
            print(f"Error scanning Route53 hosted zones: {e}")
        
        return findings
    
    def _check_hosted_zone(self, zone, route53_client):
        """
        Check a hosted zone.
        
        Args:
            zone: Hosted zone details
            route53_client: Route53 client
            
        Returns:
            Finding dictionary or None
        """
        zone_id = zone.get('Id', 'unknown').split('/')[-1]
        zone_name = zone.get('Name', 'unknown')
        
        # Get tags
        tags = {}
        try:
            tag_response = route53_client.list_tags_for_resource(
                ResourceType='hostedzone',
                ResourceId=zone_id
            )
            for tag in tag_response.get('Tags', []):
                tags[tag['Key']] = tag['Value']
        except Exception:
            pass
        
        finding = {
            'resource_type': 'route53_hosted_zone',
            'resource_id': zone_id,
            'resource_name': zone_name,
            'public_access': 'Public hosted zone with DNS records',
            'region': 'global',
            'account_id': self.account_id,
            'severity': 'info',
            'details': {
                'zone_id': zone_id,
                'zone_name': zone_name,
                'tags': tags
            }
        }
        
        return finding
