"""Elastic IP addresses scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class ElasticIPPlugin(AWSBasePlugin):
    """Scans Elastic IP addresses."""
    
    def get_name(self):
        """Return plugin name."""
        return "Elastic IP Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "elastic_ip"
    
    def scan(self):
        """
        Scan Elastic IPs.
        
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
                print(f"Error scanning Elastic IPs in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan Elastic IPs in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            ec2 = self.session.client('ec2', region_name=region)
            
            # Get all Elastic IPs
            response = ec2.describe_addresses()
            addresses = response.get('Addresses', [])
            
            for address in addresses:
                finding = self._check_elastic_ip(address, region)
                if finding:
                    findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_elastic_ip(self, address, region):
        """
        Check an Elastic IP.
        
        Args:
            address: Elastic IP details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        public_ip = address.get('PublicIp', 'unknown')
        allocation_id = address.get('AllocationId', 'unknown')
        association_id = address.get('AssociationId')
        instance_id = address.get('InstanceId')
        
        # Get tags
        tags = {}
        for tag in address.get('Tags', []):
            tags[tag['Key']] = tag['Value']
        
        # Elastic IPs are public by definition
        status = 'Associated' if association_id else 'Unassociated'
        
        finding = {
            'resource_type': 'elastic_ip',
            'resource_id': allocation_id,
            'resource_name': public_ip,
            'public_access': f'Public Elastic IP ({status})',
            'region': region,
            'account_id': self.account_id,
            'severity': 'low' if association_id else 'info',
            'details': {
                'public_ip': public_ip,
                'allocation_id': allocation_id,
                'instance_id': instance_id,
                'status': status,
                'tags': tags
            }
        }
        
        return finding
