"""RDS and Aurora instances scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class RDSPlugin(AWSBasePlugin):
    """Scans RDS and Aurora database instances for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "RDS/Aurora Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "rds"
    
    def scan(self):
        """
        Scan RDS instances for public accessibility.
        
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
                print(f"Error scanning RDS in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan RDS instances in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            rds = self.session.client('rds', region_name=region)
            
            # Get all DB instances
            paginator = rds.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                instances = page.get('DBInstances', [])
                
                for instance in instances:
                    if instance.get('PubliclyAccessible', False):
                        finding = self._check_instance(instance, region, rds)
                        if finding:
                            findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_instance(self, instance, region, rds_client):
        """
        Check an RDS instance.
        
        Args:
            instance: Instance details
            region: AWS region
            rds_client: RDS client
            
        Returns:
            Finding dictionary or None
        """
        instance_id = instance.get('DBInstanceIdentifier', 'unknown')
        instance_arn = instance.get('DBInstanceArn', 'unknown')
        engine = instance.get('Engine', 'unknown')
        endpoint = instance.get('Endpoint', {}).get('Address', 'unknown')
        
        # Get tags
        tags = {}
        try:
            tag_response = rds_client.list_tags_for_resource(ResourceName=instance_arn)
            for tag in tag_response.get('TagList', []):
                tags[tag['Key']] = tag['Value']
        except Exception:
            pass
        
        finding = {
            'resource_type': 'rds_instance',
            'resource_id': instance_arn,
            'resource_name': instance_id,
            'public_access': f'RDS instance is publicly accessible: {endpoint}',
            'region': region,
            'account_id': self.account_id,
            'severity': 'high',
            'details': {
                'instance_id': instance_id,
                'engine': engine,
                'endpoint': endpoint,
                'tags': tags
            }
        }
        
        return finding
