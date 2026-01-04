"""EC2 instances with public IPs scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class EC2InstancePlugin(AWSBasePlugin):
    """Scans EC2 instances with public IP addresses."""
    
    def get_name(self):
        """Return plugin name."""
        return "EC2 Instance Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "ec2_instances"
    
    def scan(self):
        """
        Scan EC2 instances with public IPs.
        
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
                print(f"Error scanning EC2 instances in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan EC2 instances in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            ec2 = self.session.client('ec2', region_name=region)
            
            # Get all instances with public IPs
            paginator = ec2.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        finding = self._check_instance(instance, region)
                        if finding:
                            findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_instance(self, instance, region):
        """
        Check an EC2 instance for public access.
        
        Args:
            instance: Instance details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        instance_id = instance.get('InstanceId', 'unknown')
        public_ip = instance.get('PublicIpAddress')
        state = instance.get('State', {}).get('Name', 'unknown')
        
        # Only report instances with public IPs
        if not public_ip:
            return None
        
        # Get instance name from tags
        instance_name = instance_id
        tags = {}
        for tag in instance.get('Tags', []):
            tags[tag['Key']] = tag['Value']
            if tag['Key'] == 'Name':
                instance_name = tag['Value']
        
        # Get security groups
        security_groups = []
        for sg in instance.get('SecurityGroups', []):
            security_groups.append(sg.get('GroupId', 'unknown'))
        
        finding = {
            'resource_type': 'ec2_instance',
            'resource_id': instance_id,
            'resource_name': instance_name,
            'public_access': f'EC2 instance with public IP: {public_ip}',
            'region': region,
            'account_id': self.account_id,
            'severity': 'medium',
            'details': {
                'instance_id': instance_id,
                'public_ip': public_ip,
                'state': state,
                'security_groups': security_groups,
                'tags': tags
            }
        }
        
        return finding
