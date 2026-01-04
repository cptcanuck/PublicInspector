"""AMI (Amazon Machine Images) scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class AMIPlugin(AWSBasePlugin):
    """Scans AMIs for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "AMI Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "ami"
    
    def scan(self):
        """
        Scan AMIs.
        
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
                print(f"Error scanning AMIs in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan AMIs in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            ec2 = self.session.client('ec2', region_name=region)
            
            # Get AMIs owned by this account
            response = ec2.describe_images(Owners=['self'])
            images = response.get('Images', [])
            
            for image in images:
                if image.get('Public', False):
                    finding = self._check_ami(image, region)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_ami(self, image, region):
        """
        Check an AMI.
        
        Args:
            image: Image details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        image_id = image.get('ImageId', 'unknown')
        image_name = image.get('Name', image_id)
        description = image.get('Description', '')
        
        # Get tags
        tags = {}
        for tag in image.get('Tags', []):
            tags[tag['Key']] = tag['Value']
        
        finding = {
            'resource_type': 'ami',
            'resource_id': image_id,
            'resource_name': image_name,
            'public_access': 'AMI is publicly shared',
            'region': region,
            'account_id': self.account_id,
            'severity': 'high',
            'details': {
                'image_id': image_id,
                'image_name': image_name,
                'description': description,
                'tags': tags
            }
        }
        
        return finding
