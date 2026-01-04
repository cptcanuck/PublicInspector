"""EFS file systems scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class EFSPlugin(AWSBasePlugin):
    """Scans EFS file systems for public mount targets."""
    
    def get_name(self):
        """Return plugin name."""
        return "EFS Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "efs"
    
    def scan(self):
        """
        Scan EFS file systems.
        
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
                print(f"Error scanning EFS in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan EFS file systems in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            efs = self.session.client('efs', region_name=region)
            
            # Get all file systems
            paginator = efs.get_paginator('describe_file_systems')
            
            for page in paginator.paginate():
                file_systems = page.get('FileSystems', [])
                
                for fs in file_systems:
                    finding = self._check_file_system(fs, region, efs)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_file_system(self, fs, region, efs_client):
        """
        Check an EFS file system.
        
        Args:
            fs: File system details
            region: AWS region
            efs_client: EFS client
            
        Returns:
            Finding dictionary or None
        """
        fs_id = fs.get('FileSystemId', 'unknown')
        fs_name = fs.get('Name', fs_id)
        
        # Get tags
        tags = {}
        for tag in fs.get('Tags', []):
            tags[tag['Key']] = tag['Value']
            if tag['Key'] == 'Name':
                fs_name = tag['Value']
        
        # Check mount targets - EFS itself isn't directly public,
        # but we report it if it has mount targets that could be accessed
        try:
            mt_response = efs_client.describe_mount_targets(FileSystemId=fs_id)
            mount_targets = mt_response.get('MountTargets', [])
            
            if mount_targets:
                # EFS is accessible via mount targets in VPC
                # We report it as potentially accessible
                finding = {
                    'resource_type': 'efs_file_system',
                    'resource_id': fs_id,
                    'resource_name': fs_name,
                    'public_access': f'EFS file system with {len(mount_targets)} mount target(s)',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'info',
                    'details': {
                        'file_system_id': fs_id,
                        'mount_target_count': len(mount_targets),
                        'tags': tags
                    }
                }
                
                return finding
        except Exception:
            pass
        
        return None
