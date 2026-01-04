"""EBS snapshots scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class EBSSnapshotPlugin(AWSBasePlugin):
    """Scans EBS snapshots for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "EBS Snapshot Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "ebs_snapshots"
    
    def scan(self):
        """
        Scan EBS snapshots.
        
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
                print(f"Error scanning EBS snapshots in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan EBS snapshots in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            ec2 = self.session.client('ec2', region_name=region)
            
            # Get snapshots owned by this account
            response = ec2.describe_snapshots(OwnerIds=['self'])
            snapshots = response.get('Snapshots', [])
            
            for snapshot in snapshots:
                finding = self._check_snapshot(snapshot, region, ec2)
                if finding:
                    findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_snapshot(self, snapshot, region, ec2_client):
        """
        Check an EBS snapshot.
        
        Args:
            snapshot: Snapshot details
            region: AWS region
            ec2_client: EC2 client
            
        Returns:
            Finding dictionary or None
        """
        snapshot_id = snapshot.get('SnapshotId', 'unknown')
        description = snapshot.get('Description', '')
        volume_size = snapshot.get('VolumeSize', 0)
        
        # Get tags
        tags = {}
        for tag in snapshot.get('Tags', []):
            tags[tag['Key']] = tag['Value']
        
        # Check permissions
        try:
            perms = ec2_client.describe_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute='createVolumePermission'
            )
            
            create_volume_perms = perms.get('CreateVolumePermissions', [])
            
            # Check if publicly shared
            is_public = False
            for perm in create_volume_perms:
                if perm.get('Group') == 'all':
                    is_public = True
                    break
            
            if is_public:
                finding = {
                    'resource_type': 'ebs_snapshot',
                    'resource_id': snapshot_id,
                    'resource_name': snapshot_id,
                    'public_access': f'EBS snapshot is publicly shared ({volume_size} GB)',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'critical',
                    'details': {
                        'snapshot_id': snapshot_id,
                        'description': description,
                        'volume_size_gb': volume_size,
                        'tags': tags
                    }
                }
                
                return finding
                
        except Exception:
            pass
        
        return None
