"""Redshift clusters scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class RedshiftPlugin(AWSBasePlugin):
    """Scans Redshift clusters for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "Redshift Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "redshift"
    
    def scan(self):
        """
        Scan Redshift clusters.
        
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
                print(f"Error scanning Redshift in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan Redshift clusters in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            redshift = self.session.client('redshift', region_name=region)
            
            # Get all clusters
            paginator = redshift.get_paginator('describe_clusters')
            
            for page in paginator.paginate():
                clusters = page.get('Clusters', [])
                
                for cluster in clusters:
                    if cluster.get('PubliclyAccessible', False):
                        finding = self._check_cluster(cluster, region)
                        if finding:
                            findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_cluster(self, cluster, region):
        """
        Check a Redshift cluster.
        
        Args:
            cluster: Cluster details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        cluster_id = cluster.get('ClusterIdentifier', 'unknown')
        endpoint = cluster.get('Endpoint', {}).get('Address', 'unknown')
        
        # Get tags
        tags = {}
        for tag in cluster.get('Tags', []):
            tags[tag['Key']] = tag['Value']
        
        finding = {
            'resource_type': 'redshift_cluster',
            'resource_id': cluster_id,
            'resource_name': cluster_id,
            'public_access': f'Redshift cluster is publicly accessible: {endpoint}',
            'region': region,
            'account_id': self.account_id,
            'severity': 'critical',
            'details': {
                'cluster_id': cluster_id,
                'endpoint': endpoint,
                'tags': tags
            }
        }
        
        return finding
