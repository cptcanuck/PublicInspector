"""Elastic Beanstalk environments scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class ElasticBeanstalkPlugin(AWSBasePlugin):
    """Scans Elastic Beanstalk environments."""
    
    def get_name(self):
        """Return plugin name."""
        return "Elastic Beanstalk Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "elasticbeanstalk"
    
    def scan(self):
        """
        Scan Elastic Beanstalk environments.
        
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
                print(f"Error scanning Elastic Beanstalk in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan Elastic Beanstalk environments in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            eb = self.session.client('elasticbeanstalk', region_name=region)
            
            # Get all environments
            response = eb.describe_environments()
            environments = response.get('Environments', [])
            
            for env in environments:
                finding = self._check_environment(env, region, eb)
                if finding:
                    findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_environment(self, env, region, eb_client):
        """
        Check an Elastic Beanstalk environment.
        
        Args:
            env: Environment details
            region: AWS region
            eb_client: Elastic Beanstalk client
            
        Returns:
            Finding dictionary or None
        """
        env_name = env.get('EnvironmentName', 'unknown')
        env_id = env.get('EnvironmentId', 'unknown')
        cname = env.get('CNAME', 'unknown')
        status = env.get('Status', 'unknown')
        
        # Get tags
        tags = {}
        try:
            tag_response = eb_client.list_tags_for_resource(ResourceArn=env.get('EnvironmentArn'))
            for tag in tag_response.get('ResourceTags', []):
                tags[tag['Key']] = tag['Value']
        except Exception:
            pass
        
        # Elastic Beanstalk environments with CNAME are publicly accessible
        if cname and cname != 'unknown':
            finding = {
                'resource_type': 'elasticbeanstalk_environment',
                'resource_id': env_id,
                'resource_name': env_name,
                'public_access': f'Elastic Beanstalk environment is publicly accessible: {cname}',
                'region': region,
                'account_id': self.account_id,
                'severity': 'info',
                'details': {
                    'environment_name': env_name,
                    'cname': cname,
                    'status': status,
                    'tags': tags
                }
            }
            
            return finding
        
        return None
