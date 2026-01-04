"""ECR (Elastic Container Registry) repositories scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class ECRPlugin(AWSBasePlugin):
    """Scans ECR repositories for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "ECR Repository Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "ecr"
    
    def scan(self):
        """
        Scan ECR repositories.
        
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
                print(f"Error scanning ECR in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan ECR repositories in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        # Check private ECR repositories
        try:
            ecr = self.session.client('ecr', region_name=region)
            
            paginator = ecr.get_paginator('describe_repositories')
            
            for page in paginator.paginate():
                repositories = page.get('repositories', [])
                
                for repo in repositories:
                    finding = self._check_repository(repo, region, ecr)
                    if finding:
                        findings.append(finding)
        except Exception:
            pass
        
        # Check public ECR repositories
        try:
            ecr_public = self.session.client('ecr-public', region_name='us-east-1')
            
            paginator = ecr_public.get_paginator('describe_repositories')
            
            for page in paginator.paginate():
                repositories = page.get('repositories', [])
                
                for repo in repositories:
                    finding = self._check_public_repository(repo, 'us-east-1')
                    if finding:
                        findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _check_repository(self, repo, region, ecr_client):
        """
        Check a private ECR repository.
        
        Args:
            repo: Repository details
            region: AWS region
            ecr_client: ECR client
            
        Returns:
            Finding dictionary or None
        """
        repo_name = repo.get('repositoryName', 'unknown')
        repo_arn = repo.get('repositoryArn', 'unknown')
        repo_uri = repo.get('repositoryUri', 'unknown')
        
        # Get repository policy
        try:
            policy_response = ecr_client.get_repository_policy(repositoryName=repo_name)
            policy_text = policy_response.get('policyText', '')
            
            # Check if policy allows public access
            if '*' in policy_text:
                # Get tags
                tags = {}
                try:
                    tag_response = ecr_client.list_tags_for_resource(resourceArn=repo_arn)
                    for tag in tag_response.get('tags', []):
                        tags[tag['Key']] = tag['Value']
                except Exception:
                    pass
                
                finding = {
                    'resource_type': 'ecr_repository',
                    'resource_id': repo_arn,
                    'resource_name': repo_name,
                    'public_access': 'ECR repository policy may allow public access',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'medium',
                    'details': {
                        'repository_name': repo_name,
                        'repository_uri': repo_uri,
                        'tags': tags
                    }
                }
                
                return finding
        except ecr_client.exceptions.RepositoryPolicyNotFoundException:
            pass
        except Exception:
            pass
        
        return None
    
    def _check_public_repository(self, repo, region):
        """
        Check a public ECR repository.
        
        Args:
            repo: Repository details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        repo_name = repo.get('repositoryName', 'unknown')
        repo_arn = repo.get('repositoryArn', 'unknown')
        repo_uri = repo.get('repositoryUri', 'unknown')
        
        # Public ECR repositories are public by definition
        finding = {
            'resource_type': 'ecr_public_repository',
            'resource_id': repo_arn,
            'resource_name': repo_name,
            'public_access': 'Public ECR repository',
            'region': region,
            'account_id': self.account_id,
            'severity': 'info',
            'details': {
                'repository_name': repo_name,
                'repository_uri': repo_uri,
                'tags': {}
            }
        }
        
        return finding
