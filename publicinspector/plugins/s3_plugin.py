"""S3 bucket public access scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class S3Plugin(AWSBasePlugin):
    """Scans S3 buckets for public access configurations."""
    
    def get_name(self):
        """Return plugin name."""
        return "S3 Bucket Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "s3"
    
    def scan(self):
        """
        Scan S3 buckets for public access.
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # S3 is global but uses regional endpoints
            s3 = self.session.client('s3', region_name=self.region)
            
            # List all buckets
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check bucket for public access
                bucket_findings = self._check_bucket(s3, bucket_name)
                findings.extend(bucket_findings)
                
        except Exception as e:
            print(f"Error scanning S3 buckets: {e}")
        
        return findings
    
    def _check_bucket(self, s3_client, bucket_name):
        """
        Check a single bucket for public access.
        
        Args:
            s3_client: boto3 S3 client
            bucket_name: Name of the bucket
            
        Returns:
            List of findings for this bucket
        """
        findings = []
        public_access_reasons = []
        
        try:
            # Get bucket location
            try:
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
            except Exception:
                bucket_region = 'unknown'
            
            # Check public access block configuration
            try:
                public_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_block['PublicAccessBlockConfiguration']
                
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    public_access_reasons.append('Public access block not fully enabled')
            except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                public_access_reasons.append('No public access block configured')
            except Exception:
                pass
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri:
                            public_access_reasons.append('Bucket ACL allows public read access')
                        elif 'AuthenticatedUsers' in uri:
                            public_access_reasons.append('Bucket ACL allows authenticated user access')
            except Exception:
                pass
            
            # Check bucket policy
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = policy_response.get('Policy', '')
                if '*' in policy:
                    public_access_reasons.append('Bucket policy may contain wildcard principals')
            except s3_client.exceptions.NoSuchBucketPolicy:
                pass
            except Exception:
                pass
            
            # If any public access found, create a finding
            if public_access_reasons:
                finding = {
                    'resource_type': 's3_bucket',
                    'resource_id': bucket_name,
                    'resource_name': bucket_name,
                    'public_access': '; '.join(public_access_reasons),
                    'region': bucket_region,
                    'account_id': self.account_id,
                    'severity': 'high',
                    'details': {
                        'bucket_name': bucket_name,
                        'reasons': public_access_reasons
                    }
                }
                findings.append(finding)
                
        except Exception as e:
            # Skip buckets we can't access
            pass
        
        return findings
