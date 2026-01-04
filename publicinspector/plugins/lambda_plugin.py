"""Lambda functions with public URLs scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class LambdaPlugin(AWSBasePlugin):
    """Scans Lambda functions with function URLs."""
    
    def get_name(self):
        """Return plugin name."""
        return "Lambda Function Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "lambda"
    
    def scan(self):
        """
        Scan Lambda functions with public URLs.
        
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
                print(f"Error scanning Lambda functions in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan Lambda functions in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            lambda_client = self.session.client('lambda', region_name=region)
            
            # Get all functions
            paginator = lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for function in page.get('Functions', []):
                    finding = self._check_function(function, region, lambda_client)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_function(self, function, region, lambda_client):
        """
        Check a Lambda function for public access.
        
        Args:
            function: Function details
            region: AWS region
            lambda_client: Lambda client
            
        Returns:
            Finding dictionary or None
        """
        function_name = function.get('FunctionName', 'unknown')
        function_arn = function.get('FunctionArn', 'unknown')
        
        # Check for function URL configuration
        has_public_url = False
        function_url = None
        
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=function_name)
            function_url = url_config.get('FunctionUrl')
            auth_type = url_config.get('AuthType', 'AWS_IAM')
            
            # NONE auth type means publicly accessible
            if auth_type == 'NONE':
                has_public_url = True
        except lambda_client.exceptions.ResourceNotFoundException:
            # No function URL configured
            pass
        except Exception:
            pass
        
        if not has_public_url:
            return None
        
        # Get tags
        tags = {}
        try:
            tag_response = lambda_client.list_tags(Resource=function_arn)
            tags = tag_response.get('Tags', {})
        except Exception:
            pass
        
        finding = {
            'resource_type': 'lambda_function',
            'resource_id': function_arn,
            'resource_name': function_name,
            'public_access': f'Lambda function with public URL: {function_url}',
            'region': region,
            'account_id': self.account_id,
            'severity': 'medium',
            'details': {
                'function_name': function_name,
                'function_url': function_url,
                'tags': tags
            }
        }
        
        return finding
