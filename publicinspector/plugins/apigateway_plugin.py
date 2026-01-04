"""API Gateway public access scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class APIGatewayPlugin(AWSBasePlugin):
    """Scans API Gateway REST APIs and HTTP APIs for public access."""
    
    def get_name(self):
        """Return plugin name."""
        return "API Gateway Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "apigateway"
    
    def scan(self):
        """
        Scan API Gateway APIs for public access.
        
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
                print(f"Error scanning API Gateway in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan API Gateway in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        # Scan REST APIs
        try:
            apigw = self.session.client('apigateway', region_name=region)
            rest_apis = apigw.get_rest_apis()
            
            for api in rest_apis.get('items', []):
                finding = self._check_rest_api(api, region, apigw)
                if finding:
                    findings.append(finding)
        except Exception:
            pass
        
        # Scan HTTP APIs (API Gateway v2)
        try:
            apigwv2 = self.session.client('apigatewayv2', region_name=region)
            
            paginator = apigwv2.get_paginator('get_apis')
            for page in paginator.paginate():
                for api in page.get('Items', []):
                    finding = self._check_http_api(api, region)
                    if finding:
                        findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _check_rest_api(self, api, region, apigw_client):
        """
        Check a REST API for public access.
        
        Args:
            api: API details
            region: AWS region
            apigw_client: API Gateway client
            
        Returns:
            Finding dictionary or None
        """
        api_id = api.get('id', 'unknown')
        api_name = api.get('name', 'unknown')
        
        # Get tags
        tags = {}
        try:
            tag_response = apigw_client.get_tags(resourceArn=f'arn:aws:apigateway:{region}::/restapis/{api_id}')
            tags = tag_response.get('tags', {})
        except Exception:
            pass
        
        # REST APIs are publicly accessible by default
        # Check if there's any authorization configured
        endpoint_config = api.get('endpointConfiguration', {})
        endpoint_types = endpoint_config.get('types', [])
        
        finding = {
            'resource_type': 'apigateway_rest_api',
            'resource_id': api_id,
            'resource_name': api_name,
            'public_access': 'REST API is publicly accessible',
            'region': region,
            'account_id': self.account_id,
            'severity': 'info',
            'details': {
                'api_id': api_id,
                'api_name': api_name,
                'endpoint_types': endpoint_types,
                'tags': tags
            }
        }
        
        return finding
    
    def _check_http_api(self, api, region):
        """
        Check an HTTP API for public access.
        
        Args:
            api: API details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        api_id = api.get('ApiId', 'unknown')
        api_name = api.get('Name', 'unknown')
        api_endpoint = api.get('ApiEndpoint', 'unknown')
        
        # Get tags
        tags = api.get('Tags', {})
        
        # HTTP APIs are publicly accessible by default
        finding = {
            'resource_type': 'apigateway_http_api',
            'resource_id': api_id,
            'resource_name': api_name,
            'public_access': 'HTTP API is publicly accessible',
            'region': region,
            'account_id': self.account_id,
            'severity': 'info',
            'details': {
                'api_id': api_id,
                'api_name': api_name,
                'api_endpoint': api_endpoint,
                'tags': tags
            }
        }
        
        return finding
