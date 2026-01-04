"""AWS App Runner services scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class AppRunnerPlugin(AWSBasePlugin):
    """Scans App Runner services."""
    
    def get_name(self):
        """Return plugin name."""
        return "App Runner Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "apprunner"
    
    def scan(self):
        """
        Scan App Runner services.
        
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
                print(f"Error scanning App Runner in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan App Runner services in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            apprunner = self.session.client('apprunner', region_name=region)
            
            # List all services
            paginator = apprunner.get_paginator('list_services')
            
            for page in paginator.paginate():
                services = page.get('ServiceSummaryList', [])
                
                for service_summary in services:
                    service_arn = service_summary.get('ServiceArn')
                    
                    # Get detailed service info
                    service_detail = apprunner.describe_service(ServiceArn=service_arn)
                    service = service_detail.get('Service', {})
                    
                    finding = self._check_service(service, region)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_service(self, service, region):
        """
        Check an App Runner service.
        
        Args:
            service: Service details
            region: AWS region
            
        Returns:
            Finding dictionary or None
        """
        service_name = service.get('ServiceName', 'unknown')
        service_arn = service.get('ServiceArn', 'unknown')
        service_url = service.get('ServiceUrl', 'unknown')
        status = service.get('Status', 'unknown')
        
        # App Runner services are publicly accessible by default
        # Check if service is ingress configuration
        network_config = service.get('NetworkConfiguration', {})
        ingress_config = network_config.get('IngressConfiguration', {})
        is_public = ingress_config.get('IsPubliclyAccessible', True)
        
        if not is_public:
            return None
        
        finding = {
            'resource_type': 'apprunner_service',
            'resource_id': service_arn,
            'resource_name': service_name,
            'public_access': f'App Runner service is publicly accessible: https://{service_url}',
            'region': region,
            'account_id': self.account_id,
            'severity': 'info',
            'details': {
                'service_name': service_name,
                'service_url': service_url,
                'status': status,
                'tags': {}
            }
        }
        
        return finding
