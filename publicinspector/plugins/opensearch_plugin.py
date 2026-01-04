"""OpenSearch domains scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class OpenSearchPlugin(AWSBasePlugin):
    """Scans OpenSearch/Elasticsearch domains for public access."""
    
    def get_name(self):
        """Return plugin name."""
        return "OpenSearch Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "opensearch"
    
    def scan(self):
        """
        Scan OpenSearch domains.
        
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
                print(f"Error scanning OpenSearch in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan OpenSearch domains in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            opensearch = self.session.client('opensearch', region_name=region)
            
            # List all domain names
            response = opensearch.list_domain_names()
            domain_names = [d['DomainName'] for d in response.get('DomainNames', [])]
            
            for domain_name in domain_names:
                finding = self._check_domain(domain_name, region, opensearch)
                if finding:
                    findings.append(finding)
                        
        except Exception:
            # Try Elasticsearch service for older domains
            try:
                es = self.session.client('es', region_name=region)
                response = es.list_domain_names()
                domain_names = [d['DomainName'] for d in response.get('DomainNames', [])]
                
                for domain_name in domain_names:
                    finding = self._check_es_domain(domain_name, region, es)
                    if finding:
                        findings.append(finding)
            except Exception:
                pass
        
        return findings
    
    def _check_domain(self, domain_name, region, opensearch_client):
        """
        Check an OpenSearch domain.
        
        Args:
            domain_name: Domain name
            region: AWS region
            opensearch_client: OpenSearch client
            
        Returns:
            Finding dictionary or None
        """
        try:
            response = opensearch_client.describe_domain(DomainName=domain_name)
            domain = response.get('DomainStatus', {})
            
            endpoint = domain.get('Endpoint')
            domain_arn = domain.get('ARN', 'unknown')
            
            # Check if domain has public endpoint
            vpc_options = domain.get('VPCOptions', {})
            is_vpc = bool(vpc_options.get('VPCId'))
            
            if not is_vpc and endpoint:
                # Get tags
                tags = {}
                try:
                    tag_response = opensearch_client.list_tags(ARN=domain_arn)
                    for tag in tag_response.get('TagList', []):
                        tags[tag['Key']] = tag['Value']
                except Exception:
                    pass
                
                finding = {
                    'resource_type': 'opensearch_domain',
                    'resource_id': domain_arn,
                    'resource_name': domain_name,
                    'public_access': f'OpenSearch domain with public endpoint: {endpoint}',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'high',
                    'details': {
                        'domain_name': domain_name,
                        'endpoint': endpoint,
                        'tags': tags
                    }
                }
                
                return finding
                
        except Exception:
            pass
        
        return None
    
    def _check_es_domain(self, domain_name, region, es_client):
        """
        Check an Elasticsearch domain.
        
        Args:
            domain_name: Domain name
            region: AWS region
            es_client: Elasticsearch client
            
        Returns:
            Finding dictionary or None
        """
        try:
            response = es_client.describe_elasticsearch_domain(DomainName=domain_name)
            domain = response.get('DomainStatus', {})
            
            endpoint = domain.get('Endpoint')
            domain_arn = domain.get('ARN', 'unknown')
            
            # Check if domain has public endpoint
            vpc_options = domain.get('VPCOptions', {})
            is_vpc = bool(vpc_options.get('VPCId'))
            
            if not is_vpc and endpoint:
                # Get tags
                tags = {}
                try:
                    tag_response = es_client.list_tags(ARN=domain_arn)
                    for tag in tag_response.get('TagList', []):
                        tags[tag['Key']] = tag['Value']
                except Exception:
                    pass
                
                finding = {
                    'resource_type': 'elasticsearch_domain',
                    'resource_id': domain_arn,
                    'resource_name': domain_name,
                    'public_access': f'Elasticsearch domain with public endpoint: {endpoint}',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'high',
                    'details': {
                        'domain_name': domain_name,
                        'endpoint': endpoint,
                        'tags': tags
                    }
                }
                
                return finding
                
        except Exception:
            pass
        
        return None
