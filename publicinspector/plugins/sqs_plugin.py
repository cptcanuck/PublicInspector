"""SQS queues scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class SQSPlugin(AWSBasePlugin):
    """Scans SQS queues for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "SQS Queue Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "sqs"
    
    def scan(self):
        """
        Scan SQS queues.
        
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
                print(f"Error scanning SQS in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan SQS queues in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            sqs = self.session.client('sqs', region_name=region)
            
            # List all queues
            response = sqs.list_queues()
            queue_urls = response.get('QueueUrls', [])
            
            for queue_url in queue_urls:
                finding = self._check_queue(queue_url, region, sqs)
                if finding:
                    findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_queue(self, queue_url, region, sqs_client):
        """
        Check an SQS queue.
        
        Args:
            queue_url: Queue URL
            region: AWS region
            sqs_client: SQS client
            
        Returns:
            Finding dictionary or None
        """
        queue_name = queue_url.split('/')[-1]
        
        # Get queue attributes including policy
        try:
            attrs = sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['All']
            )
            attributes = attrs.get('Attributes', {})
            
            policy = attributes.get('Policy', '')
            queue_arn = attributes.get('QueueArn', queue_url)
            
            # Check if policy allows public access
            if '*' in policy and ('SendMessage' in policy or 'ReceiveMessage' in policy):
                # Get tags
                tags = {}
                try:
                    tag_response = sqs_client.list_queue_tags(QueueUrl=queue_url)
                    tags = tag_response.get('Tags', {})
                except Exception:
                    pass
                
                finding = {
                    'resource_type': 'sqs_queue',
                    'resource_id': queue_arn,
                    'resource_name': queue_name,
                    'public_access': 'SQS queue policy may allow public access',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'medium',
                    'details': {
                        'queue_name': queue_name,
                        'queue_url': queue_url,
                        'tags': tags
                    }
                }
                
                return finding
                
        except Exception:
            pass
        
        return None
