"""SNS topics scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class SNSPlugin(AWSBasePlugin):
    """Scans SNS topics for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "SNS Topic Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "sns"
    
    def scan(self):
        """
        Scan SNS topics.
        
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
                print(f"Error scanning SNS in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan SNS topics in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            sns = self.session.client('sns', region_name=region)
            
            # List all topics
            paginator = sns.get_paginator('list_topics')
            
            for page in paginator.paginate():
                topics = page.get('Topics', [])
                
                for topic in topics:
                    finding = self._check_topic(topic, region, sns)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_topic(self, topic, region, sns_client):
        """
        Check an SNS topic.
        
        Args:
            topic: Topic details
            region: AWS region
            sns_client: SNS client
            
        Returns:
            Finding dictionary or None
        """
        topic_arn = topic.get('TopicArn', 'unknown')
        topic_name = topic_arn.split(':')[-1] if ':' in topic_arn else topic_arn
        
        # Get topic attributes including policy
        try:
            attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
            attributes = attrs.get('Attributes', {})
            
            policy = attributes.get('Policy', '')
            
            # Check if policy allows public access
            if '*' in policy and ('Publish' in policy or 'Subscribe' in policy):
                # Get tags
                tags = {}
                try:
                    tag_response = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
                    for tag in tag_response.get('Tags', []):
                        tags[tag['Key']] = tag['Value']
                except Exception:
                    pass
                
                finding = {
                    'resource_type': 'sns_topic',
                    'resource_id': topic_arn,
                    'resource_name': topic_name,
                    'public_access': 'SNS topic policy may allow public access',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'medium',
                    'details': {
                        'topic_arn': topic_arn,
                        'topic_name': topic_name,
                        'tags': tags
                    }
                }
                
                return finding
                
        except Exception:
            pass
        
        return None
