"""DynamoDB tables scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class DynamoDBPlugin(AWSBasePlugin):
    """Scans DynamoDB tables (tables themselves aren't public but checks for public endpoints)."""
    
    def get_name(self):
        """Return plugin name."""
        return "DynamoDB Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "dynamodb"
    
    def scan(self):
        """
        Scan DynamoDB tables.
        
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
                print(f"Error scanning DynamoDB in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan DynamoDB tables in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            dynamodb = self.session.client('dynamodb', region_name=region)
            
            # List all tables
            paginator = dynamodb.get_paginator('list_tables')
            
            for page in paginator.paginate():
                table_names = page.get('TableNames', [])
                
                for table_name in table_names:
                    finding = self._check_table(table_name, region, dynamodb)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_table(self, table_name, region, dynamodb_client):
        """
        Check a DynamoDB table.
        
        Args:
            table_name: Table name
            region: AWS region
            dynamodb_client: DynamoDB client
            
        Returns:
            Finding dictionary or None
        """
        try:
            response = dynamodb_client.describe_table(TableName=table_name)
            table = response.get('Table', {})
            
            table_arn = table.get('TableArn', 'unknown')
            
            # Get tags
            tags = {}
            try:
                tag_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
                for tag in tag_response.get('Tags', []):
                    tags[tag['Key']] = tag['Value']
            except Exception:
                pass
            
            # DynamoDB tables accessed via AWS API are not "publicly accessible" in traditional sense
            # They are protected by IAM. We report them for informational purposes.
            finding = {
                'resource_type': 'dynamodb_table',
                'resource_id': table_arn,
                'resource_name': table_name,
                'public_access': 'DynamoDB table (access controlled by IAM)',
                'region': region,
                'account_id': self.account_id,
                'severity': 'info',
                'details': {
                    'table_name': table_name,
                    'table_arn': table_arn,
                    'tags': tags
                }
            }
            
            return finding
            
        except Exception:
            pass
        
        return None
