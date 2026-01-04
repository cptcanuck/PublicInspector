"""IAM Access Analyzer plugin for detecting external access to IAM roles and policies."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class IAMAccessAnalyzerPlugin(AWSBasePlugin):
    """Scans for IAM roles/policies with external access using IAM Access Analyzer."""
    
    def get_name(self):
        """Return plugin name."""
        return "IAM Access Analyzer Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "iam_access_analyzer"
    
    def scan(self):
        """
        Scan for IAM resources with external access using Access Analyzer.
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # IAM Access Analyzer is regional
            analyzer_client = self.session.client('accessanalyzer', region_name=self.region)
            
            # List all analyzers in this region
            analyzers = self._list_analyzers(analyzer_client)
            
            if not analyzers:
                # No analyzer found - this is common for regions not in use
                return findings
            
            # Use the first active analyzer
            analyzer_arn = None
            for analyzer in analyzers:
                if analyzer.get('status') == 'ACTIVE':
                    analyzer_arn = analyzer.get('arn')
                    break
            
            if not analyzer_arn:
                # No active analyzer in this region
                return findings
            
            # Get findings from the analyzer
            findings = self._get_analyzer_findings(analyzer_client, analyzer_arn)
            
        except analyzer_client.exceptions.ResourceNotFoundException:
            # No analyzer configured in this region
            pass
        except Exception as e:
            error_str = str(e)
            # Skip if Access Analyzer is not available/enabled
            if 'AccessDeniedException' in error_str or 'not available' in error_str:
                pass
            else:
                print(f"Error scanning IAM Access Analyzer in {self.region}: {e}")
        
        return findings
    
    def _list_analyzers(self, client):
        """
        List all Access Analyzers in the region.
        
        Args:
            client: boto3 accessanalyzer client
            
        Returns:
            List of analyzer summaries
        """
        try:
            response = client.list_analyzers()
            return response.get('analyzers', [])
        except Exception as e:
            print(f"Error listing analyzers: {e}")
            return []
    
    def _get_analyzer_findings(self, client, analyzer_arn):
        """
        Get findings from an Access Analyzer.
        
        Args:
            client: boto3 accessanalyzer client
            analyzer_arn: ARN of the analyzer
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # List findings - filter for ACTIVE findings only
            paginator = client.get_paginator('list_findings')
            
            # Filter for external access findings
            finding_filter = {
                'status': {
                    'eq': ['ACTIVE']
                }
            }
            
            page_iterator = paginator.paginate(
                analyzerArn=analyzer_arn,
                filter=finding_filter
            )
            
            for page in page_iterator:
                for finding_summary in page.get('findings', []):
                    # Get detailed finding information
                    finding_detail = self._get_finding_detail(
                        client, 
                        analyzer_arn, 
                        finding_summary.get('id')
                    )
                    
                    if finding_detail:
                        findings.append(finding_detail)
                        
        except Exception as e:
            print(f"Error getting analyzer findings: {e}")
        
        return findings
    
    def _get_finding_detail(self, client, analyzer_arn, finding_id):
        """
        Get detailed information about a specific finding.
        
        Args:
            client: boto3 accessanalyzer client
            analyzer_arn: ARN of the analyzer
            finding_id: ID of the finding
            
        Returns:
            Dictionary with finding details or None
        """
        try:
            response = client.get_finding(
                analyzerArn=analyzer_arn,
                id=finding_id
            )
            
            finding = response.get('finding', {})
            
            # Extract relevant information
            resource_type = finding.get('resourceType', 'Unknown')
            resource_arn = finding.get('resource', 'Unknown')
            
            # Get resource name from ARN
            resource_name = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]
            
            # Build finding result
            result = {
                'resource_type': f'iam_{resource_type.lower()}',
                'resource_id': finding_id,
                'resource_name': resource_name,
                'resource_arn': resource_arn,
                'account_id': self.account_id,
                'region': self.region,
                'finding_type': finding.get('resourceType', 'Unknown'),
                'status': finding.get('status', 'Unknown'),
                'principal': self._format_principal(finding.get('principal', {})),
                'action': ', '.join(finding.get('action', [])) if finding.get('action') else 'Unknown',
                'condition': self._format_condition(finding.get('condition', {})),
                'analyzed_at': finding.get('analyzedAt', 'Unknown'),
                'created_at': finding.get('createdAt', 'Unknown'),
                'updated_at': finding.get('updatedAt', 'Unknown'),
                'is_public': finding.get('isPublic', False),
                'resource_owner_account': finding.get('resourceOwnerAccount', 'Unknown'),
                'error': finding.get('error', None),
                'details': self._build_finding_description(finding),
                'tags': self._get_resource_tags(resource_arn, resource_type)
            }
            
            return result
            
        except Exception as e:
            print(f"Error getting finding detail for {finding_id}: {e}")
            return None
    
    def _format_principal(self, principal):
        """Format principal information for display."""
        if not principal:
            return "Unknown"
        
        # Principal can be AWS account, federated user, service, etc.
        principal_parts = []
        
        if isinstance(principal, dict):
            for key, value in principal.items():
                if isinstance(value, list):
                    principal_parts.append(f"{key}: {', '.join(value)}")
                else:
                    principal_parts.append(f"{key}: {value}")
        else:
            principal_parts.append(str(principal))
        
        return '; '.join(principal_parts) if principal_parts else "Unknown"
    
    def _format_condition(self, condition):
        """Format condition information for display."""
        if not condition:
            return "None"
        
        condition_parts = []
        if isinstance(condition, dict):
            for key, value in condition.items():
                condition_parts.append(f"{key}={value}")
        else:
            condition_parts.append(str(condition))
        
        return '; '.join(condition_parts) if condition_parts else "None"
    
    def _build_finding_description(self, finding):
        """
        Build a human-readable description of the finding.
        
        Args:
            finding: Finding details from Access Analyzer
            
        Returns:
            String description
        """
        resource_type = finding.get('resourceType', 'Unknown')
        principal = finding.get('principal', {})
        actions = finding.get('action', [])
        is_public = finding.get('isPublic', False)
        
        # Build description
        description_parts = []
        
        if is_public:
            description_parts.append("PUBLIC ACCESS:")
        else:
            description_parts.append("EXTERNAL ACCESS:")
        
        description_parts.append(f"{resource_type} allows")
        
        # Format principal
        if isinstance(principal, dict):
            if 'AWS' in principal:
                aws_principals = principal['AWS']
                if isinstance(aws_principals, list):
                    if '*' in aws_principals:
                        description_parts.append("anyone (*)")
                    else:
                        description_parts.append(f"AWS accounts: {', '.join(aws_principals)}")
                elif aws_principals == '*':
                    description_parts.append("anyone (*)")
                else:
                    description_parts.append(f"AWS account: {aws_principals}")
            elif 'Federated' in principal:
                description_parts.append(f"federated users: {principal['Federated']}")
            elif 'Service' in principal:
                description_parts.append(f"AWS services: {principal['Service']}")
            else:
                description_parts.append(f"principal: {principal}")
        else:
            description_parts.append(f"principal: {principal}")
        
        # Add actions
        if actions:
            action_str = ', '.join(actions[:5])  # Limit to first 5 actions
            if len(actions) > 5:
                action_str += f" (and {len(actions) - 5} more)"
            description_parts.append(f"to perform: {action_str}")
        
        return ' '.join(description_parts)
    
    def _get_resource_tags(self, resource_arn, resource_type):
        """
        Get tags for the resource.
        
        Args:
            resource_arn: ARN of the resource
            resource_type: Type of resource
            
        Returns:
            Dictionary of tags
        """
        tags = {}
        
        try:
            # For IAM roles, we can get tags
            if resource_type == 'AWS::IAM::Role':
                iam_client = self.session.client('iam')
                role_name = resource_arn.split('/')[-1]
                
                response = iam_client.list_role_tags(RoleName=role_name)
                for tag in response.get('Tags', []):
                    tags[tag['Key']] = tag['Value']
                    
        except Exception as e:
            # Tags might not be accessible
            pass
        
        return tags
