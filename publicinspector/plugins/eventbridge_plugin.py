"""EventBridge event buses scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class EventBridgePlugin(AWSBasePlugin):
    """Scans EventBridge event buses for public accessibility."""
    
    def get_name(self):
        """Return plugin name."""
        return "EventBridge Bus Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "eventbridge"
    
    def scan(self):
        """
        Scan EventBridge event buses.
        
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
                print(f"Error scanning EventBridge in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan EventBridge event buses in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            events = self.session.client('events', region_name=region)
            
            # List all event buses
            paginator = events.get_paginator('list_event_buses')
            
            for page in paginator.paginate():
                event_buses = page.get('EventBuses', [])
                
                for bus in event_buses:
                    finding = self._check_event_bus(bus, region, events)
                    if finding:
                        findings.append(finding)
                        
        except Exception:
            pass
        
        return findings
    
    def _check_event_bus(self, bus, region, events_client):
        """
        Check an EventBridge event bus.
        
        Args:
            bus: Event bus details
            region: AWS region
            events_client: EventBridge client
            
        Returns:
            Finding dictionary or None
        """
        bus_name = bus.get('Name', 'unknown')
        bus_arn = bus.get('Arn', 'unknown')
        
        # Skip default event bus (always present)
        if bus_name == 'default':
            return None
        
        # Get event bus policy
        try:
            policy_response = events_client.describe_event_bus(Name=bus_name)
            policy = policy_response.get('Policy', '')
            
            # Check if policy allows public access
            if policy and '*' in policy:
                # Get tags
                tags = {}
                try:
                    tag_response = events_client.list_tags_for_resource(ResourceARN=bus_arn)
                    for tag in tag_response.get('Tags', []):
                        tags[tag['Key']] = tag['Value']
                except Exception:
                    pass
                
                finding = {
                    'resource_type': 'eventbridge_bus',
                    'resource_id': bus_arn,
                    'resource_name': bus_name,
                    'public_access': 'EventBridge event bus policy may allow public access',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': 'medium',
                    'details': {
                        'bus_name': bus_name,
                        'bus_arn': bus_arn,
                        'tags': tags
                    }
                }
                
                return finding
                
        except Exception:
            pass
        
        return None
