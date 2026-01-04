"""Base plugin interface for cloud resource scanners.

This module provides the base class for the plugin system.
It's designed to support multiple cloud providers (AWS, Azure, GCP, etc.)
"""


class BasePlugin:
    """
    Base class for all cloud resource scanner plugins.
    
    Each plugin scans a specific service (e.g., S3, CloudFront, etc.)
    and finds publicly exposed resources.
    """

    def __init__(self, session, account_id=None, region=None):
        """
        Initialize the plugin.
        
        Args:
            session: Cloud provider session (boto3.Session for AWS)
            account_id: Account identifier (optional)
            region: Region/location (optional)
        """
        self.session = session
        self.account_id = account_id
        self.region = region

    def get_name(self):
        """Return the human-readable name of this plugin."""
        return "Base Plugin"

    def get_service_name(self):
        """Return the service name (e.g., 's3', 'cloudfront')."""
        return "base"

    def get_provider(self):
        """Return the cloud provider ('aws', 'azure', 'gcp')."""
        return "unknown"

    def scan(self):
        """
        Scan for publicly exposed resources.
        
        Returns:
            List of dictionaries with resource information:
            - resource_type: Type (e.g., 's3_bucket')
            - resource_id: Unique identifier
            - resource_name: Human-readable name
            - public_access: How it's publicly accessible
            - region: Cloud region
            - account_id: Account ID
            - severity: 'critical', 'high', 'medium', 'low', 'info'
            - details: Extra information
        """
        return []

    def is_enabled(self):
        """Check if this plugin should run. Can be overridden."""
        return True
