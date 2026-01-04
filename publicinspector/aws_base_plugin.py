"""AWS-specific base plugin class."""

from publicinspector.base_plugin import BasePlugin


class AWSBasePlugin(BasePlugin):
    """
    Base class for AWS service scanner plugins.
    
    This class extends BasePlugin with AWS-specific functionality.
    """

    def __init__(self, session, account_id=None, region=None):
        """
        Initialize AWS plugin.
        
        Args:
            session: boto3.Session object
            account_id: AWS account ID
            region: AWS region
        """
        super().__init__(session, account_id, region)
        
        # If account_id not provided, try to get it
        if not self.account_id:
            try:
                sts = self.session.client('sts')
                self.account_id = sts.get_caller_identity()['Account']
            except Exception:
                self.account_id = 'unknown'
        
        # If region not provided, use session region
        if not self.region:
            self.region = self.session.region_name or 'us-east-1'

    def get_provider(self):
        """Return 'aws' as the provider."""
        return "aws"

    def get_all_regions(self):
        """Get list of all available AWS regions."""
        ec2 = self.session.client('ec2', region_name='us-east-1')
        try:
            regions = ec2.describe_regions()['Regions']
            region_list = []
            for region in regions:
                region_list.append(region['RegionName'])
            return region_list
        except Exception:
            # Return common regions if API call fails
            return [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-central-1',
                'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
            ]
