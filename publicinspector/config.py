"""Configuration management for account metadata and exceptions."""

import json
import os
from datetime import datetime


class Config:
    """
    Manages configuration for account tags and resource exceptions.
    
    The configuration is stored in a JSON file that contains:
    - Account metadata (tags like production/non-production)
    - Resource exceptions (approved public resources)
    """
    
    def __init__(self, config_file='publicinspector-config.json'):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file
        self.config_data = self._load_config()
    
    def _load_config(self):
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
                return self._default_config()
        else:
            return self._default_config()
    
    def _default_config(self):
        """
        Create default configuration structure.
        
        Returns:
            Default configuration dictionary
        """
        return {
            'version': '1.0',
            'accounts': {},
            'exceptions': [],
            'region_lists': {
                'all_used': ['us-east-1', 'us-west-2', 'eu-west-1'],
                'us_only': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
                'eu_only': ['eu-west-1', 'eu-west-2', 'eu-central-1'],
                'common': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
            },
            'organizations': {
                'default': {
                    'name': 'Default Organization',
                    'profile': None,
                    'management_account_id': None,
                    'role_name': 'OrganizationAccountAccessRole',
                    'description': 'Default organization configuration'
                }
            },
            'default_organization': 'default'
        }
    
    def save_config(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    # Account metadata methods
    
    def set_account_tag(self, account_id, tag_name, tag_value):
        """
        Set a tag on an account.
        
        Args:
            account_id: AWS account ID
            tag_name: Tag name (e.g., 'environment', 'team')
            tag_value: Tag value (e.g., 'production', 'dev-team')
        """
        if account_id not in self.config_data['accounts']:
            self.config_data['accounts'][account_id] = {'tags': {}}
        
        if 'tags' not in self.config_data['accounts'][account_id]:
            self.config_data['accounts'][account_id]['tags'] = {}
        
        self.config_data['accounts'][account_id]['tags'][tag_name] = tag_value
    
    def get_account_tag(self, account_id, tag_name):
        """
        Get a tag value for an account.
        
        Args:
            account_id: AWS account ID
            tag_name: Tag name
            
        Returns:
            Tag value or None if not set
        """
        if account_id in self.config_data['accounts']:
            tags = self.config_data['accounts'][account_id].get('tags', {})
            return tags.get(tag_name)
        return None
    
    def get_account_tags(self, account_id):
        """
        Get all tags for an account.
        
        Args:
            account_id: AWS account ID
            
        Returns:
            Dictionary of tags or empty dict
        """
        if account_id in self.config_data['accounts']:
            return self.config_data['accounts'][account_id].get('tags', {})
        return {}
    
    def set_account_metadata(self, account_id, name=None, environment=None, tags=None):
        """
        Set metadata for an account (convenience method).
        
        Args:
            account_id: AWS account ID
            name: Account name (optional)
            environment: Environment type like 'production' or 'non-production' (optional)
            tags: Additional tags dictionary (optional)
        """
        if account_id not in self.config_data['accounts']:
            self.config_data['accounts'][account_id] = {'tags': {}}
        
        if name:
            self.config_data['accounts'][account_id]['name'] = name
        
        if environment:
            self.set_account_tag(account_id, 'environment', environment)
        
        if tags:
            for tag_name, tag_value in tags.items():
                self.set_account_tag(account_id, tag_name, tag_value)
    
    def is_production_account(self, account_id):
        """
        Check if an account is tagged as production.
        
        Args:
            account_id: AWS account ID
            
        Returns:
            True if production, False otherwise
        """
        env = self.get_account_tag(account_id, 'environment')
        if env:
            return env.lower() == 'production'
        return False
    
    # Exception methods
    
    def add_exception(self, account_id, region, resource_id, resource_type, 
                     reason, expiration_date=None, added_by=None):
        """
        Add a resource exception (approved public resource).
        
        Args:
            account_id: AWS account ID
            region: AWS region
            resource_id: Resource identifier (ARN or ID)
            resource_type: Type of resource (e.g., 's3_bucket')
            reason: Why this resource is approved for public access
            expiration_date: Optional expiration date (YYYY-MM-DD format)
            added_by: Who added this exception (optional)
        """
        exception = {
            'account_id': account_id,
            'region': region,
            'resource_id': resource_id,
            'resource_type': resource_type,
            'reason': reason,
            'added_date': datetime.now().strftime('%Y-%m-%d'),
            'expiration_date': expiration_date,
            'added_by': added_by
        }
        
        self.config_data['exceptions'].append(exception)
    
    def is_exception(self, account_id, region, resource_id):
        """
        Check if a resource is in the exceptions list.
        
        Args:
            account_id: AWS account ID
            region: AWS region
            resource_id: Resource identifier
            
        Returns:
            Tuple (is_exception, reason, is_expired)
        """
        for exception in self.config_data['exceptions']:
            if (exception['account_id'] == account_id and 
                exception['region'] == region and 
                exception['resource_id'] == resource_id):
                
                # Check if exception has expired
                is_expired = False
                if exception.get('expiration_date'):
                    try:
                        expiration = datetime.strptime(exception['expiration_date'], '%Y-%m-%d')
                        if datetime.now() > expiration:
                            is_expired = True
                    except Exception:
                        pass
                
                return True, exception.get('reason', 'No reason provided'), is_expired
        
        return False, None, False
    
    def remove_exception(self, account_id, region, resource_id):
        """
        Remove a resource exception.
        
        Args:
            account_id: AWS account ID
            region: AWS region
            resource_id: Resource identifier
            
        Returns:
            True if removed, False if not found
        """
        original_length = len(self.config_data['exceptions'])
        
        self.config_data['exceptions'] = [
            exc for exc in self.config_data['exceptions']
            if not (exc['account_id'] == account_id and 
                   exc['region'] == region and 
                   exc['resource_id'] == resource_id)
        ]
        
        return len(self.config_data['exceptions']) < original_length
    
    def get_all_exceptions(self):
        """
        Get all exceptions.
        
        Returns:
            List of exception dictionaries
        """
        return self.config_data['exceptions']
    
    def get_expired_exceptions(self):
        """
        Get all expired exceptions.
        
        Returns:
            List of expired exception dictionaries
        """
        expired = []
        now = datetime.now()
        
        for exception in self.config_data['exceptions']:
            if exception.get('expiration_date'):
                try:
                    expiration = datetime.strptime(exception['expiration_date'], '%Y-%m-%d')
                    if now > expiration:
                        expired.append(exception)
                except Exception:
                    pass
        
        return expired
    
    # Region list methods
    
    def get_region_list(self, list_name):
        """
        Get a named region list from configuration.
        
        Args:
            list_name: Name of the region list
            
        Returns:
            List of region names, or None if not found
        """
        region_lists = self.config_data.get('region_lists', {})
        return region_lists.get(list_name)
    
    def set_region_list(self, list_name, regions):
        """
        Set a named region list in configuration.
        
        Args:
            list_name: Name of the region list
            regions: List of region names
        """
        if 'region_lists' not in self.config_data:
            self.config_data['region_lists'] = {}
        
        self.config_data['region_lists'][list_name] = regions
    
    def get_all_region_lists(self):
        """
        Get all defined region lists.
        
        Returns:
            Dictionary of region lists
        """
        return self.config_data.get('region_lists', {})
    
    # Organization methods
    
    def add_organization(self, org_id, name, profile=None, management_account_id=None, 
                        role_name='OrganizationAccountAccessRole', description=''):
        """
        Add or update an organization configuration.
        
        Args:
            org_id: Unique identifier for this organization (e.g., 'prod-org', 'dev-org')
            name: Human-readable name for the organization
            profile: AWS profile to use for this organization (optional)
            management_account_id: Management account ID (optional)
            role_name: IAM role name to assume in member accounts
            description: Description of this organization
        """
        if 'organizations' not in self.config_data:
            self.config_data['organizations'] = {}
        
        self.config_data['organizations'][org_id] = {
            'name': name,
            'profile': profile,
            'management_account_id': management_account_id,
            'role_name': role_name,
            'description': description
        }
    
    def get_organization(self, org_id):
        """
        Get organization configuration by ID.
        
        Args:
            org_id: Organization identifier
            
        Returns:
            Organization configuration dict or None
        """
        orgs = self.config_data.get('organizations', {})
        return orgs.get(org_id)
    
    def get_all_organizations(self):
        """
        Get all organization configurations.
        
        Returns:
            Dictionary of organizations
        """
        return self.config_data.get('organizations', {})
    
    def set_default_organization(self, org_id):
        """
        Set the default organization to use.
        
        Args:
            org_id: Organization identifier
        """
        self.config_data['default_organization'] = org_id
    
    def get_default_organization(self):
        """
        Get the default organization ID.
        
        Returns:
            Organization ID string
        """
        return self.config_data.get('default_organization', 'default')
    
    def remove_organization(self, org_id):
        """
        Remove an organization configuration.
        
        Args:
            org_id: Organization identifier
            
        Returns:
            True if removed, False if not found
        """
        if 'organizations' in self.config_data:
            if org_id in self.config_data['organizations']:
                del self.config_data['organizations'][org_id]
                return True
        return False
