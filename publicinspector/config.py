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
            'exceptions': []
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
