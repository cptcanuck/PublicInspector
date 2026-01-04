"""Tests for the configuration management module."""

import pytest
import json
import os
import tempfile
from datetime import datetime, timedelta
from publicinspector.config import Config


class TestConfig:
    """Tests for Config class."""
    
    def test_config_initialization(self):
        """Test that config initializes with default values."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            assert config.config_data['version'] == '1.0'
            assert 'accounts' in config.config_data
            assert 'exceptions' in config.config_data
            assert 'region_lists' in config.config_data
            assert 'organizations' in config.config_data
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_set_and_get_account_tag(self):
        """Test setting and getting account tags."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            config.set_account_tag('123456789012', 'environment', 'production')
            
            result = config.get_account_tag('123456789012', 'environment')
            assert result == 'production'
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_is_production_account(self):
        """Test checking if account is production."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            config.set_account_tag('123456789012', 'environment', 'production')
            config.set_account_tag('987654321098', 'environment', 'non-production')
            
            assert config.is_production_account('123456789012') == True
            assert config.is_production_account('987654321098') == False
            assert config.is_production_account('111111111111') == False
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_add_exception(self):
        """Test adding an exception."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            config.add_exception(
                account_id='123456789012',
                region='us-east-1',
                resource_id='test-bucket',
                resource_type='s3_bucket',
                reason='Public website',
                added_by='test-user'
            )
            
            exceptions = config.get_all_exceptions()
            assert len(exceptions) == 1
            assert exceptions[0]['resource_id'] == 'test-bucket'
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_is_exception(self):
        """Test checking if resource is an exception."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            config.add_exception(
                account_id='123456789012',
                region='us-east-1',
                resource_id='test-bucket',
                resource_type='s3_bucket',
                reason='Public website'
            )
            
            is_exception, reason, is_expired = config.is_exception(
                '123456789012', 'us-east-1', 'test-bucket'
            )
            
            assert is_exception == True
            assert reason == 'Public website'
            assert is_expired == False
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_expired_exception(self):
        """Test detecting expired exceptions."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            
            # Add exception with past expiration date
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            config.add_exception(
                account_id='123456789012',
                region='us-east-1',
                resource_id='expired-bucket',
                resource_type='s3_bucket',
                reason='Temporary exception',
                expiration_date=yesterday
            )
            
            is_exception, reason, is_expired = config.is_exception(
                '123456789012', 'us-east-1', 'expired-bucket'
            )
            
            assert is_exception == True
            assert is_expired == True
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_region_lists(self):
        """Test region list management."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            
            # Test default region lists exist
            all_used = config.get_region_list('all_used')
            assert all_used is not None
            assert 'us-east-1' in all_used
            
            # Test adding custom region list
            config.set_region_list('my_regions', ['us-west-1', 'us-west-2'])
            my_regions = config.get_region_list('my_regions')
            assert my_regions == ['us-west-1', 'us-west-2']
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_organization_management(self):
        """Test organization configuration management."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            
            # Add organization
            config.add_organization(
                org_id='test-org',
                name='Test Organization',
                profile='test-profile',
                role_name='TestRole'
            )
            
            # Get organization
            org = config.get_organization('test-org')
            assert org is not None
            assert org['name'] == 'Test Organization'
            assert org['profile'] == 'test-profile'
            
            # Set as default
            config.set_default_organization('test-org')
            default = config.get_default_organization()
            assert default == 'test-org'
            
            # Remove organization
            result = config.remove_organization('test-org')
            assert result == True
            assert config.get_organization('test-org') is None
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def test_organization_specific_region_lists(self):
        """Test organization-specific region lists."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config = Config(config_file)
            
            # Set global region list
            config.set_region_list('all_used', ['us-east-1', 'us-west-2'])
            
            # Add organization with custom region lists
            config.add_organization(
                org_id='org1',
                name='Organization 1',
                profile='org1-profile',
                region_lists={
                    'all_used': ['ca-central-1', 'us-east-1'],
                    'ca_only': ['ca-central-1']
                }
            )
            
            # Add organization without region lists
            config.add_organization(
                org_id='org2',
                name='Organization 2',
                profile='org2-profile'
            )
            
            # Test org-specific region list takes precedence
            org1_regions = config.get_region_list('all_used', org_id='org1')
            assert org1_regions == ['ca-central-1', 'us-east-1']
            
            # Test org-specific unique region list
            ca_only = config.get_region_list('ca_only', org_id='org1')
            assert ca_only == ['ca-central-1']
            
            # Test fallback to global when org doesn't have region list
            org2_regions = config.get_region_list('all_used', org_id='org2')
            assert org2_regions == ['us-east-1', 'us-west-2']
            
            # Test non-existent region list returns None
            nonexistent = config.get_region_list('nonexistent', org_id='org1')
            assert nonexistent is None
            
            # Test without org_id uses global
            global_regions = config.get_region_list('all_used')
            assert global_regions == ['us-east-1', 'us-west-2']
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
