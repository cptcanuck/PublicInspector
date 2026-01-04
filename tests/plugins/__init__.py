"""Base test class for plugin tests."""

import pytest
from unittest.mock import MagicMock


class BasePluginTest:
    """Base class for plugin tests with common utilities."""
    
    def create_mock_session(self, region='us-east-1'):
        """Create a mock boto3 session."""
        session = MagicMock()
        session.region_name = region
        return session
    
    def create_mock_client(self):
        """Create a mock AWS client."""
        return MagicMock()
    
    def assert_finding_structure(self, finding):
        """Assert that a finding has the required structure."""
        required_keys = [
            'resource_type',
            'resource_id',
            'resource_name',
            'public_access',
            'region',
            'account_id',
            'severity',
            'details'
        ]
        
        for key in required_keys:
            assert key in finding, f"Finding missing required key: {key}"
        
        # Verify severity is valid
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        assert finding['severity'] in valid_severities, f"Invalid severity: {finding['severity']}"
        
        # Verify details contains tags
        assert 'tags' in finding['details'], "Finding details missing tags"
        assert isinstance(finding['details']['tags'], dict), "Tags should be a dictionary"
    
    def assert_no_exceptions_raised(self, plugin, method_name='scan'):
        """Assert that calling a plugin method doesn't raise exceptions."""
        try:
            method = getattr(plugin, method_name)
            method()
        except Exception as e:
            pytest.fail(f"Plugin {plugin.__class__.__name__}.{method_name}() raised {type(e).__name__}: {e}")
