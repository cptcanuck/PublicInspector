"""Test configuration and fixtures."""

import pytest
from unittest.mock import MagicMock
import boto3


@pytest.fixture
def mock_session():
    """Create a mock boto3 session for testing plugins."""
    session = MagicMock()
    session.region_name = 'us-east-1'
    
    # Mock STS client for account ID
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        'Account': '123456789012'
    }
    
    def client_factory(service, **kwargs):
        if service == 'sts':
            return mock_sts
        return MagicMock()
    
    session.client = client_factory
    return session


@pytest.fixture
def mock_boto3_session():
    """Create a mock boto3 session for testing."""
    session = MagicMock()
    session.region_name = 'us-east-1'
    return session


@pytest.fixture
def mock_sts_client():
    """Create a mock STS client."""
    client = MagicMock()
    client.get_caller_identity.return_value = {
        'Account': '123456789012',
        'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
        'Arn': 'arn:aws:iam::123456789012:user/test'
    }
    return client


@pytest.fixture
def sample_account_id():
    """Sample AWS account ID for testing."""
    return '123456789012'


@pytest.fixture
def sample_region():
    """Sample AWS region for testing."""
    return 'us-east-1'


@pytest.fixture
def sample_tags():
    """Sample resource tags for testing."""
    return {
        'Name': 'test-resource',
        'Environment': 'production',
        'Owner': 'test-team'
    }
