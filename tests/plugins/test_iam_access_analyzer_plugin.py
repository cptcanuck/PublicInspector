"""Tests for IAM Access Analyzer plugin."""

import pytest
from unittest.mock import MagicMock, patch
from publicinspector.plugins.iam_access_analyzer_plugin import IAMAccessAnalyzerPlugin


def test_plugin_initialization():
    """Test plugin initialization."""
    plugin = IAMAccessAnalyzerPlugin(None, None, None)
    assert plugin.get_name() == "IAM Access Analyzer Scanner"
    assert plugin.get_service_name() == "iam_access_analyzer"


def test_scan_no_analyzers(mock_session):
    """Test scanning when no analyzers are configured."""
    plugin = IAMAccessAnalyzerPlugin(mock_session, '123456789012', 'us-east-1')
    
    # Mock client with no analyzers
    mock_client = MagicMock()
    mock_client.list_analyzers.return_value = {'analyzers': []}
    mock_session.client.return_value = mock_client
    
    findings = plugin.scan()
    assert findings == []


def test_scan_with_active_analyzer(mock_session):
    """Test scanning with an active analyzer."""
    # Mock analyzer client
    mock_client = MagicMock()
    
    # Mock list_analyzers
    mock_client.list_analyzers.return_value = {
        'analyzers': [{
            'arn': 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'name': 'test-analyzer',
            'status': 'ACTIVE'
        }]
    }
    
    # Mock paginator for findings
    mock_paginator = MagicMock()
    mock_page_iterator = [{
        'findings': [{
            'id': 'finding-123',
            'resourceType': 'AWS::IAM::Role',
            'resource': 'arn:aws:iam::123456789012:role/test-role',
            'status': 'ACTIVE'
        }]
    }]
    mock_paginator.paginate.return_value = mock_page_iterator
    mock_client.get_paginator.return_value = mock_paginator
    
    # Mock get_finding
    mock_client.get_finding.return_value = {
        'finding': {
            'id': 'finding-123',
            'resourceType': 'AWS::IAM::Role',
            'resource': 'arn:aws:iam::123456789012:role/test-role',
            'status': 'ACTIVE',
            'principal': {'AWS': ['*']},
            'action': ['sts:AssumeRole'],
            'condition': {},
            'isPublic': True,
            'analyzedAt': '2024-01-01T00:00:00Z',
            'createdAt': '2024-01-01T00:00:00Z',
            'updatedAt': '2024-01-01T00:00:00Z',
            'resourceOwnerAccount': '123456789012'
        }
    }
    
    # Mock IAM client for tags
    mock_iam = MagicMock()
    mock_iam.list_role_tags.return_value = {'Tags': []}
    
    # Update session to return the right clients
    def client_factory(service, **kwargs):
        if service == 'accessanalyzer':
            return mock_client
        elif service == 'iam':
            return mock_iam
        elif service == 'sts':
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
            return mock_sts
        return MagicMock()
    
    mock_session.client = client_factory
    
    plugin = IAMAccessAnalyzerPlugin(mock_session, '123456789012', 'us-east-1')
    findings = plugin.scan()
    
    assert len(findings) == 1
    assert findings[0]['resource_type'] == 'iam_aws::iam::role'
    assert findings[0]['is_public'] is True
    assert findings[0]['principal'] == 'AWS: *'
    assert 'PUBLIC ACCESS' in findings[0]['details']


def test_scan_with_inactive_analyzer(mock_session):
    """Test scanning with an inactive analyzer."""
    plugin = IAMAccessAnalyzerPlugin(mock_session, '123456789012', 'us-east-1')
    
    # Mock client with inactive analyzer
    mock_client = MagicMock()
    mock_client.list_analyzers.return_value = {
        'analyzers': [{
            'arn': 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'name': 'test-analyzer',
            'status': 'INACTIVE'
        }]
    }
    
    mock_session.client.return_value = mock_client
    
    findings = plugin.scan()
    assert findings == []


def test_format_principal():
    """Test principal formatting."""
    plugin = IAMAccessAnalyzerPlugin(None, None, None)
    
    # Test AWS principal
    principal = {'AWS': ['*']}
    result = plugin._format_principal(principal)
    assert result == 'AWS: *'
    
    # Test multiple AWS principals
    principal = {'AWS': ['arn:aws:iam::111111111111:root', 'arn:aws:iam::222222222222:root']}
    result = plugin._format_principal(principal)
    assert 'AWS:' in result
    assert '111111111111' in result
    
    # Test federated principal
    principal = {'Federated': 'arn:aws:iam::123456789012:saml-provider/ExampleProvider'}
    result = plugin._format_principal(principal)
    assert 'Federated:' in result
    
    # Test service principal
    principal = {'Service': 'lambda.amazonaws.com'}
    result = plugin._format_principal(principal)
    assert 'Service:' in result


def test_format_condition():
    """Test condition formatting."""
    plugin = IAMAccessAnalyzerPlugin(None, None, None)
    
    # Test no condition
    result = plugin._format_condition({})
    assert result == 'None'
    
    # Test with condition
    condition = {'StringEquals': 'value'}
    result = plugin._format_condition(condition)
    assert 'StringEquals' in result


def test_build_finding_description():
    """Test finding description building."""
    plugin = IAMAccessAnalyzerPlugin(None, None, None)
    
    # Test public access finding
    finding = {
        'resourceType': 'AWS::IAM::Role',
        'principal': {'AWS': ['*']},
        'action': ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity'],
        'isPublic': True
    }
    
    description = plugin._build_finding_description(finding)
    assert 'PUBLIC ACCESS' in description
    assert 'anyone (*)' in description
    assert 'sts:AssumeRole' in description
    
    # Test external access finding
    finding = {
        'resourceType': 'AWS::S3::Bucket',
        'principal': {'AWS': ['arn:aws:iam::111111111111:root']},
        'action': ['s3:GetObject'],
        'isPublic': False
    }
    
    description = plugin._build_finding_description(finding)
    assert 'EXTERNAL ACCESS' in description
    assert '111111111111' in description


def test_scan_access_denied(mock_session):
    """Test handling of AccessDeniedException."""
    plugin = IAMAccessAnalyzerPlugin(mock_session, '123456789012', 'us-east-1')
    
    # Mock client that raises AccessDeniedException
    mock_client = MagicMock()
    mock_client.list_analyzers.side_effect = Exception('AccessDeniedException')
    mock_session.client.return_value = mock_client
    
    # Should not raise exception, just return empty findings
    findings = plugin.scan()
    assert findings == []


def test_scan_resource_not_found(mock_session):
    """Test handling of ResourceNotFoundException."""
    plugin = IAMAccessAnalyzerPlugin(mock_session, '123456789012', 'us-east-1')
    
    # Mock client that raises ResourceNotFoundException
    mock_client = MagicMock()
    mock_client.list_analyzers.side_effect = mock_client.exceptions.ResourceNotFoundException({}, 'operation')
    mock_client.exceptions.ResourceNotFoundException = Exception
    mock_session.client.return_value = mock_client
    
    # Should not raise exception, just return empty findings
    findings = plugin.scan()
    assert findings == []
