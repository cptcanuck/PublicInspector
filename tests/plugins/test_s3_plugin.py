"""Tests for S3 plugin."""

import pytest
from unittest.mock import MagicMock, patch
from publicinspector.plugins.s3_plugin import S3Plugin
from tests.plugins import BasePluginTest


class TestS3Plugin(BasePluginTest):
    """Tests for S3Plugin class."""
    
    def test_plugin_initialization(self):
        """Test S3 plugin initialization."""
        session = self.create_mock_session()
        plugin = S3Plugin(session, account_id='123456789012', region='us-east-1')
        
        assert plugin.get_name() == "S3 Bucket Scanner"
        assert plugin.get_service_name() == "s3"
        assert plugin.get_provider() == "aws"
    
    def test_scan_with_no_buckets(self):
        """Test scanning when no buckets exist."""
        session = self.create_mock_session()
        plugin = S3Plugin(session, account_id='123456789012', region='us-east-1')
        
        # Mock S3 client
        mock_s3 = self.create_mock_client()
        mock_s3.list_buckets.return_value = {'Buckets': []}
        session.client.return_value = mock_s3
        
        findings = plugin.scan()
        
        assert isinstance(findings, list)
        assert len(findings) == 0
    
    def test_scan_with_public_bucket(self):
        """Test scanning with a public bucket."""
        session = self.create_mock_session()
        plugin = S3Plugin(session, account_id='123456789012', region='us-east-1')
        
        # Mock S3 client
        mock_s3 = self.create_mock_client()
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-public-bucket'}
            ]
        }
        
        # Mock public access block - not configured (indicates potential public access)
        from botocore.exceptions import ClientError
        mock_s3.exceptions.NoSuchPublicAccessBlockConfiguration = type('NoSuchPublicAccessBlockConfiguration', (Exception,), {})
        mock_s3.get_public_access_block.side_effect = mock_s3.exceptions.NoSuchPublicAccessBlockConfiguration("Not configured")
        
        # Mock bucket location
        mock_s3.get_bucket_location.return_value = {'LocationConstraint': 'us-east-1'}
        
        # Mock ACL - no public grants
        mock_s3.get_bucket_acl.return_value = {'Grants': []}
        
        # Mock policy - no policy
        mock_s3.exceptions.NoSuchBucketPolicy = type('NoSuchBucketPolicy', (Exception,), {})
        mock_s3.get_bucket_policy.side_effect = mock_s3.exceptions.NoSuchBucketPolicy("No policy")
        
        session.client.return_value = mock_s3
        
        findings = plugin.scan()
        
        assert isinstance(findings, list)
        # Should find at least one issue (no public access block configured)
        assert len(findings) >= 1
        
        if len(findings) > 0:
            finding = findings[0]
            self.assert_finding_structure(finding)
            assert finding['resource_type'] == 's3_bucket'
            assert finding['resource_name'] == 'test-public-bucket'
    
    def test_scan_handles_errors_gracefully(self):
        """Test that scan handles API errors gracefully."""
        session = self.create_mock_session()
        plugin = S3Plugin(session, account_id='123456789012', region='us-east-1')
        
        # Mock S3 client that raises an error
        mock_s3 = self.create_mock_client()
        mock_s3.list_buckets.side_effect = Exception("Access Denied")
        session.client.return_value = mock_s3
        
        # Should not raise exception
        findings = plugin.scan()
        assert isinstance(findings, list)
