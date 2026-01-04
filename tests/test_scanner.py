"""Tests for the scanner orchestrator."""

import pytest
from unittest.mock import MagicMock, patch
from publicinspector.scanner import Scanner


class TestScanner:
    """Tests for Scanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        with patch('publicinspector.scanner.Config'):
            scanner = Scanner(max_workers=5)
            assert scanner.max_workers == 5
            assert scanner.plugin_loader is not None
    
    def test_set_service_filter(self):
        """Test setting service filter."""
        with patch('publicinspector.scanner.Config'):
            scanner = Scanner()
            scanner.set_service_filter(['s3', 'cloudfront'])
            assert scanner.service_filter == ['s3', 'cloudfront']
    
    def test_set_region_filter(self):
        """Test setting region filter."""
        with patch('publicinspector.scanner.Config'):
            scanner = Scanner()
            scanner.set_region_filter(['us-east-1', 'us-west-2'])
            assert scanner.region_filter == ['us-east-1', 'us-west-2']
    
    def test_get_service_mapping(self):
        """Test getting service mapping."""
        with patch('publicinspector.scanner.Config'):
            scanner = Scanner()
            mapping = scanner.get_service_mapping()
            
            # Should return a dictionary
            assert isinstance(mapping, dict)
            
            # Should have service names as keys
            assert len(mapping) > 0
    
    @patch('publicinspector.scanner.Config')
    def test_filter_exceptions(self, mock_config):
        """Test filtering exceptions from findings."""
        # Setup mock config
        mock_config_instance = MagicMock()
        mock_config.return_value = mock_config_instance
        
        # No exception for first finding, exception for second
        mock_config_instance.is_exception.side_effect = [
            (False, None, False),
            (True, 'Approved', False)
        ]
        
        scanner = Scanner()
        
        findings = [
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'resource_id': 'bucket1',
                'resource_type': 's3_bucket'
            },
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'resource_id': 'bucket2',
                'resource_type': 's3_bucket'
            }
        ]
        
        filtered = scanner._filter_exceptions(findings)
        
        # Only first finding should remain (second is exception)
        assert len(filtered) == 1
        assert filtered[0]['resource_id'] == 'bucket1'
