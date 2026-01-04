"""Tests for output formatting."""

import pytest
import json
from publicinspector.output import OutputFormatter


class TestOutputFormatter:
    """Tests for OutputFormatter class."""
    
    def test_formatter_initialization(self):
        """Test formatter initialization."""
        formatter = OutputFormatter(format_type='json')
        assert formatter.format_type == 'json'
    
    def test_format_json(self):
        """Test JSON output formatting."""
        formatter = OutputFormatter(format_type='json')
        
        findings = [
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'resource_type': 's3_bucket',
                'resource_name': 'test-bucket',
                'resource_id': 'test-bucket',
                'severity': 'high',
                'public_access': 'Publicly accessible',
                'details': {'tags': {'Name': 'test'}}
            }
        ]
        
        output = formatter.format_findings(findings)
        
        # Should be valid JSON
        parsed = json.loads(output)
        assert len(parsed) == 1
        assert parsed[0]['resource_name'] == 'test-bucket'
    
    def test_format_csv(self):
        """Test CSV output formatting."""
        formatter = OutputFormatter(format_type='csv')
        
        findings = [
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'resource_type': 's3_bucket',
                'resource_name': 'test-bucket',
                'resource_id': 'test-bucket',
                'severity': 'high',
                'public_access': 'Publicly accessible',
                'details': {'tags': {'Name': 'test'}}
            }
        ]
        
        output = formatter.format_findings(findings)
        
        # Should contain CSV headers
        assert 'Account ID' in output
        assert 'Resource Type' in output
        assert 'test-bucket' in output
    
    def test_format_table(self):
        """Test table output formatting."""
        formatter = OutputFormatter(format_type='table')
        
        findings = [
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'resource_type': 's3_bucket',
                'resource_name': 'test-bucket',
                'resource_id': 'test-bucket',
                'severity': 'high',
                'public_access': 'Publicly accessible',
                'details': {'tags': {'Name': 'test'}}
            }
        ]
        
        output = formatter.format_findings(findings)
        
        # Should contain table elements
        assert 'Account' in output
        assert 'test-bucket' in output
    
    def test_empty_findings(self):
        """Test formatting with no findings."""
        formatter = OutputFormatter(format_type='table')
        
        output = formatter.format_findings([])
        
        assert 'No public resources found' in output
