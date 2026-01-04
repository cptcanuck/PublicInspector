"""Tests for Security Group plugin."""

import pytest
from unittest.mock import MagicMock
from publicinspector.plugins.security_group_plugin import SecurityGroupPlugin
from tests.plugins import BasePluginTest


class TestSecurityGroupPlugin(BasePluginTest):
    """Tests for SecurityGroupPlugin class."""
    
    def test_plugin_initialization(self):
        """Test Security Group plugin initialization."""
        session = self.create_mock_session()
        plugin = SecurityGroupPlugin(session, account_id='123456789012', region='us-east-1')
        
        assert plugin.get_name() == "Security Group Scanner"
        assert plugin.get_service_name() == "ec2_security_groups"
        assert plugin.get_provider() == "aws"
    
    def test_determine_severity_all_ports(self):
        """Test severity determination for all ports open."""
        session = self.create_mock_session()
        plugin = SecurityGroupPlugin(session, account_id='123456789012', region='us-east-1')
        
        severity = plugin._determine_severity('all', 'all', 'all')
        assert severity == 'critical'
    
    def test_determine_severity_ssh(self):
        """Test severity determination for SSH port."""
        session = self.create_mock_session()
        plugin = SecurityGroupPlugin(session, account_id='123456789012', region='us-east-1')
        
        severity = plugin._determine_severity(22, 22, 'tcp')
        assert severity == 'high'
    
    def test_determine_severity_http(self):
        """Test severity determination for HTTP port."""
        session = self.create_mock_session()
        plugin = SecurityGroupPlugin(session, account_id='123456789012', region='us-east-1')
        
        severity = plugin._determine_severity(80, 80, 'tcp')
        assert severity == 'low'
    
    def test_check_security_group_with_public_access(self):
        """Test checking a security group with public access."""
        session = self.create_mock_session()
        plugin = SecurityGroupPlugin(session, account_id='123456789012', region='us-east-1')
        
        sg = {
            'GroupId': 'sg-12345',
            'GroupName': 'test-sg',
            'Tags': [],
            'IpPermissions': [
                {
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                    'Ipv6Ranges': []
                }
            ]
        }
        
        findings = plugin._check_security_group(sg, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        
        self.assert_finding_structure(finding)
        assert finding['resource_type'] == 'security_group'
        assert finding['severity'] == 'high'  # SSH is high severity
