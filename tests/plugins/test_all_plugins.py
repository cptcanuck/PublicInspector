"""Tests for all plugins - generic functionality tests."""

import pytest
from unittest.mock import MagicMock
from tests.plugins import BasePluginTest

# Import all plugins
from publicinspector.plugins.s3_plugin import S3Plugin
from publicinspector.plugins.cloudfront_plugin import CloudFrontPlugin
from publicinspector.plugins.security_group_plugin import SecurityGroupPlugin
from publicinspector.plugins.load_balancer_plugin import LoadBalancerPlugin
from publicinspector.plugins.elb_plugin import ELBPlugin
from publicinspector.plugins.apigateway_plugin import APIGatewayPlugin
from publicinspector.plugins.route53_plugin import Route53Plugin
from publicinspector.plugins.elastic_ip_plugin import ElasticIPPlugin
from publicinspector.plugins.ec2_instance_plugin import EC2InstancePlugin
from publicinspector.plugins.lambda_plugin import LambdaPlugin
from publicinspector.plugins.apprunner_plugin import AppRunnerPlugin
from publicinspector.plugins.elasticbeanstalk_plugin import ElasticBeanstalkPlugin
from publicinspector.plugins.efs_plugin import EFSPlugin
from publicinspector.plugins.rds_plugin import RDSPlugin
from publicinspector.plugins.dynamodb_plugin import DynamoDBPlugin
from publicinspector.plugins.opensearch_plugin import OpenSearchPlugin
from publicinspector.plugins.redshift_plugin import RedshiftPlugin
from publicinspector.plugins.ebs_snapshot_plugin import EBSSnapshotPlugin
from publicinspector.plugins.ami_plugin import AMIPlugin
from publicinspector.plugins.ecr_plugin import ECRPlugin
from publicinspector.plugins.sns_plugin import SNSPlugin
from publicinspector.plugins.sqs_plugin import SQSPlugin
from publicinspector.plugins.eventbridge_plugin import EventBridgePlugin


# List of all plugin classes
ALL_PLUGINS = [
    S3Plugin,
    CloudFrontPlugin,
    SecurityGroupPlugin,
    LoadBalancerPlugin,
    ELBPlugin,
    APIGatewayPlugin,
    Route53Plugin,
    ElasticIPPlugin,
    EC2InstancePlugin,
    LambdaPlugin,
    AppRunnerPlugin,
    ElasticBeanstalkPlugin,
    EFSPlugin,
    RDSPlugin,
    DynamoDBPlugin,
    OpenSearchPlugin,
    RedshiftPlugin,
    EBSSnapshotPlugin,
    AMIPlugin,
    ECRPlugin,
    SNSPlugin,
    SQSPlugin,
    EventBridgePlugin,
]


class TestAllPlugins(BasePluginTest):
    """Generic tests that should pass for all plugins."""
    
    @pytest.mark.parametrize("plugin_class", ALL_PLUGINS)
    def test_plugin_has_required_methods(self, plugin_class):
        """Test that each plugin has required methods."""
        session = self.create_mock_session()
        plugin = plugin_class(session, account_id='123456789012', region='us-east-1')
        
        # Check required methods exist
        assert hasattr(plugin, 'get_name')
        assert hasattr(plugin, 'get_service_name')
        assert hasattr(plugin, 'get_provider')
        assert hasattr(plugin, 'scan')
        
        # Check methods are callable
        assert callable(plugin.get_name)
        assert callable(plugin.get_service_name)
        assert callable(plugin.get_provider)
        assert callable(plugin.scan)
    
    @pytest.mark.parametrize("plugin_class", ALL_PLUGINS)
    def test_plugin_returns_correct_types(self, plugin_class):
        """Test that plugin methods return correct types."""
        session = self.create_mock_session()
        plugin = plugin_class(session, account_id='123456789012', region='us-east-1')
        
        # get_name should return string
        name = plugin.get_name()
        assert isinstance(name, str)
        assert len(name) > 0
        
        # get_service_name should return string
        service = plugin.get_service_name()
        assert isinstance(service, str)
        assert len(service) > 0
        
        # get_provider should return string
        provider = plugin.get_provider()
        assert isinstance(provider, str)
        assert provider == 'aws'
    
    @pytest.mark.parametrize("plugin_class", ALL_PLUGINS)
    def test_plugin_scan_returns_list(self, plugin_class):
        """Test that scan() returns a list."""
        session = self.create_mock_session()
        
        # Mock all client calls to return empty responses
        mock_client = MagicMock()
        mock_client.get_paginator.return_value.paginate.return_value = []
        session.client.return_value = mock_client
        
        plugin = plugin_class(session, account_id='123456789012', region='us-east-1')
        
        result = plugin.scan()
        
        # Should always return a list (even if empty)
        assert isinstance(result, list)
    
    @pytest.mark.parametrize("plugin_class", ALL_PLUGINS)
    def test_plugin_handles_none_session(self, plugin_class):
        """Test that plugins can be instantiated with None session for discovery."""
        # Should not raise exception
        plugin = plugin_class(None, None, None)
        
        # Should still be able to get metadata
        assert isinstance(plugin.get_name(), str)
        assert isinstance(plugin.get_service_name(), str)
        assert isinstance(plugin.get_provider(), str)
