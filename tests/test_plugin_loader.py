"""Tests for plugin loader."""

import pytest
from unittest.mock import MagicMock, patch
from publicinspector.plugin_loader import PluginLoader


class TestPluginLoader:
    """Tests for PluginLoader class."""
    
    def test_plugin_loader_initialization(self):
        """Test that plugin loader initializes correctly."""
        loader = PluginLoader()
        assert loader.plugins == []
        assert loader.plugin_classes == []
    
    def test_discover_plugins(self):
        """Test that plugins are discovered."""
        loader = PluginLoader()
        loader.discover_plugins()
        
        # Should have discovered multiple plugins
        assert len(loader.plugin_classes) > 0
        
        # Check for specific plugins
        plugin_names = [cls.__name__ for cls in loader.plugin_classes]
        assert 'S3Plugin' in plugin_names
        assert 'CloudFrontPlugin' in plugin_names
        assert 'SecurityGroupPlugin' in plugin_names
    
    def test_load_plugins_with_session(self, mock_boto3_session, sample_account_id):
        """Test loading plugins with a session."""
        loader = PluginLoader()
        loader.discover_plugins()
        
        plugins = loader.load_plugins(
            mock_boto3_session,
            account_id=sample_account_id,
            region='us-east-1'
        )
        
        # Should have loaded plugins
        assert len(plugins) > 0
        
        # Each plugin should have the session
        for plugin in plugins:
            assert plugin.session == mock_boto3_session
            assert plugin.account_id == sample_account_id
    
    def test_get_plugin_names(self):
        """Test getting plugin names."""
        loader = PluginLoader()
        loader.discover_plugins()
        
        names = loader.get_plugin_names()
        
        # Should return plugin class names
        assert len(names) > 0
        assert 'S3Plugin' in names or any('S3' in name for name in names)
