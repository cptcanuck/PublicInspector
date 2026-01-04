"""Plugin loader and manager."""

import os
import importlib
import inspect


class PluginLoader:
    """
    Loads and manages scanner plugins.
    
    This class discovers plugins in the plugins directory and
    provides methods to load and use them.
    """
    
    def __init__(self):
        """Initialize the plugin loader."""
        self.plugins = []
        self.plugin_classes = []
    
    def discover_plugins(self, plugin_dir=None):
        """
        Discover all available plugins.
        
        Args:
            plugin_dir: Directory to search for plugins (optional)
        """
        if plugin_dir is None:
            # Default to plugins directory next to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            plugin_dir = os.path.join(current_dir, 'plugins')
        
        if not os.path.exists(plugin_dir):
            return
        
        # Look for all Python files in plugins directory
        for filename in os.listdir(plugin_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                module_name = filename[:-3]  # Remove .py extension
                self._load_plugin_module(module_name)
    
    def _load_plugin_module(self, module_name):
        """
        Load a specific plugin module.
        
        Args:
            module_name: Name of the module to load
        """
        try:
            # Import the module
            module = importlib.import_module(f'publicinspector.plugins.{module_name}')
            
            # Find all classes in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's a plugin class (not the base class)
                if hasattr(obj, 'scan') and name != 'BasePlugin' and name != 'AWSBasePlugin':
                    self.plugin_classes.append(obj)
        except Exception as e:
            print(f"Warning: Could not load plugin {module_name}: {e}")
    
    def load_plugins(self, session, account_id=None, region=None):
        """
        Load all discovered plugins with the given session.
        
        Args:
            session: Cloud provider session
            account_id: Account ID
            region: Region
            
        Returns:
            List of plugin instances
        """
        plugins = []
        
        for plugin_class in self.plugin_classes:
            try:
                plugin = plugin_class(session, account_id, region)
                if plugin.is_enabled():
                    plugins.append(plugin)
            except Exception as e:
                print(f"Warning: Could not instantiate plugin {plugin_class.__name__}: {e}")
        
        return plugins
    
    def get_plugin_names(self):
        """
        Get names of all discovered plugins.
        
        Returns:
            List of plugin names
        """
        names = []
        for plugin_class in self.plugin_classes:
            # Get the class name as a fallback
            names.append(plugin_class.__name__)
        
        return names
