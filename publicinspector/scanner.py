"""Scanner orchestrator with parallel execution support."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from publicinspector.plugin_loader import PluginLoader
from publicinspector.config import Config


class Scanner:
    """
    Orchestrates scanning across multiple accounts and regions.
    
    This class handles:
    - Loading plugins
    - Running scans across accounts (with parallelization)
    - Running scans across regions (with parallelization)
    - Collecting and aggregating results
    - Filtering out approved exceptions
    """
    
    def __init__(self, max_workers=10, config_file='publicinspector-config.json'):
        """
        Initialize the scanner.
        
        Args:
            max_workers: Maximum number of parallel workers (default: 10)
            config_file: Path to configuration file (default: publicinspector-config.json)
        """
        self.max_workers = max_workers
        self.plugin_loader = PluginLoader()
        self.plugin_loader.discover_plugins()
        self.config = Config(config_file)
    
    def scan_account(self, session, account_id=None):
        """
        Scan a single AWS account.
        
        Args:
            session: boto3.Session for the account
            account_id: AWS account ID
            
        Returns:
            List of all findings (after filtering exceptions)
        """
        all_findings = []
        
        # Get account ID if not provided
        if not account_id:
            try:
                sts = session.client('sts')
                account_id = sts.get_caller_identity()['Account']
            except Exception:
                account_id = 'unknown'
        
        # Get account metadata
        account_tags = self.config.get_account_tags(account_id)
        environment = account_tags.get('environment', 'unknown')
        
        print(f"Scanning account {account_id} (environment: {environment})...")
        
        # Load plugins for this session
        plugins = self.plugin_loader.load_plugins(session, account_id)
        
        print(f"Found {len(plugins)} plugins to run")
        
        # Run each plugin in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all plugin scans
            future_to_plugin = {}
            for plugin in plugins:
                future = executor.submit(self._run_plugin, plugin)
                future_to_plugin[future] = plugin
            
            # Collect results as they complete
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    print(f"  {plugin.get_name()}: Found {len(findings)} potential issues")
                except Exception as e:
                    print(f"  {plugin.get_name()}: Error - {e}")
        
        # Filter out approved exceptions
        filtered_findings = self._filter_exceptions(all_findings)
        
        excluded_count = len(all_findings) - len(filtered_findings)
        if excluded_count > 0:
            print(f"  Excluded {excluded_count} approved exceptions")
        
        return filtered_findings
    
    def scan_accounts(self, sessions_with_ids):
        """
        Scan multiple AWS accounts in parallel.
        
        Args:
            sessions_with_ids: List of tuples (session, account_id)
            
        Returns:
            List of all findings across all accounts
        """
        all_findings = []
        
        print(f"Scanning {len(sessions_with_ids)} accounts...")
        
        # Run account scans in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all account scans
            future_to_account = {}
            for session, account_id in sessions_with_ids:
                future = executor.submit(self.scan_account, session, account_id)
                future_to_account[future] = account_id
            
            # Collect results as they complete
            for future in as_completed(future_to_account):
                account_id = future_to_account[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"Error scanning account {account_id}: {e}")
        
        return all_findings
    
    def _run_plugin(self, plugin):
        """
        Run a single plugin scan.
        
        Args:
            plugin: Plugin instance
            
        Returns:
            List of findings
        """
        try:
            return plugin.scan()
        except Exception as e:
            print(f"Error in {plugin.get_name()}: {e}")
            return []
    
    def _filter_exceptions(self, findings):
        """
        Filter out findings that are approved exceptions.
        
        Args:
            findings: List of findings
            
        Returns:
            List of findings with exceptions removed
        """
        filtered = []
        
        for finding in findings:
            account_id = finding.get('account_id', 'unknown')
            region = finding.get('region', 'unknown')
            resource_id = finding.get('resource_id', 'unknown')
            
            is_exception, reason, is_expired = self.config.is_exception(
                account_id, region, resource_id
            )
            
            if is_exception:
                if is_expired:
                    # Include expired exceptions in findings with a note
                    finding['exception_expired'] = True
                    finding['exception_reason'] = reason
                    filtered.append(finding)
                else:
                    # Skip valid exceptions
                    pass
            else:
                # Include non-exception findings
                filtered.append(finding)
        
        return filtered
    
    def get_available_plugins(self):
        """
        Get list of available plugin names.
        
        Returns:
            List of plugin names
        """
        return self.plugin_loader.get_plugin_names()
    
    def get_config(self):
        """
        Get the configuration object.
        
        Returns:
            Config object
        """
        return self.config
