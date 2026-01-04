"""Output formatting utilities."""

import json
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class OutputFormatter:
    """
    Formats and displays scan results.
    
    Supports multiple output formats: table, json, csv
    """
    
    def __init__(self, format_type='table'):
        """
        Initialize the formatter.
        
        Args:
            format_type: Output format ('table', 'json', 'csv')
        """
        self.format_type = format_type
    
    def format_findings(self, findings):
        """
        Format findings according to the specified format.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Formatted string
        """
        if self.format_type == 'json':
            return self._format_json(findings)
        elif self.format_type == 'csv':
            return self._format_csv(findings)
        else:
            return self._format_table(findings)
    
    def _format_table(self, findings):
        """Format findings as a colored table."""
        if not findings:
            return "No public resources found!"
        
        # Prepare table data
        table_data = []
        for finding in findings:
            # Color code based on severity
            severity = finding.get('severity', 'info')
            severity_colored = self._color_severity(severity)
            
            # Get resource details
            details = finding.get('details', {})
            tags = details.get('tags', {})
            
            # Format tags for display
            tag_str = ''
            if tags:
                tag_items = [f"{k}={v}" for k, v in list(tags.items())[:2]]  # Show first 2 tags
                tag_str = ', '.join(tag_items)
                if len(tags) > 2:
                    tag_str += '...'
            
            row = [
                finding.get('account_id', 'unknown'),
                finding.get('region', 'unknown'),
                finding.get('resource_type', 'unknown'),
                finding.get('resource_name', 'unknown'),
                severity_colored,
                finding.get('public_access', 'unknown'),
                tag_str
            ]
            table_data.append(row)
        
        headers = ['Account', 'Region', 'Type', 'Resource', 'Severity', 'Public Access', 'Tags']
        
        return tabulate(table_data, headers=headers, tablefmt='grid')
    
    def _format_json(self, findings):
        """Format findings as JSON."""
        return json.dumps(findings, indent=2, default=str)
    
    def _format_csv(self, findings):
        """Format findings as CSV."""
        if not findings:
            return ""
        
        # CSV header
        headers = ['Account ID', 'Region', 'Resource Type', 'Resource Name', 'Resource ID', 
                   'Severity', 'Public Access', 'Tags', 'Details']
        lines = [','.join(headers)]
        
        # CSV rows
        for finding in findings:
            details = finding.get('details', {})
            tags = details.get('tags', {})
            
            # Format tags
            tag_str = '; '.join([f"{k}={v}" for k, v in tags.items()]) if tags else ''
            
            # Format additional details (exclude tags)
            detail_items = []
            for key, value in details.items():
                if key != 'tags' and value:
                    detail_items.append(f"{key}={value}")
            detail_str = '; '.join(detail_items)
            
            row = [
                finding.get('account_id', 'unknown'),
                finding.get('region', 'unknown'),
                finding.get('resource_type', 'unknown'),
                finding.get('resource_name', 'unknown'),
                finding.get('resource_id', 'unknown'),
                finding.get('severity', 'unknown'),
                finding.get('public_access', 'unknown'),
                tag_str,
                detail_str
            ]
            # Escape commas and quotes in fields
            row = [f'"{str(field).replace('"', '""')}"' for field in row]
            lines.append(','.join(row))
        
        return '\n'.join(lines)
    
    def _color_severity(self, severity):
        """
        Add color to severity level.
        
        Args:
            severity: Severity string
            
        Returns:
            Colored severity string
        """
        severity_lower = severity.lower()
        
        if severity_lower == 'critical':
            return f"{Fore.RED}{Style.BRIGHT}{severity.upper()}{Style.RESET_ALL}"
        elif severity_lower == 'high':
            return f"{Fore.RED}{severity.upper()}{Style.RESET_ALL}"
        elif severity_lower == 'medium':
            return f"{Fore.YELLOW}{severity.upper()}{Style.RESET_ALL}"
        elif severity_lower == 'low':
            return f"{Fore.BLUE}{severity.upper()}{Style.RESET_ALL}"
        else:
            return f"{Fore.GREEN}{severity.upper()}{Style.RESET_ALL}"
    
    def print_summary(self, findings):
        """
        Print a summary of findings.
        
        Args:
            findings: List of findings
        """
        print(f"\n{Style.BRIGHT}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Total findings: {len(findings)}")
        
        if findings:
            # Count by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\nFindings by severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    colored_severity = self._color_severity(severity)
                    print(f"  {colored_severity}: {count}")
