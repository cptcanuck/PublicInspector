"""Command-line interface for PublicInspector."""

import click
import sys
from publicinspector.scanner import Scanner
from publicinspector.output import OutputFormatter
from publicinspector.config import Config
from publicinspector.aws_accounts import (
    get_session_for_profile,
    get_organization_accounts,
    get_session_for_account,
    get_current_account_id
)


@click.group()
def cli():
    """
    PublicInspector - Find publicly exposed AWS resources.
    
    This tool scans AWS accounts for resources that are publicly accessible,
    including S3 buckets, CloudFront distributions, security groups, and load balancers.
    """
    pass


@cli.command()
@click.option(
    '--profile',
    help='AWS profile name to use (from ~/.aws/credentials)',
    default=None
)
@click.option(
    '--organization',
    is_flag=True,
    help='Scan all accounts in the AWS organization'
)
@click.option(
    '--role-name',
    default='OrganizationAccountAccessRole',
    help='IAM role name to assume in organization accounts (default: OrganizationAccountAccessRole)'
)
@click.option(
    '--format',
    'output_format',
    type=click.Choice(['table', 'json', 'csv']),
    default='table',
    help='Output format (default: table)'
)
@click.option(
    '--output',
    '-o',
    help='Output file (optional, defaults to stdout)',
    default=None
)
@click.option(
    '--max-workers',
    type=int,
    default=10,
    help='Maximum parallel workers for scanning (default: 10)'
)
@click.option(
    '--config',
    'config_file',
    default='publicinspector-config.json',
    help='Configuration file path (default: publicinspector-config.json)'
)
@click.option(
    '--list-plugins',
    is_flag=True,
    help='List available scanner plugins and exit'
)
def scan(profile, organization, role_name, output_format, output, max_workers, config_file, list_plugins):
    """
    Scan AWS accounts for publicly exposed resources.
    
    Examples:
    
        # Scan current AWS account (uses default credentials)
        publicinspector scan
        
        # Scan using a specific AWS profile
        publicinspector scan --profile my-profile
        
        # Scan all accounts in an AWS organization
        publicinspector scan --organization
        
        # Output results as JSON
        publicinspector scan --format json --output results.json
    """
    
    # Initialize scanner
    scanner = Scanner(max_workers=max_workers, config_file=config_file)
    
    # List plugins if requested
    if list_plugins:
        print("Available scanner plugins:")
        for plugin_name in scanner.get_available_plugins():
            print(f"  - {plugin_name}")
        sys.exit(0)
    
    # Determine which accounts to scan
    try:
        if organization:
            # Scan organization accounts
            print("Fetching organization accounts...")
            accounts = get_organization_accounts()
            print(f"Found {len(accounts)} active accounts in organization")
            
            # Update config with organization account info
            config = scanner.get_config()
            for account in accounts:
                account_id = account['Id']
                account_name = account['Name']
                config.set_account_metadata(account_id, name=account_name)
            config.save_config()
            
            # Create sessions for each account
            sessions_with_ids = []
            for account in accounts:
                account_id = account['Id']
                account_name = account['Name']
                try:
                    print(f"Assuming role in account {account_id} ({account_name})...")
                    session = get_session_for_account(account_id, role_name)
                    sessions_with_ids.append((session, account_id))
                except Exception as e:
                    print(f"Warning: Could not access account {account_id}: {e}")
            
            # Scan all accounts
            findings = scanner.scan_accounts(sessions_with_ids)
            
        else:
            # Scan single account
            if profile:
                print(f"Using AWS profile: {profile}")
                session = get_session_for_profile(profile)
            else:
                print("Using default AWS credentials")
                import boto3
                session = boto3.Session()
            
            # Get account ID
            try:
                account_id = get_current_account_id()
            except Exception:
                account_id = None
            
            # Scan the account
            findings = scanner.scan_account(session, account_id)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Format and output results
    formatter = OutputFormatter(format_type=output_format)
    
    # Print summary to console
    formatter.print_summary(findings)
    
    # Format findings
    output_text = formatter.format_findings(findings)
    
    # Write to file or stdout
    if output:
        with open(output, 'w') as f:
            f.write(output_text)
        print(f"\nResults written to {output}")
    else:
        print("\n" + output_text)


@cli.command()
@click.argument('account_id')
@click.option('--name', help='Account name')
@click.option('--environment', type=click.Choice(['production', 'non-production']), help='Environment type')
@click.option('--tag', 'tags', multiple=True, help='Additional tags in format key=value')
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def tag_account(account_id, name, environment, tags, config_file):
    """
    Add metadata tags to an account.
    
    Examples:
    
        # Tag account as production
        publicinspector tag-account 123456789012 --environment production
        
        # Add multiple tags
        publicinspector tag-account 123456789012 --name "My Account" --environment production --tag team=devops --tag owner=john
    """
    config = Config(config_file)
    
    # Parse additional tags
    tag_dict = {}
    for tag in tags:
        if '=' in tag:
            key, value = tag.split('=', 1)
            tag_dict[key] = value
    
    # Set metadata
    config.set_account_metadata(account_id, name=name, environment=environment, tags=tag_dict)
    
    if config.save_config():
        print(f"Successfully updated metadata for account {account_id}")
        print(f"  Name: {name or 'not set'}")
        print(f"  Environment: {environment or 'not set'}")
        if tag_dict:
            print(f"  Additional tags:")
            for key, value in tag_dict.items():
                print(f"    {key}: {value}")
    else:
        print(f"Error saving configuration")
        sys.exit(1)


@cli.command()
@click.argument('account_id')
@click.argument('region')
@click.argument('resource_id')
@click.argument('resource_type')
@click.option('--reason', required=True, help='Reason why this resource is approved for public access')
@click.option('--expires', help='Expiration date in YYYY-MM-DD format')
@click.option('--added-by', help='Who is adding this exception')
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def add_exception(account_id, region, resource_id, resource_type, reason, expires, added_by, config_file):
    """
    Add an exception for a publicly accessible resource.
    
    This marks a resource as approved for public access so it won't appear in scan results.
    
    Examples:
    
        # Add exception for an S3 bucket
        publicinspector add-exception 123456789012 us-east-1 my-public-bucket s3_bucket --reason "Public website hosting"
        
        # Add exception with expiration
        publicinspector add-exception 123456789012 us-east-1 sg-12345678 security_group --reason "Temporary access for demo" --expires 2024-12-31
    """
    config = Config(config_file)
    
    config.add_exception(
        account_id=account_id,
        region=region,
        resource_id=resource_id,
        resource_type=resource_type,
        reason=reason,
        expiration_date=expires,
        added_by=added_by
    )
    
    if config.save_config():
        print(f"Successfully added exception for {resource_id}")
        print(f"  Account: {account_id}")
        print(f"  Region: {region}")
        print(f"  Type: {resource_type}")
        print(f"  Reason: {reason}")
        if expires:
            print(f"  Expires: {expires}")
    else:
        print(f"Error saving configuration")
        sys.exit(1)


@cli.command()
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
@click.option('--expired-only', is_flag=True, help='Show only expired exceptions')
def list_exceptions(config_file, expired_only):
    """
    List all resource exceptions.
    
    Examples:
    
        # List all exceptions
        publicinspector list-exceptions
        
        # List only expired exceptions
        publicinspector list-exceptions --expired-only
    """
    config = Config(config_file)
    
    if expired_only:
        exceptions = config.get_expired_exceptions()
        print(f"Expired exceptions: {len(exceptions)}")
    else:
        exceptions = config.get_all_exceptions()
        print(f"Total exceptions: {len(exceptions)}")
    
    if not exceptions:
        print("No exceptions found")
        return
    
    print("")
    for exc in exceptions:
        print(f"Resource: {exc['resource_id']}")
        print(f"  Account: {exc['account_id']}")
        print(f"  Region: {exc['region']}")
        print(f"  Type: {exc['resource_type']}")
        print(f"  Reason: {exc['reason']}")
        print(f"  Added: {exc.get('added_date', 'unknown')}")
        if exc.get('expiration_date'):
            print(f"  Expires: {exc['expiration_date']}")
        if exc.get('added_by'):
            print(f"  Added by: {exc['added_by']}")
        print("")


@cli.command()
@click.argument('account_id')
@click.argument('region')
@click.argument('resource_id')
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def remove_exception(account_id, region, resource_id, config_file):
    """
    Remove an exception for a resource.
    
    Examples:
    
        # Remove exception
        publicinspector remove-exception 123456789012 us-east-1 my-public-bucket
    """
    config = Config(config_file)
    
    if config.remove_exception(account_id, region, resource_id):
        config.save_config()
        print(f"Successfully removed exception for {resource_id}")
    else:
        print(f"Exception not found for {resource_id}")
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
