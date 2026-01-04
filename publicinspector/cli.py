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
    '--org', '--organization',
    'organization',
    default=None,
    help='Scan AWS organization. Use organization ID from config (e.g., "prod-org") or "default" to use default org, or use flag without value to auto-detect'
)
@click.option(
    '--role-name',
    default=None,
    help='IAM role name to assume in organization accounts (overrides organization config)'
)
@click.option(
    '--services', '--service',
    'services',
    default='all',
    help='Comma-separated list of services to scan, or "all" for all services. Examples: s3,cloudfront or all'
)
@click.option(
    '--regions', '--region',
    'regions',
    default=None,
    help='Comma-separated list of regions, a named region list from config, or "all". Examples: us-east-1,us-west-2 or all_used'
)
@click.option(
    '--tag-match', '--tag_match',
    'tag_match',
    default=None,
    help='Filter accounts by environment tag value (e.g., prod, production, non-production)'
)
@click.option(
    '--ignore-exceptions',
    is_flag=True,
    help='Show all public resources including those marked as exceptions'
)
@click.option(
    '--list-services',
    is_flag=True,
    help='List available services and exit'
)
@click.option(
    '--list-regions',
    is_flag=True,
    help='List available region lists from config and exit'
)
@click.option(
    '--list-orgs',
    is_flag=True,
    help='List available organizations from config and exit'
)
@click.option(
    '--format',
    'output_format',
    type=click.Choice(['table', 'json', 'csv', 'audit']),
    default='table',
    help='Output format: table (human-readable), json (raw findings), csv (spreadsheet), audit (standardized JSON)'
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
    help='List available scanner plugins and exit (deprecated: use --list-services)'
)
def scan(profile, organization, role_name, services, regions, tag_match, ignore_exceptions, list_services, list_regions, list_orgs,
         output_format, output, max_workers, config_file, list_plugins):
    """
    Scan AWS accounts for publicly exposed resources.
    
    Examples:
    
        # Scan current AWS account for all services
        publicinspector scan
        
        # Scan specific service
        publicinspector scan --service s3
        
        # Scan organization accounts tagged as production, only S3 in specific regions
        publicinspector scan --org prod-org --tag-match prod --service s3 --regions all_used
        
        # Show all public resources including exceptions
        publicinspector scan --ignore-exceptions
        
        # Scan default organization
        publicinspector scan --org default
        
        # Scan using a specific AWS profile
        publicinspector scan --profile my-profile --service s3,cloudfront
        
        # Output results as JSON
        publicinspector scan --format json --output results.json
    """
    
    # Initialize scanner
    scanner = Scanner(max_workers=max_workers, config_file=config_file)
    config = scanner.get_config()
    
    # List organizations if requested
    if list_orgs:
        print("Available organizations from configuration:")
        organizations = config.get_all_organizations()
        default_org = config.get_default_organization()
        
        for org_id, org_config in organizations.items():
            default_marker = " (default)" if org_id == default_org else ""
            print(f"\n  {org_id}{default_marker}")
            print(f"    Name: {org_config.get('name', 'N/A')}")
            if org_config.get('management_profile'):
                print(f"    Management Profile: {org_config.get('management_profile')}")
            if org_config.get('profile'):
                print(f"    Member Profile: {org_config.get('profile')}")
            print(f"    Role: {org_config.get('role_name', 'N/A')}")
            if org_config.get('description'):
                print(f"    Description: {org_config.get('description')}")
        sys.exit(0)
    
    # List region lists if requested
    if list_regions:
        print("Available region lists from configuration:")
        region_lists = config.get_all_region_lists()
        for list_name, region_list in region_lists.items():
            print(f"  {list_name}: {', '.join(region_list)}")
        sys.exit(0)
    
    # List services if requested
    if list_services or list_plugins:
        print("Available services to scan:")
        print("  all - Scan all services")
        print("")
        print("Individual services:")
        
        # Get service mapping
        service_map = scanner.get_service_mapping()
        for service_key in sorted(service_map.keys()):
            plugin_classes = service_map[service_key]
            plugin_names = [cls.__name__ for cls in plugin_classes]
            print(f"  {service_key:<25} - {', '.join(plugin_names)}")
        
        sys.exit(0)
    
    # Parse services to scan
    services_to_scan = []
    if services.lower() == 'all':
        services_to_scan = None  # Scan all
    else:
        services_to_scan = [s.strip() for s in services.split(',')]
    
    # Determine organization configuration first (needed for region lookup)
    org_config = None
    scan_organization = False
    org_id_for_regions = None
    
    if organization is not None:
        scan_organization = True
        
        # If organization is empty string (flag used without value), use default
        if organization == '':
            organization = config.get_default_organization()
        
        org_config = config.get_organization(organization)
        if not org_config:
            print(f"Error: Organization '{organization}' not found in configuration")
            print("Use 'publicinspector list-orgs' to see available organizations")
            print("Use 'publicinspector add-org' to add a new organization")
            sys.exit(1)
        
        print(f"Using organization: {org_config.get('name', organization)}")
        org_id_for_regions = organization
        
        # Determine which profile to use for member accounts
        member_profile = profile  # Command line profile takes precedence
        if not member_profile and org_config.get('profile'):
            member_profile = org_config.get('profile')
            print(f"Using member profile from organization config: {member_profile}")
        
        # Determine which profile to use for management account (for listing accounts)
        management_profile_to_use = org_config.get('management_profile')
        if management_profile_to_use:
            print(f"Using management profile for org API calls: {management_profile_to_use}")
        
        # Store member profile back to profile variable for later use
        profile = member_profile
        
        # Override role_name if not specified and organization has one
        if not role_name and org_config.get('role_name'):
            role_name = org_config.get('role_name')
    
    # Parse regions to scan (after organization config is determined)
    regions_to_scan = None
    if regions:
        if regions.lower() == 'all':
            regions_to_scan = None  # Scan all regions
        elif ',' in regions:
            # Comma-separated list of regions
            regions_to_scan = [r.strip() for r in regions.split(',')]
        else:
            # Try to load named region list from config (organization-specific first)
            region_list = config.get_region_list(regions, org_id=org_id_for_regions)
            if region_list:
                regions_to_scan = region_list
                source = "organization" if org_id_for_regions and config.get_organization(org_id_for_regions).get('region_lists', {}).get(regions) else "global"
                print(f"Using region list '{regions}' from {source} config: {', '.join(region_list)}")
            else:
                # Treat as single region
                regions_to_scan = [regions]
    
    # Set scanner filters
    if services_to_scan:
        scanner.set_service_filter(services_to_scan)
    
    if regions_to_scan:
        scanner.set_region_filter(regions_to_scan)
    
    if ignore_exceptions:
        scanner.set_ignore_exceptions(True)
        print("Note: Ignoring exceptions - all public resources will be shown")
    
    # Default role name if still not set
    if not role_name:
        role_name = 'OrganizationAccountAccessRole'
    
    # Determine which accounts to scan
    try:
        if scan_organization:
            # Scan organization accounts
            print("Fetching organization accounts...")
            
            # Determine which profile to use for org API calls
            # Priority: management_profile from org config > profile parameter > default
            org_api_profile = None
            if org_config and org_config.get('management_profile'):
                org_api_profile = org_config.get('management_profile')
            elif profile:
                org_api_profile = profile
            
            # Use organization-specific session if profile specified
            if org_api_profile:
                import boto3
                session = boto3.Session(profile_name=org_api_profile)
                # Temporarily override default session for organization API calls
                old_session = boto3.DEFAULT_SESSION
                boto3.setup_default_session(profile_name=org_api_profile)
                accounts = get_organization_accounts()
                boto3.DEFAULT_SESSION = old_session
            else:
                accounts = get_organization_accounts()
            
            print(f"Found {len(accounts)} active accounts in organization")
            
            # Update config with organization account info
            for account in accounts:
                account_id = account['Id']
                account_name = account['Name']
                config.set_account_metadata(account_id, name=account_name)
            config.save_config()
            
            # Filter accounts by tag if specified
            if tag_match:
                filtered_accounts = []
                for account in accounts:
                    account_id = account['Id']
                    env_tag = config.get_account_tag(account_id, 'environment')
                    
                    # Match tag (case insensitive partial match)
                    if env_tag and tag_match.lower() in env_tag.lower():
                        filtered_accounts.append(account)
                
                accounts = filtered_accounts
                print(f"Filtered to {len(accounts)} accounts matching tag '{tag_match}'")
                
                if len(accounts) == 0:
                    print("No accounts match the specified tag filter.")
                    print("Tip: Use 'publicinspector tag-account' to tag accounts first.")
                    sys.exit(0)
            
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
        import traceback
        traceback.print_exc()
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
@click.argument('org_id')
@click.option('--name', required=True, help='Organization name')
@click.option('--profile', help='AWS profile to use for member accounts')
@click.option('--management-profile', help='AWS profile to use for the management/payer account')
@click.option('--management-account-id', help='Management account ID')
@click.option('--role-name', default='OrganizationAccountAccessRole', help='IAM role name to assume in member accounts')
@click.option('--description', help='Description of this organization')
@click.option('--set-default', is_flag=True, help='Set this as the default organization')
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def add_org(org_id, name, profile, management_profile, management_account_id, role_name, description, set_default, config_file):
    """
    Add or update an organization configuration.
    
    Examples:
    
        # Add organization "AW" with separate profiles for payer and member accounts
        publicinspector add-org AW --name "AW Organization" --management-profile AW-Payer-ReadOnly --profile ReadOnly
        
        # Add a production organization
        publicinspector add-org prod-org --name "Production Organization" --profile prod-profile --set-default
        
        # Add a development organization
        publicinspector add-org dev-org --name "Development Organization" --profile dev-profile
    """
    config = Config(config_file)
    
    config.add_organization(
        org_id=org_id,
        name=name,
        profile=profile,
        management_profile=management_profile,
        management_account_id=management_account_id,
        role_name=role_name,
        description=description or ''
    )
    
    if set_default:
        config.set_default_organization(org_id)
    
    if config.save_config():
        print(f"Successfully added/updated organization '{org_id}'")
        print(f"  Name: {name}")
        if management_profile:
            print(f"  Management Profile: {management_profile}")
        if profile:
            print(f"  Member Profile: {profile}")
        print(f"  Role: {role_name}")
        if set_default:
            print(f"  Set as default organization")
    else:
        print(f"Error saving configuration")
        sys.exit(1)


@cli.command()
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def list_orgs(config_file):
    """
    List all configured organizations.
    
    Examples:
    
        # List all organizations
        publicinspector list-orgs
    """
    config = Config(config_file)
    
    organizations = config.get_all_organizations()
    default_org = config.get_default_organization()
    
    if not organizations:
        print("No organizations configured")
        print("Use 'publicinspector add-org' to add an organization")
        return
    
    print("Configured organizations:")
    for org_id, org_config in organizations.items():
        default_marker = " (default)" if org_id == default_org else ""
        print(f"\n  {org_id}{default_marker}")
        print(f"    Name: {org_config.get('name', 'N/A')}")
        if org_config.get('management_profile'):
            print(f"    Management Profile: {org_config.get('management_profile')}")
        if org_config.get('profile'):
            print(f"    Member Profile: {org_config.get('profile')}")
        print(f"    Role: {org_config.get('role_name', 'N/A')}")
        if org_config.get('management_account_id'):
            print(f"    Management Account: {org_config.get('management_account_id')}")
        if org_config.get('description'):
            print(f"    Description: {org_config.get('description')}")


@cli.command()
@click.argument('org_id')
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def remove_org(org_id, config_file):
    """
    Remove an organization configuration.
    
    Examples:
    
        # Remove an organization
        publicinspector remove-org dev-org
    """
    config = Config(config_file)
    
    if config.remove_organization(org_id):
        config.save_config()
        print(f"Successfully removed organization '{org_id}'")
    else:
        print(f"Organization '{org_id}' not found")
        sys.exit(1)


@cli.command()
@click.argument('org_id')
@click.option('--config', 'config_file', default='publicinspector-config.json', help='Configuration file path')
def set_default_org(org_id, config_file):
    """
    Set the default organization.
    
    Examples:
    
        # Set default organization
        publicinspector set-default-org prod-org
    """
    config = Config(config_file)
    
    # Check if organization exists
    if not config.get_organization(org_id):
        print(f"Error: Organization '{org_id}' not found")
        sys.exit(1)
    
    config.set_default_organization(org_id)
    
    if config.save_config():
        print(f"Successfully set '{org_id}' as default organization")
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
