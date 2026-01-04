# PublicInspector

A command-line tool that scans AWS accounts to find publicly exposed resources.

PublicInspector helps you identify security risks by scanning your AWS infrastructure for resources that are accessible from the internet, including S3 buckets, CloudFront distributions, security groups, and load balancers.

## Features

- **Plugin Architecture**: Modular scanner plugins for different AWS services
- **Multi-Account Support**: Scan individual accounts or entire AWS Organizations
- **Parallel Scanning**: Fast scanning across multiple accounts and regions
- **Account Classification**: Tag accounts as production/non-production with custom metadata
- **Exception Management**: Whitelist approved public resources with expiration dates
- **Multiple Output Formats**: Table, JSON, and CSV output
- **Read-Only Operations**: Uses only AWS read permissions (least privilege)

## Supported AWS Services

- **S3 Buckets**: Checks for public access configurations, ACLs, and policies
- **CloudFront**: Identifies publicly accessible distributions
- **Security Groups**: Finds overly permissive inbound rules (0.0.0.0/0)
- **Load Balancers**: Detects internet-facing ALBs and NLBs

## Installation

### From Source

```bash
git clone https://github.com/cptcanuck/PublicInspector.git
cd PublicInspector
pip install -e .
```

### Requirements

- Python 3.8+
- AWS credentials configured
- Appropriate IAM permissions (see below)

## IAM Permissions

PublicInspector follows the **principle of least privilege** and uses **only READ operations**. No write permissions are required.

### For Single Account Scanning

Use the following AWS Managed Policies:

- `SecurityAudit` - Provides read-only access to security-related resources
- `ViewOnlyAccess` - Provides read-only access to AWS services

**Recommended**: Attach both policies to the IAM user/role running PublicInspector.

```bash
# Example: Attach policies to an IAM user
aws iam attach-user-policy --user-name publicinspector-user --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-user-policy --user-name publicinspector-user --policy-arn arn:aws:iam::aws:policy/ViewOnlyAccess
```

### For Organization Scanning

In addition to the policies above, you need:

1. **In the Management Account** (where you run the tool):
   - `organizations:ListAccounts` permission

2. **In Each Member Account**:
   - Create an IAM role (e.g., `OrganizationAccountAccessRole`) with the managed policies above
   - Trust relationship allowing the management account to assume the role

#### Custom Minimal Policy (Alternative)

If you prefer a minimal custom policy instead of managed policies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetPublicAccessBlock",
        "cloudfront:ListDistributions",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "elasticloadbalancing:DescribeLoadBalancers",
        "sts:GetCallerIdentity",
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note**: The `organizations:ListAccounts` permission is only needed if using `--organization` flag.

### IAM Role for Organization Scanning

Create a role in each member account with this trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Replace `MANAGEMENT_ACCOUNT_ID` with your management account ID.

## Usage

### Basic Scanning

```bash
# Scan current AWS account (uses default credentials)
publicinspector scan

# Scan using a specific AWS profile
publicinspector scan --profile my-profile

# Scan all accounts in an AWS organization
publicinspector scan --organization

# Scan organization with custom role name
publicinspector scan --organization --role-name MyCustomRole
```

### Output Options

```bash
# Output as JSON
publicinspector scan --format json

# Save to file
publicinspector scan --output results.json --format json

# Output as CSV
publicinspector scan --format csv --output report.csv
```

### Performance Tuning

```bash
# Adjust parallel workers (default: 10)
publicinspector scan --max-workers 20
```

### Account Classification

Tag accounts with metadata to organize and classify them:

```bash
# Tag account as production
publicinspector tag-account 123456789012 --environment production

# Add account name and tags
publicinspector tag-account 123456789012 \
  --name "Production Web App" \
  --environment production \
  --tag team=engineering \
  --tag owner=john.doe@example.com

# Tag as non-production
publicinspector tag-account 987654321098 --environment non-production
```

### Exception Management

Whitelist approved public resources to exclude them from scan results:

```bash
# Add exception for a public S3 bucket (website hosting)
publicinspector add-exception \
  123456789012 \
  us-east-1 \
  my-public-website-bucket \
  s3_bucket \
  --reason "Public website hosting - approved by security team" \
  --added-by john.doe@example.com

# Add temporary exception with expiration
publicinspector add-exception \
  123456789012 \
  us-east-1 \
  sg-abc12345 \
  security_group \
  --reason "Temporary access for demo presentation" \
  --expires 2024-12-31 \
  --added-by jane.smith@example.com

# List all exceptions
publicinspector list-exceptions

# List only expired exceptions
publicinspector list-exceptions --expired-only

# Remove an exception
publicinspector remove-exception 123456789012 us-east-1 my-public-website-bucket
```

### Plugin Management

```bash
# List available scanner plugins
publicinspector scan --list-plugins
```

## Configuration File

PublicInspector stores account metadata and exceptions in `publicinspector-config.json` (created automatically).

You can specify a custom config file location:

```bash
publicinspector scan --config /path/to/config.json
publicinspector tag-account 123456789012 --environment production --config /path/to/config.json
```

### Configuration File Format

```json
{
  "version": "1.0",
  "accounts": {
    "123456789012": {
      "name": "Production Account",
      "tags": {
        "environment": "production",
        "team": "engineering"
      }
    }
  },
  "exceptions": [
    {
      "account_id": "123456789012",
      "region": "us-east-1",
      "resource_id": "my-public-bucket",
      "resource_type": "s3_bucket",
      "reason": "Public website hosting",
      "added_date": "2024-01-15",
      "expiration_date": null,
      "added_by": "john.doe@example.com"
    }
  ]
}
```

## Architecture

PublicInspector uses a plugin-based architecture designed for extensibility:

```
publicinspector/
├── base_plugin.py          # Base plugin interface (cloud-agnostic)
├── aws_base_plugin.py      # AWS-specific base class
├── plugins/                # Service scanner plugins
│   ├── s3_plugin.py        # S3 bucket scanner
│   ├── cloudfront_plugin.py    # CloudFront scanner
│   ├── security_group_plugin.py    # Security group scanner
│   └── load_balancer_plugin.py     # Load balancer scanner
├── scanner.py              # Orchestration with parallelization
├── plugin_loader.py        # Dynamic plugin discovery
├── config.py               # Configuration management
├── aws_accounts.py         # AWS account utilities
├── output.py               # Output formatting
└── cli.py                  # Command-line interface
```

### Adding New Plugins

To add a scanner for a new AWS service:

1. Create a new file in `publicinspector/plugins/` (e.g., `rds_plugin.py`)
2. Extend `AWSBasePlugin` class
3. Implement required methods: `get_name()`, `get_service_name()`, `scan()`
4. The plugin will be automatically discovered and loaded

Example:

```python
from publicinspector.aws_base_plugin import AWSBasePlugin

class RDSPlugin(AWSBasePlugin):
    def get_name(self):
        return "RDS Instance Scanner"
    
    def get_service_name(self):
        return "rds"
    
    def scan(self):
        findings = []
        # Your scanning logic here
        return findings
```

### Future Cloud Provider Support

The architecture is designed to support multiple cloud providers:

- `base_plugin.py` provides cloud-agnostic interfaces
- Provider-specific base classes (e.g., `aws_base_plugin.py`, future `azure_base_plugin.py`)
- Provider-specific plugins in subdirectories

## Output Severity Levels

- **CRITICAL**: All ports/protocols open to the internet
- **HIGH**: Sensitive ports exposed (SSH, RDP, databases)
- **MEDIUM**: Other services exposed with potential risk
- **LOW**: Common web services (HTTP/HTTPS)
- **INFO**: Informational findings (e.g., CloudFront distributions)

## Security Considerations

- **Read-Only**: PublicInspector never modifies your AWS resources
- **Credentials**: Use IAM roles or profiles; never hardcode credentials
- **Exceptions**: Review and audit exceptions regularly
- **Expired Exceptions**: Automatically flagged in scan results
- **Least Privilege**: Only requires read permissions

## Troubleshooting

### Permission Errors

If you encounter permission errors:

1. Verify IAM policies are attached
2. Check trust relationships for organization scanning
3. Ensure AWS credentials are properly configured
4. Test with `aws sts get-caller-identity`

### No Results Found

- Ensure resources exist in the scanned regions
- Check that the account has active resources
- Verify AWS credentials are for the correct account

### Organization Scanning Issues

- Confirm you're running from the management account
- Verify the IAM role exists in all member accounts
- Check the role name matches (default: `OrganizationAccountAccessRole`)
- Ensure trust relationships are configured correctly

## Contributing

Contributions are welcome! To add support for additional AWS services:

1. Create a new plugin in `publicinspector/plugins/`
2. Follow the existing plugin patterns
3. Ensure only read operations are used
4. Add tests if available
5. Update documentation

## License

MIT License

## Support

For issues and questions:
- GitHub Issues: https://github.com/cptcanuck/PublicInspector/issues
