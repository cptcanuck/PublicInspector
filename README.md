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

PublicInspector scans **25 AWS services** for public exposure:

- **S3 Buckets**: Checks for public access configurations, ACLs, and policies
- **CloudFront**: Identifies publicly accessible distributions
- **Security Groups**: Finds overly permissive inbound rules (0.0.0.0/0)
- **Load Balancers**: Detects internet-facing ALBs, NLBs, and Classic ELBs
- **API Gateway**: Identifies public REST APIs and HTTP APIs
- **Route53**: Finds public hosted zones
- **Elastic IPs**: Lists unattached or public IP addresses
- **EC2 Instances**: Checks for publicly accessible instances via security groups
- **Lambda Functions**: Detects function URLs and resource policies allowing public access
- **App Runner**: Identifies publicly accessible services
- **Elastic Beanstalk**: Finds public environments
- **EFS**: Checks for publicly accessible file systems
- **RDS/Aurora**: Detects publicly accessible databases
- **DynamoDB**: Identifies tables with public access
- **OpenSearch/Elasticsearch**: Finds publicly accessible domains
- **Redshift**: Detects publicly accessible clusters
- **EBS Snapshots**: Checks for publicly shared snapshots
- **AMIs**: Identifies publicly shared Amazon Machine Images
- **ECR**: Finds publicly accessible container repositories
- **SNS Topics**: Checks for topics with public policies
- **SQS Queues**: Identifies queues with public policies
- **EventBridge**: Finds event buses with public access
- **IAM Access Analyzer**: Leverages AWS IAM Access Analyzer to detect IAM roles/policies with external access

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

## Development Setup

### Using DevContainer (Recommended for Windows/VS Code)

PublicInspector includes a DevContainer configuration for consistent development environments, especially useful for Windows users.

#### Prerequisites

1. **Install Required Tools:**
   - [Visual Studio Code](https://code.visualstudio.com/)
   - [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) or Docker Engine (Linux)
   - [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for VS Code

2. **Configure AWS Credentials on Your Host Machine:**
   
   On Windows, run in PowerShell:
   ```powershell
   # Create .aws directory if it doesn't exist
   mkdir $env:USERPROFILE\.aws -Force
   
   # Configure AWS credentials
   aws configure
   ```
   
   Or manually create `%USERPROFILE%\.aws\credentials`:
   ```ini
   [default]
   aws_access_key_id = YOUR_ACCESS_KEY
   aws_secret_access_key = YOUR_SECRET_KEY
   
   [profile-name]
   aws_access_key_id = YOUR_ACCESS_KEY
   aws_secret_access_key = YOUR_SECRET_KEY
   ```
   
   And `%USERPROFILE%\.aws\config`:
   ```ini
   [default]
   region = us-east-1
   
   [profile profile-name]
   region = us-east-1
   ```

#### Opening the Project in DevContainer

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cptcanuck/PublicInspector.git
   cd PublicInspector
   ```

2. **Open in VS Code:**
   ```bash
   code .
   ```

3. **Start DevContainer:**
   - VS Code will detect the `.devcontainer` configuration
   - Click "Reopen in Container" when prompted, or
   - Press `F1` → "Dev Containers: Reopen in Container"

4. **Wait for Setup:**
   - The container will build and install all dependencies automatically
   - This may take a few minutes on first run
   - The `post-create.sh` script will install the project and run tests

#### What's Included in the DevContainer

- **Python 3.11** with all project dependencies pre-installed
- **AWS CLI** for credential management and testing
- **VS Code Extensions:**
  - Python language support with IntelliSense
  - Black formatter and isort for code formatting
  - Flake8 for linting
  - pytest for testing
  - AWS Toolkit for AWS resource exploration
  - GitHub Copilot (if you have access)

#### Using AWS Credentials in DevContainer

The devcontainer automatically mounts your AWS credentials from your host machine:

- **Windows:** `%USERPROFILE%\.aws` → `/home/vscode/.aws`
- **Linux/Mac:** `~/.aws` → `/home/vscode/.aws`

**Set AWS Profile (Optional):**
```bash
# In the devcontainer terminal
export AWS_PROFILE=your-profile-name

# Or set in VS Code settings.json
```

**Verify AWS Access:**
```bash
# Inside devcontainer
aws sts get-caller-identity
```

#### Development Workflow in DevContainer

```bash
# Run tests
./run_tests.sh

# Run the tool
python -m publicinspector.cli --help

# Scan for public resources
python -m publicinspector.cli scan --services s3

# Format code (automatic on save)
black publicinspector/
isort publicinspector/

# Run linter
flake8 publicinspector/
```

### Manual Development Setup (Linux/Mac)

If not using DevContainer:

```bash
# Clone and install
git clone https://github.com/cptcanuck/PublicInspector.git
cd PublicInspector
pip install -e .
pip install -r requirements-dev.txt

# Configure AWS credentials
aws configure

# Run tests
./run_tests.sh
```

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
        "cloudfront:GetDistribution",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeAddresses",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "apigateway:GET",
        "route53:ListHostedZones",
        "lambda:ListFunctions",
        "lambda:GetPolicy",
        "lambda:GetFunctionUrlConfig",
        "apprunner:ListServices",
        "elasticbeanstalk:DescribeEnvironments",
        "elasticfilesystem:DescribeFileSystems",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "es:ListDomainNames",
        "es:DescribeDomain",
        "redshift:DescribeClusters",
        "ecr:DescribeRepositories",
        "ecr:GetRepositoryPolicy",
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "events:ListEventBuses",
        "events:DescribeEventBus",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "access-analyzer:GetFinding",
        "iam:ListRoleTags",
        "sts:GetCallerIdentity",
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note**: 
- The `organizations:ListAccounts` permission is only needed if using `--organization` flag.
- The `access-analyzer:*` permissions are only needed for IAM Access Analyzer plugin.
- For IAM Access Analyzer to work, you must have an active Access Analyzer configured in each region you want to scan.

### IAM Access Analyzer Setup

The IAM Access Analyzer plugin requires an active Access Analyzer in the regions you want to scan:

```bash
# Create an Access Analyzer (one-time setup per region)
aws accessanalyzer create-analyzer \
  --analyzer-name PublicInspectorAnalyzer \
  --type ACCOUNT \
  --region us-east-1

# Verify it's active
aws accessanalyzer list-analyzers --region us-east-1
```

PublicInspector will automatically use any active Access Analyzer it finds in each region to detect IAM roles and policies with external access.

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

PublicInspector supports multiple output formats:

```bash
# Table format (default) - human-readable with colors
publicinspector scan

# JSON format - raw findings data
publicinspector scan --format json

# CSV format - for spreadsheet analysis
publicinspector scan --format csv --output report.csv

# Audit format - standardized JSON for compliance/automation
publicinspector scan --format audit --output audit-report.json
```

#### Audit Format

The **audit format** provides a standardized JSON structure ideal for compliance auditing, SIEM integration, and automation:

```json
{
  "version": "1.0",
  "scan_timestamp": "2024-01-15T10:30:00Z",
  "finding_count": 1,
  "findings": [
    {
      "resource_arn": "arn:aws:s3:::my-public-bucket",
      "account_id": "123456789012",
      "region": "us-east-1",
      "edge_type": "service",
      "exposure_vector": "s3_bucket_policy",
      "public_endpoint": "https://my-public-bucket.s3.amazonaws.com",
      "auth_required": "none",
      "evidence_source": "aws_s3_api",
      "last_verified": "2024-01-15T10:30:00Z",
      "resource_type": "s3_bucket",
      "resource_name": "my-public-bucket",
      "severity": "high",
      "is_exception": false,
      "tags": {"Environment": "prod"}
    }
  ]
}
```

**Audit Fields:**
- `resource_arn`: Full ARN of the resource
- `account_id`: AWS account ID
- `region`: AWS region
- `edge_type`: Exposure type (`network`, `identity`, `service`, `composite`)
- `exposure_vector`: How the resource is exposed (e.g., `s3_bucket_policy`, `security_group_ingress_rule`)
- `public_endpoint`: Publicly accessible URL/IP (if applicable)
- `auth_required`: Authentication requirement (`none`, `aws_iam`, `custom`, or `null` if uncertain)
- `evidence_source`: AWS API used to detect the finding (e.g., `aws_s3_api`, `aws_iam_access_analyzer`)
- `last_verified`: ISO timestamp of scan

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

### Multiple Organization Configuration

PublicInspector supports multiple AWS Organizations with separate profiles for management and member accounts.

#### Adding Organizations

```bash
# Add organization "AW" with separate profiles for payer and member accounts
publicinspector add-org AW \
  --name "AW Organization" \
  --management-profile AW-Payer-ReadOnly \
  --profile ReadOnly

# Add another organization with single profile
publicinspector add-org prod-org \
  --name "Production Org" \
  --profile prod-profile \
  --set-default
```

#### Organization Configuration Format

Organizations can define their own region lists, allowing different orgs to use different standard regions:

```json
{
  "organizations": {
    "AW": {
      "name": "AW Organization",
      "management_profile": "AW-Payer-ReadOnly",
      "profile": "ReadOnly",
      "role_name": "OrganizationAccountAccessRole",
      "description": "Uses separate profiles for payer and member accounts",
      "region_lists": {
        "all_used": ["us-east-1", "us-west-2", "ca-central-1"],
        "us_only": ["us-east-1", "us-west-2"],
        "ca_only": ["ca-central-1"]
      }
    },
    "prod-org": {
      "name": "Production Organization",
      "profile": "prod-profile",
      "management_profile": null,
      "role_name": "OrganizationAccountAccessRole",
      "description": "Uses single profile for all operations",
      "region_lists": {
        "all_used": ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"],
        "us_regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2"],
        "eu_regions": ["eu-west-1", "eu-west-2", "eu-central-1"]
      }
    }
  },
  "default_organization": "prod-org",
  "region_lists": {
    "all_used": ["us-east-1", "us-west-2", "eu-west-1"],
    "us_only": ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
  }
}
```

**Key Points:**
- `management_profile`: AWS profile used to access the management/payer account for listing organization accounts
- `profile`: AWS profile used to access member accounts (via role assumption)
- `region_lists`: Organization-specific named region lists (e.g., "all_used", "us_only")
- If `management_profile` is not specified, `profile` is used for both operations
- Command-line `--profile` option overrides the organization's member account profile
- When scanning an organization, region lists are looked up in the organization config first, then fall back to global region lists
- Global `region_lists` provide backward compatibility and defaults for non-organization scans

#### Region List Priority

When using the `--regions` flag with a named region list:
1. **Organization-specific region lists** (if `--org` is used): Checked first in the organization's config
2. **Global region lists**: Fallback for backward compatibility or when not using `--org`

Example:
```bash
# Uses "all_used" from AW organization config
publicinspector scan --org AW --regions all_used --service s3

# Uses "all_used" from global config (no org specified)
publicinspector scan --regions all_used --service s3
```

#### Scanning Organizations

```bash
# Scan organization using configured profiles
publicinspector scan --org AW

# List configured organizations
publicinspector list-orgs

# Scan with --list-orgs to see available organizations
publicinspector scan --list-orgs
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
