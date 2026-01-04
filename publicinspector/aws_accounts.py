"""AWS account management utilities."""

import boto3


def get_session_for_profile(profile_name):
    """
    Create a boto3 session for a specific AWS profile.
    
    Args:
        profile_name: Name of the AWS profile from ~/.aws/credentials
        
    Returns:
        boto3.Session object
    """
    return boto3.Session(profile_name=profile_name)


def get_session_for_account(account_id, role_name='OrganizationAccountAccessRole'):
    """
    Create a boto3 session for a specific AWS account using role assumption.
    
    Args:
        account_id: AWS account ID to access
        role_name: IAM role name to assume in the target account
        
    Returns:
        boto3.Session object
    """
    sts = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f'PublicInspector-{account_id}'
    )
    
    credentials = response['Credentials']
    
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    return session


def get_organization_accounts():
    """
    Get all accounts in the AWS organization.
    
    Returns:
        List of dictionaries with 'Id', 'Name', 'Email', 'Status'
    """
    org_client = boto3.client('organizations')
    
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    
    for page in paginator.paginate():
        for account in page['Accounts']:
            if account['Status'] == 'ACTIVE':
                accounts.append({
                    'Id': account['Id'],
                    'Name': account['Name'],
                    'Email': account['Email'],
                    'Status': account['Status']
                })
    
    return accounts


def get_current_account_id():
    """
    Get the current AWS account ID.
    
    Returns:
        AWS account ID string
    """
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account']
