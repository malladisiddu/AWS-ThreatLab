import boto3
import json
import time
import uuid

def run(profile=None, region=None):
    """
    Simulate cross-account trust abuse scenario:
    1. Create a role with overly permissive cross-account trust
    2. Create a policy allowing cross-account access
    3. Test the trust relationship
    4. Simulate external account access
    """
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    
    iam_client = session.client('iam')
    sts_client = session.client('sts')
    
    # Generate unique identifiers
    role_name = f'cross-account-role-{uuid.uuid4().hex[:8]}'
    policy_name = f'cross-account-policy-{uuid.uuid4().hex[:8]}'
    external_id = f'external-{uuid.uuid4().hex[:8]}'
    
    # Get current account ID
    account_id = sts_client.get_caller_identity()['Account']
    
    # Create overly permissive cross-account trust policy
    # WARNING: This allows ANY AWS account to assume the role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id
                    }
                }
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{account_id}:root"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    # Create policy with sensitive permissions
    cross_account_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "rds:DescribeDBInstances",
                    "rds:DescribeDBClusters",
                    "lambda:GetFunction",
                    "lambda:InvokeFunction",
                    "iam:ListRoles",
                    "iam:ListUsers",
                    "iam:GetRole",
                    "sts:GetCallerIdentity"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            }
        ]
    }
    
    # Create IAM role
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='Cross-account role with overly permissive trust policy',
        MaxSessionDuration=3600
    )
    
    # Create and attach policy
    iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(cross_account_policy),
        Description='Cross-account access policy'
    )
    
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )
    
    # Wait for role propagation
    time.sleep(10)
    
    # Test the cross-account role assumption
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    try:
        # Assume the role (simulating external account access)
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='CrossAccountTest',
            ExternalId=external_id,
            DurationSeconds=3600
        )
        
        # Create a new session with the assumed role credentials
        assumed_credentials = assume_role_response['Credentials']
        assumed_session = boto3.Session(
            aws_access_key_id=assumed_credentials['AccessKeyId'],
            aws_secret_access_key=assumed_credentials['SecretAccessKey'],
            aws_session_token=assumed_credentials['SessionToken'],
            region_name=region
        )
        
        # Test access with assumed role
        assumed_sts = assumed_session.client('sts')
        caller_identity = assumed_sts.get_caller_identity()
        
        print(f"Cross-account role created: {role_name}")
        print(f"Role ARN: {role_arn}")
        print(f"External ID: {external_id}")
        print(f"Successfully assumed role - Identity: {caller_identity['Arn']}")
        
        # Test accessing services with assumed role
        try:
            assumed_s3 = assumed_session.client('s3')
            buckets = assumed_s3.list_buckets()
            print(f"Cross-account S3 access: Found {len(buckets['Buckets'])} buckets")
        except Exception as e:
            print(f"Cross-account S3 access failed: {e}")
        
        assumption_success = True
        
    except Exception as e:
        print(f"Role assumption failed: {e}")
        assumption_success = False
    
    return {
        'scenario': 'cross_account_abuse',
        'role_name': role_name,
        'role_arn': role_arn,
        'policy_name': policy_name,
        'policy_arn': policy_arn,
        'external_id': external_id,
        'account_id': account_id,
        'assumption_success': assumption_success,
        'status': 'deployed'
    }

def cleanup(profile=None, region=None, role_name=None, policy_name=None):
    """Clean up cross-account abuse resources"""
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    
    iam_client = session.client('iam')
    sts_client = session.client('sts')
    
    cleanup_results = []
    
    # Get account ID
    account_id = sts_client.get_caller_identity()['Account']
    
    # Detach and delete policy
    if role_name and policy_name:
        try:
            policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
            
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            iam_client.delete_policy(PolicyArn=policy_arn)
            cleanup_results.append(f"Deleted IAM policy: {policy_name}")
        except Exception as e:
            cleanup_results.append(f"Error deleting IAM policy: {e}")
    
    # Delete IAM role
    if role_name:
        try:
            iam_client.delete_role(RoleName=role_name)
            cleanup_results.append(f"Deleted IAM role: {role_name}")
        except Exception as e:
            cleanup_results.append(f"Error deleting IAM role: {e}")
    
    for result in cleanup_results:
        print(result)
    
    return {'cleanup_results': cleanup_results}