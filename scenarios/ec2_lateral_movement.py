#!/usr/bin/Python3
#Author: Siddartha Malladi
#Twitter: st0ic3r
import boto3
import json
import time
import uuid
import base64

def run(profile=None, region=None):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    
    ec2_client = session.client('ec2')
    iam_client = session.client('iam')
    
    
    instance_name = f'lateral-movement-{uuid.uuid4().hex[:8]}'
    role_name = f'ec2-lateral-role-{uuid.uuid4().hex[:8]}'
    profile_name = f'ec2-lateral-profile-{uuid.uuid4().hex[:8]}'
    policy_name = f'ec2-lateral-policy-{uuid.uuid4().hex[:8]}'
    sg_name = f'lateral-sg-{uuid.uuid4().hex[:8]}'
    
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    
    lateral_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:*",
                    "rds:*",
                    "lambda:*",
                    "secretsmanager:*",
                    "ssm:*",
                    "ec2:*",
                    "iam:ListRoles",
                    "iam:ListUsers",
                    "iam:GetRole",
                    "iam:GetUser",
                    "sts:AssumeRole"
                ],
                "Resource": "*"
            }
        ]
    }
    
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='EC2 role for lateral movement simulation'
    )
    
    
    iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(lateral_policy),
        Description='Lateral movement permissions'
    )
    
    account_id = session.client('sts').get_caller_identity()['Account']
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )
    
    
    iam_client.create_instance_profile(InstanceProfileName=profile_name)
    iam_client.add_role_to_instance_profile(
        InstanceProfileName=profile_name,
        RoleName=role_name
    )
    
    
    vpc_response = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
    vpc_id = vpc_response['Vpcs'][0]['VpcId'] if vpc_response['Vpcs'] else None
    
    sg_response = ec2_client.create_security_group(
        GroupName=sg_name,
        Description='Security group for lateral movement testing',
        VpcId=vpc_id
    )
    sg_id = sg_response['GroupId']
    
    
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH from anywhere'}]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from anywhere'}]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 3389,
                'ToPort': 3389,
                'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'RDP from anywhere'}]
            }
        ]
    )
    
    
    user_data_script = '''#!/bin/bash
# Simulate credential harvesting and lateral movement
echo "Starting lateral movement simulation..." > /tmp/lateral_movement.log
echo "Attempting to access AWS services..." >> /tmp/lateral_movement.log

# Simulate credential harvesting
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ >> /tmp/lateral_movement.log
echo "Credential harvesting simulated" >> /tmp/lateral_movement.log

# Simulate service discovery
aws s3 ls >> /tmp/lateral_movement.log 2>&1
aws rds describe-db-instances >> /tmp/lateral_movement.log 2>&1
aws lambda list-functions >> /tmp/lateral_movement.log 2>&1

echo "Lateral movement simulation completed" >> /tmp/lateral_movement.log
'''
    
    user_data_encoded = base64.b64encode(user_data_script.encode()).decode()
    
    
    time.sleep(15)
    
    
    try:
        ami_response = ec2_client.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        
        latest_ami = sorted(ami_response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
        ami_id = latest_ami['ImageId']
    except Exception as e:
        
        print(f"Warning: Could not get latest AMI, using fallback: {e}")
        ami_id = 'ami-0c02fb55956c7d316'
    
    
    response = ec2_client.run_instances(
        ImageId=ami_id,
        MinCount=1,
        MaxCount=1,
        InstanceType='t2.micro',
        SecurityGroupIds=[sg_id],
        UserData=user_data_encoded,
        IamInstanceProfile={'Name': profile_name},
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': instance_name},
                    {'Key': 'Purpose', 'Value': 'LateralMovementTest'}
                ]
            }
        ]
    )
    
    instance_id = response['Instances'][0]['InstanceId']
    
    
    print(f"Waiting for instance {instance_id} to be running...")
    waiter = ec2_client.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    
    print(f"EC2 lateral movement scenario deployed")
    print(f"Instance ID: {instance_id}")
    print(f"Security Group: {sg_id}")
    print(f"IAM Role: {role_name}")
    
    return {
        'scenario': 'ec2_lateral_movement',
        'instance_id': instance_id,
        'instance_name': instance_name,
        'security_group_id': sg_id,
        'security_group_name': sg_name,
        'role_name': role_name,
        'profile_name': profile_name,
        'policy_name': policy_name,
        'policy_arn': policy_arn,
        'status': 'deployed'
    }

def cleanup(profile=None, region=None, instance_id=None, security_group_id=None, 
           role_name=None, profile_name=None, policy_name=None):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    
    ec2_client = session.client('ec2')
    iam_client = session.client('iam')
    
    cleanup_results = []
    
    
    if instance_id:
        try:
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            cleanup_results.append(f"Terminated EC2 instance: {instance_id}")
            
            waiter = ec2_client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=[instance_id])
        except Exception as e:
            cleanup_results.append(f"Error terminating instance: {e}")
    
    if security_group_id:
        try:
            ec2_client.delete_security_group(GroupId=security_group_id)
            cleanup_results.append(f"Deleted security group: {security_group_id}")
        except Exception as e:
            cleanup_results.append(f"Error deleting security group: {e}")

    if profile_name and role_name:
        try:
            iam_client.remove_role_from_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            iam_client.delete_instance_profile(InstanceProfileName=profile_name)
            cleanup_results.append(f"Deleted instance profile: {profile_name}")
        except Exception as e:
            cleanup_results.append(f"Error deleting instance profile: {e}")

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