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

    # 1. Create temp user
    user_name = 'poctest-user'
    iam.create_user(UserName=user_name)

    # 2. Attach overly broad policy
    policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

    # 3. Simulate an API call under that user (STS assume role simulation)
    # Note: in a real scenario, we'd generate keys; here, we just log the action
    print(f"Attached Admin policy to {user_name}")

    return {
        'scenario': 'iam_escalation',
        'user': user_name,
        'policy': policy_arn
    }
