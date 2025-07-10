import boto3
import time
from datetime import datetime

def run(profile=None, region=None):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    s3 = session.client('s3')
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    bucket_name = f'poctest-bucket-{timestamp}'

    # 1. Create bucket
    s3.create_bucket(Bucket=bucket_name)
    time.sleep(2)

    # 2. Upload object
    object_key = 'secret.txt'
    s3.put_object(Bucket=bucket_name, Key=object_key, Body=b'SecretData')

    # 3. Simulate exfil by making object public
    policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 's3:GetObject',
            'Resource': f'arn:aws:s3:::{bucket_name}/*'
        }]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    # 4. Download object (exfil)
    s3.get_object(Bucket=bucket_name, Key=object_key)

    return {
        'scenario': 's3_exfiltration',
        'bucket': bucket_name,
        'object': object_key
    }

def cleanup(profile=None, region=None, bucket_name=None, object_key='secret.txt'):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    s3 = session.resource('s3')

    # Delete object and bucket
    bucket = s3.Bucket(bucket_name)
    bucket.Object(object_key).delete()
    bucket.delete()
    print(f"Cleaned up bucket {bucket_name} and object {object_key}.")
