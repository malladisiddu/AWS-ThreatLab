import boto3
import json
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

    # 3. Simulate exfil by making object public (if possible)
    public_policy_success = False
    try:
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
        public_policy_success = True
        print(f"Successfully applied public bucket policy to {bucket_name}")
    except Exception as e:
        print(f"Warning: Could not apply public bucket policy (this is common with Block Public Access enabled): {e}")
        print("Continuing with scenario - this simulates an attacker trying to make data public")

    # 4. Download object (exfil) - This will work even without public policy
    try:
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        print(f"Successfully downloaded object {object_key} from {bucket_name}")
        exfil_success = True
    except Exception as e:
        print(f"Error downloading object: {e}")
        exfil_success = False

    return {
        'scenario': 's3_exfiltration',
        'bucket': bucket_name,
        'object': object_key,
        'public_policy_success': public_policy_success,
        'exfil_success': exfil_success
    }

def cleanup(profile=None, region=None, bucket_name=None, object_key='secret.txt'):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    s3 = session.resource('s3')
    s3_client = session.client('s3')

    if not bucket_name:
        # If no bucket name provided, find and clean up all poctest buckets
        print("No bucket name provided, searching for poctest buckets to clean up...")
        try:
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                if bucket['Name'].startswith('poctest-bucket-'):
                    bucket_name = bucket['Name']
                    print(f"Found bucket to clean up: {bucket_name}")
                    try:
                        # Delete all objects in bucket first
                        bucket_resource = s3.Bucket(bucket_name)
                        bucket_resource.objects.all().delete()
                        bucket_resource.delete()
                        print(f"Cleaned up bucket {bucket_name}")
                    except Exception as e:
                        print(f"Error cleaning up bucket {bucket_name}: {e}")
        except Exception as e:
            print(f"Error listing buckets: {e}")
    else:
        # Delete specific bucket
        try:
            bucket = s3.Bucket(bucket_name)
            bucket.Object(object_key).delete()
            bucket.delete()
            print(f"Cleaned up bucket {bucket_name} and object {object_key}")
        except Exception as e:
            print(f"Error cleaning up bucket {bucket_name}: {e}")
