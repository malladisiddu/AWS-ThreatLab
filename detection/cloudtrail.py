import boto3
import json
from datetime import datetime, timedelta

def detect_iam_escalation(profile=None, region=None, lookback_minutes=15):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    ct = session.client('cloudtrail')

    # Define time window
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=lookback_minutes)

    # Lookup AttachUserPolicy events
    resp = ct.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'AttachUserPolicy'}],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=10
    )
    events = resp.get('Events', [])

    # Return True if any event found
    return len(events) > 0, events

def detect_s3_exfil(profile=None, region=None, lookback_minutes=15):
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    ct = session.client('cloudtrail')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=lookback_minutes)

    resp = ct.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'GetObject'}],
        StartTime=start_time,
        EndTime=end_time)
    events = resp.get('Events', [])

    return len(events) > 0, events

def detect_lambda_backdoor(profile=None, region=None, lookback_minutes=15):
    """
    Detect Lambda backdoor creation via CloudTrail events
    Looks for suspicious Lambda function creation with excessive permissions
    """
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    ct = session.client('cloudtrail')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=lookback_minutes)

    suspicious_events = []
    
    # Look for Lambda function creation
    lambda_events = ['CreateFunction', 'UpdateFunctionCode', 'UpdateFunctionConfiguration']
    
    for event_name in lambda_events:
        resp = ct.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        events = resp.get('Events', [])
        
        for event in events:
            # Parse CloudTrail event details
            try:
                event_detail = json.loads(event['CloudTrailEvent'])
                
                # Check for suspicious patterns
                if event_name == 'CreateFunction':
                    # Check for suspicious function names
                    function_name = event_detail.get('requestParameters', {}).get('functionName', '')
                    if any(term in function_name.lower() for term in ['backdoor', 'malware', 'shell', 'cmd']):
                        event['suspicion_reason'] = 'Suspicious function name'
                        suspicious_events.append(event)
                    
                    # Check for excessive permissions in role
                    role_arn = event_detail.get('requestParameters', {}).get('role', '')
                    if role_arn:
                        event['suspicion_reason'] = 'Lambda function created with custom role'
                        suspicious_events.append(event)
                
                elif event_name in ['UpdateFunctionCode', 'UpdateFunctionConfiguration']:
                    # Any function updates could be suspicious
                    event['suspicion_reason'] = 'Lambda function modified'
                    suspicious_events.append(event)
                    
            except (json.JSONDecodeError, KeyError):
                continue
    
    # Also check for IAM role creation with Lambda trust policy
    iam_events = ct.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'CreateRole'}],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )
    
    for event in iam_events.get('Events', []):
        try:
            event_detail = json.loads(event['CloudTrailEvent'])
            trust_policy = event_detail.get('requestParameters', {}).get('assumeRolePolicyDocument', '')
            
            if 'lambda.amazonaws.com' in trust_policy:
                event['suspicion_reason'] = 'Lambda execution role created'
                suspicious_events.append(event)
        except (json.JSONDecodeError, KeyError):
            continue
    
    return len(suspicious_events) > 0, suspicious_events

def detect_ec2_lateral_movement(profile=None, region=None, lookback_minutes=15):
    """
    Detect EC2 lateral movement via CloudTrail events
    Looks for suspicious EC2 instance creation and privilege escalation
    """
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    ct = session.client('cloudtrail')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=lookback_minutes)

    suspicious_events = []
    
    # Look for EC2 instance launches
    ec2_events = ['RunInstances', 'ModifyInstanceAttribute']
    
    for event_name in ec2_events:
        resp = ct.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        events = resp.get('Events', [])
        
        for event in events:
            try:
                event_detail = json.loads(event['CloudTrailEvent'])
                
                if event_name == 'RunInstances':
                    # Check for instances with IAM roles
                    iam_instance_profile = event_detail.get('requestParameters', {}).get('iamInstanceProfile', {})
                    if iam_instance_profile:
                        event['suspicion_reason'] = 'EC2 instance launched with IAM role'
                        suspicious_events.append(event)
                    
                    # Check for instances in public subnets
                    subnet_id = event_detail.get('requestParameters', {}).get('subnetId', '')
                    if subnet_id:
                        event['suspicion_reason'] = 'EC2 instance launched in specific subnet'
                        suspicious_events.append(event)
                
                elif event_name == 'ModifyInstanceAttribute':
                    # Instance attribute modifications could indicate lateral movement
                    event['suspicion_reason'] = 'EC2 instance attributes modified'
                    suspicious_events.append(event)
                    
            except (json.JSONDecodeError, KeyError):
                continue
    
    # Look for security group modifications
    sg_events = ['CreateSecurityGroup', 'AuthorizeSecurityGroupIngress']
    
    for event_name in sg_events:
        resp = ct.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        events = resp.get('Events', [])
        
        for event in events:
            try:
                event_detail = json.loads(event['CloudTrailEvent'])
                
                if event_name == 'AuthorizeSecurityGroupIngress':
                    # Check for overly permissive rules
                    ip_permissions = event_detail.get('requestParameters', {}).get('ipPermissions', {})
                    if ip_permissions:
                        # Check for 0.0.0.0/0 access
                        ip_ranges = str(ip_permissions)
                        if '0.0.0.0/0' in ip_ranges:
                            event['suspicion_reason'] = 'Security group rule allows access from anywhere'
                            suspicious_events.append(event)
                            
            except (json.JSONDecodeError, KeyError):
                continue
    
    return len(suspicious_events) > 0, suspicious_events

def detect_cross_account_abuse(profile=None, region=None, lookback_minutes=15):
    """
    Detect cross-account abuse via CloudTrail events
    Looks for suspicious cross-account role assumptions and overly permissive trust policies
    """
    session_args = {}
    if profile:
        session_args['profile_name'] = profile
    if region:
        session_args['region_name'] = region
    session = boto3.Session(**session_args)
    ct = session.client('cloudtrail')

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=lookback_minutes)

    suspicious_events = []
    
    # Look for AssumeRole events
    resp = ct.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'}],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )
    events = resp.get('Events', [])
    
    for event in events:
        try:
            event_detail = json.loads(event['CloudTrailEvent'])
            
            # Check for external account assumptions
            source_ip = event_detail.get('sourceIPAddress', '')
            user_identity = event_detail.get('userIdentity', {})
            
            # Check for unusual source IPs or cross-account access
            if source_ip and not source_ip.startswith('10.') and not source_ip.startswith('172.') and not source_ip.startswith('192.168.'):
                event['suspicion_reason'] = f'AssumeRole from external IP: {source_ip}'
                suspicious_events.append(event)
            
            # Check for cross-account role assumptions
            if user_identity.get('type') == 'AssumedRole':
                event['suspicion_reason'] = 'Cross-account role assumption detected'
                suspicious_events.append(event)
                
        except (json.JSONDecodeError, KeyError):
            continue
    
    # Look for IAM role creation with overly permissive trust policies
    resp = ct.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'CreateRole'}],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )
    events = resp.get('Events', [])
    
    for event in events:
        try:
            event_detail = json.loads(event['CloudTrailEvent'])
            trust_policy = event_detail.get('requestParameters', {}).get('assumeRolePolicyDocument', '')
            
            # Check for wildcard principal
            if '"Principal":{"AWS":"*"}' in trust_policy or '"Principal":"*"' in trust_policy:
                event['suspicion_reason'] = 'IAM role created with wildcard principal trust policy'
                suspicious_events.append(event)
            
            # Check for external account principals
            if '"Principal":{"AWS":"arn:aws:iam::' in trust_policy:
                event['suspicion_reason'] = 'IAM role created with cross-account trust policy'
                suspicious_events.append(event)
                
        except (json.JSONDecodeError, KeyError):
            continue
    
    return len(suspicious_events) > 0, suspicious_events

def detect_advanced_threats(profile=None, region=None, lookback_minutes=15):
    """
    Comprehensive threat detection combining multiple attack vectors
    """
    all_detections = {}
    
    # Run all detection functions
    detection_functions = [
        ('lambda_backdoor', detect_lambda_backdoor),
        ('ec2_lateral_movement', detect_ec2_lateral_movement),
        ('cross_account_abuse', detect_cross_account_abuse),
        ('iam_escalation', detect_iam_escalation),
        ('s3_exfiltration', detect_s3_exfil)
    ]
    
    for detection_name, detection_func in detection_functions:
        try:
            found, events = detection_func(profile, region, lookback_minutes)
            all_detections[detection_name] = {
                'detected': found,
                'event_count': len(events),
                'events': events
            }
        except Exception as e:
            all_detections[detection_name] = {
                'detected': False,
                'event_count': 0,
                'events': [],
                'error': str(e)
            }
    
    # Calculate overall threat score
    threat_score = sum(1 for det in all_detections.values() if det['detected'])
    total_events = sum(det['event_count'] for det in all_detections.values())
    
    return {
        'threat_score': threat_score,
        'total_events': total_events,
        'detections': all_detections,
        'high_risk': threat_score >= 3,
        'medium_risk': 1 <= threat_score < 3,
        'low_risk': threat_score == 0
    }
