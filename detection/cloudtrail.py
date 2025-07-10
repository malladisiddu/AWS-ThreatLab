import boto3
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
