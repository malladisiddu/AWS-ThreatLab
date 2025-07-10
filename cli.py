import click
from click import echo
from scenarios.iam_escalation import run as run_iam_escalation, cleanup as cleanup_iam_escalation
from scenarios.lambda_backdoor import run as run_lambda_backdoor, cleanup as cleanup_lambda_backdoor
from scenarios.ec2_lateral_movement import run as run_ec2_lateral, cleanup as cleanup_ec2_lateral
from scenarios.cross_account_abuse import run as run_cross_account, cleanup as cleanup_cross_account
from scenarios.s3_exfiltration import run as run_s3_exfil, cleanup as cleanup_s3_exfil
from detection.cloudtrail import (
    detect_iam_escalation, detect_lambda_backdoor, detect_ec2_lateral_movement,
    detect_cross_account_abuse, detect_s3_exfil, detect_advanced_threats
)
from analyzer.report import generate_report

@click.group()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def cli(ctx, profile, region):
    """
    AWS Threat Simulation Framework CLI
    """
    ctx.ensure_object(dict)
    ctx.obj['PROFILE'] = profile
    ctx.obj['REGION'] = region

@cli.command()
def version():
    """Print CLI version"""
    click.echo('aws-threat-sim v0.1.0')

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def iam_escalation(ctx, profile, region):
    """Run IAM privilege escalation scenario"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = run_iam_escalation(profile, region)
    echo(f"Scenario: {result['scenario']} completed. User: {result['user']}")

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def iam_detect(ctx, profile, region):
    """Detect IAM privilege escalation via CloudTrail and generate report"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    found, events = detect_iam_escalation(profile, region)
    generate_report('iam_escalation', found, events)
    if found:
        echo(f"[+] Detection: AttachUserPolicy event found ({len(events)} occurrences)")
    else:
        echo("[-] Detection: No AttachUserPolicy events in the last 15 minutes")

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def iam_cleanup(ctx, profile, region):
    """Cleanup IAM escalation test artifacts"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    cleanup_iam_escalation(profile, region)

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def s3_exfil(ctx, profile, region):
    """Run S3 data exfiltration scenario"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = run_s3_exfil(profile, region)
    echo(f"Scenario: {result['scenario']} completed. Bucket: {result['bucket']}")
    
    # Store result for cleanup
    ctx.obj['S3_RESULT'] = result

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def s3_detect(ctx, profile, region):
    """Detect S3 data exfiltration via CloudTrail and generate report"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    found, events = detect_s3_exfil(profile, region)
    generate_report('s3_exfiltration', found, events)
    if found:
        echo(f"[+] Detection: GetObject event found ({len(events)} occurrences)")
    else:
        echo("[-] Detection: No GetObject events in the last 15 minutes")

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def s3_cleanup(ctx, profile, region):
    """Cleanup S3 exfiltration artifacts"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = ctx.obj.get('S3_RESULT', {})
    cleanup_s3_exfil(profile, region, bucket_name=result.get('bucket'))

# Lambda Backdoor Commands
@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def lambda_backdoor(ctx, profile, region):
    """Deploy Lambda backdoor scenario"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = run_lambda_backdoor(profile, region)
    echo(f"Lambda backdoor deployed: {result['function_name']}")
    echo(f"Status: {result['status']}")
    
    # Store result for cleanup
    ctx.obj['LAMBDA_RESULT'] = result

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def lambda_detect(ctx, profile, region):
    """Detect Lambda backdoor via CloudTrail"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    found, events = detect_lambda_backdoor(profile, region)
    generate_report('lambda_backdoor', found, events)
    if found:
        echo(f"[+] Detection: Lambda backdoor activities found ({len(events)} events)")
    else:
        echo("[-] Detection: No Lambda backdoor activities detected")

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def lambda_cleanup(ctx, profile, region):
    """Cleanup Lambda backdoor artifacts"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = ctx.obj.get('LAMBDA_RESULT', {})
    cleanup_lambda_backdoor(
        profile, region,
        function_name=result.get('function_name'),
        role_name=result.get('role_name'),
        policy_name=result.get('policy_name')
    )

# EC2 Lateral Movement Commands
@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def ec2_lateral(ctx, profile, region):
    """Deploy EC2 lateral movement scenario"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = run_ec2_lateral(profile, region)
    echo(f"EC2 lateral movement deployed: {result['instance_id']}")
    echo(f"Status: {result['status']}")
    
    # Store result for cleanup
    ctx.obj['EC2_RESULT'] = result

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def ec2_detect(ctx, profile, region):
    """Detect EC2 lateral movement via CloudTrail"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    found, events = detect_ec2_lateral_movement(profile, region)
    generate_report('ec2_lateral_movement', found, events)
    if found:
        echo(f"[+] Detection: EC2 lateral movement found ({len(events)} events)")
    else:
        echo("[-] Detection: No EC2 lateral movement detected")

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def ec2_cleanup(ctx, profile, region):
    """Cleanup EC2 lateral movement artifacts"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = ctx.obj.get('EC2_RESULT', {})
    cleanup_ec2_lateral(
        profile, region,
        instance_id=result.get('instance_id'),
        security_group_id=result.get('security_group_id'),
        role_name=result.get('role_name'),
        profile_name=result.get('profile_name'),
        policy_name=result.get('policy_name')
    )

# Cross-Account Abuse Commands
@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def cross_account(ctx, profile, region):
    """Deploy cross-account abuse scenario"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = run_cross_account(profile, region)
    echo(f"Cross-account role deployed: {result['role_name']}")
    echo(f"External ID: {result['external_id']}")
    echo(f"Status: {result['status']}")
    
    # Store result for cleanup
    ctx.obj['CROSS_ACCOUNT_RESULT'] = result

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def cross_account_detect(ctx, profile, region):
    """Detect cross-account abuse via CloudTrail"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    found, events = detect_cross_account_abuse(profile, region)
    generate_report('cross_account_abuse', found, events)
    if found:
        echo(f"[+] Detection: Cross-account abuse found ({len(events)} events)")
    else:
        echo("[-] Detection: No cross-account abuse detected")

@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def cross_account_cleanup(ctx, profile, region):
    """Cleanup cross-account abuse artifacts"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = ctx.obj.get('CROSS_ACCOUNT_RESULT', {})
    cleanup_cross_account(
        profile, region,
        role_name=result.get('role_name'),
        policy_name=result.get('policy_name')
    )

# Advanced Threat Detection
@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def advanced_detect(ctx, profile, region):
    """Run comprehensive threat detection across all scenarios"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    result = detect_advanced_threats(profile, region)
    
    echo(f"Advanced Threat Detection Results:")
    echo(f"Threat Score: {result['threat_score']}/5")
    echo(f"Total Events: {result['total_events']}")
    
    if result['high_risk']:
        echo(" HIGH RISK: Multiple attack vectors detected!")
    elif result['medium_risk']:
        echo(" MEDIUM RISK: Some suspicious activities detected")
    else:
        echo(" LOW RISK: No immediate threats detected")
    
    echo("\nDetection Breakdown:")
    for detection_name, detection_result in result['detections'].items():
        status = "[+] DETECTED" if detection_result['detected'] else "[-] NOT DETECTED"
        event_count = detection_result['event_count']
        echo(f"  {detection_name}: {status} ({event_count} events)")
    
    # Generate comprehensive report
    generate_report('advanced_threat_detection', result['threat_score'] > 0, result)

# Cleanup All
@cli.command()
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def cleanup_all(ctx, profile, region):
    """Cleanup all scenario artifacts"""
    profile = profile or ctx.obj.get('PROFILE')
    region = region or ctx.obj.get('REGION')
    echo("[+] Cleaning up all scenarios...")
    
    # Cleanup in reverse order to handle dependencies
    scenarios = [
        ('lambda_backdoor', 'LAMBDA_RESULT', cleanup_lambda_backdoor),
        ('ec2_lateral_movement', 'EC2_RESULT', cleanup_ec2_lateral),
        ('cross_account_abuse', 'CROSS_ACCOUNT_RESULT', cleanup_cross_account),
        ('iam_escalation', None, cleanup_iam_escalation),
        ('s3_exfiltration', 'S3_RESULT', cleanup_s3_exfil)
    ]
    
    for scenario_name, result_key, cleanup_func in scenarios:
        try:
            echo(f"Cleaning up {scenario_name}...")
            
            if result_key and result_key in ctx.obj:
                result = ctx.obj[result_key]
                if scenario_name == 'lambda_backdoor':
                    cleanup_func(
                        profile, region,
                        function_name=result.get('function_name'),
                        role_name=result.get('role_name'),
                        policy_name=result.get('policy_name')
                    )
                elif scenario_name == 'ec2_lateral_movement':
                    cleanup_func(
                        profile, region,
                        instance_id=result.get('instance_id'),
                        security_group_id=result.get('security_group_id'),
                        role_name=result.get('role_name'),
                        profile_name=result.get('profile_name'),
                        policy_name=result.get('policy_name')
                    )
                elif scenario_name == 'cross_account_abuse':
                    cleanup_func(
                        profile, region,
                        role_name=result.get('role_name'),
                        policy_name=result.get('policy_name')
                    )
                elif scenario_name == 's3_exfiltration':
                    cleanup_func(
                        profile, region,
                        bucket_name=result.get('bucket')
                    )
            else:
                cleanup_func(profile, region)
                
            echo(f"[+] {scenario_name} cleanup completed")
            
        except Exception as e:
            echo(f"[-] {scenario_name} cleanup failed: {e}")
    
    echo("[+] Cleanup completed!")



if __name__ == '__main__':
    cli()

