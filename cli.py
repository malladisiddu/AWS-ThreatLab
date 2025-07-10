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
@click.pass_context
def iam_escalation(ctx):
    """Run IAM privilege escalation scenario"""
    result = run_iam_escalation(ctx.obj['PROFILE'], ctx.obj['REGION'])
    echo(f"Scenario: {result['scenario']} completed. User: {result['user']}")

@cli.command()
@click.pass_context
def iam_detect(ctx):
    """Detect IAM privilege escalation via CloudTrail and generate report"""
    found, events = detect_iam_escalation(ctx.obj['PROFILE'], ctx.obj['REGION'])
    generate_report('iam_escalation', found, events)
    if found:
        echo(f"✅ Detection: AttachUserPolicy event found ({len(events)} occurrences)")
    else:
        echo("❌ Detection: No AttachUserPolicy events in the last 15 minutes")

@cli.command()
@click.pass_context
def iam_cleanup(ctx):
    """Cleanup IAM escalation test artifacts"""
    cleanup_iam_escalation(ctx.obj['PROFILE'], ctx.obj['REGION'])

@cli.command()
@click.pass_context
def s3_exfil(ctx):
    """Run S3 data exfiltration scenario"""
    result = run_s3_exfil(ctx.obj['PROFILE'], ctx.obj['REGION'])
    echo(f"Scenario: {result['scenario']} completed. Bucket: {result['bucket']}")

@cli.command()
@click.pass_context
def s3_detect(ctx):
    """Detect S3 data exfiltration via CloudTrail and generate report"""
    found, events = detect_s3_exfil(ctx.obj['PROFILE'], ctx.obj['REGION'])
    generate_report('s3_exfiltration', found, events)
    if found:
        echo(f"✅ Detection: GetObject event found ({len(events)} occurrences)")
    else:
        echo("❌ Detection: No GetObject events in the last 15 minutes")

@cli.command()
@click.pass_context
def s3_cleanup(ctx):
    """Cleanup S3 exfiltration artifacts"""
    cleanup_s3_exfil(ctx.obj['PROFILE'], ctx.obj['REGION'],
                     bucket_name=ctx.obj.get('LAST_BUCKET'))

# Lambda Backdoor Commands
@cli.command()
@click.pass_context
def lambda_backdoor(ctx):
    """Deploy Lambda backdoor scenario"""
    result = run_lambda_backdoor(ctx.obj['PROFILE'], ctx.obj['REGION'])
    echo(f"Lambda backdoor deployed: {result['function_name']}")
    echo(f"Status: {result['status']}")
    
    # Store result for cleanup
    ctx.obj['LAMBDA_RESULT'] = result

@cli.command()
@click.pass_context
def lambda_detect(ctx):
    """Detect Lambda backdoor via CloudTrail"""
    found, events = detect_lambda_backdoor(ctx.obj['PROFILE'], ctx.obj['REGION'])
    generate_report('lambda_backdoor', found, events)
    if found:
        echo(f"✅ Detection: Lambda backdoor activities found ({len(events)} events)")
    else:
        echo("❌ Detection: No Lambda backdoor activities detected")

@cli.command()
@click.pass_context
def lambda_cleanup(ctx):
    """Cleanup Lambda backdoor artifacts"""
    result = ctx.obj.get('LAMBDA_RESULT', {})
    cleanup_lambda_backdoor(
        ctx.obj['PROFILE'], ctx.obj['REGION'],
        function_name=result.get('function_name'),
        role_name=result.get('role_name'),
        policy_name=result.get('policy_name')
    )

# EC2 Lateral Movement Commands
@cli.command()
@click.pass_context
def ec2_lateral(ctx):
    """Deploy EC2 lateral movement scenario"""
    result = run_ec2_lateral(ctx.obj['PROFILE'], ctx.obj['REGION'])
    echo(f"EC2 lateral movement deployed: {result['instance_id']}")
    echo(f"Status: {result['status']}")
    
    # Store result for cleanup
    ctx.obj['EC2_RESULT'] = result

@cli.command()
@click.pass_context
def ec2_detect(ctx):
    """Detect EC2 lateral movement via CloudTrail"""
    found, events = detect_ec2_lateral_movement(ctx.obj['PROFILE'], ctx.obj['REGION'])
    generate_report('ec2_lateral_movement', found, events)
    if found:
        echo(f"✅ Detection: EC2 lateral movement found ({len(events)} events)")
    else:
        echo("❌ Detection: No EC2 lateral movement detected")

@cli.command()
@click.pass_context
def ec2_cleanup(ctx):
    """Cleanup EC2 lateral movement artifacts"""
    result = ctx.obj.get('EC2_RESULT', {})
    cleanup_ec2_lateral(
        ctx.obj['PROFILE'], ctx.obj['REGION'],
        instance_id=result.get('instance_id'),
        security_group_id=result.get('security_group_id'),
        role_name=result.get('role_name'),
        profile_name=result.get('profile_name'),
        policy_name=result.get('policy_name')
    )

# Cross-Account Abuse Commands
@cli.command()
@click.pass_context
def cross_account(ctx):
    """Deploy cross-account abuse scenario"""
    result = run_cross_account(ctx.obj['PROFILE'], ctx.obj['REGION'])
    echo(f"Cross-account role deployed: {result['role_name']}")
    echo(f"External ID: {result['external_id']}")
    echo(f"Status: {result['status']}")
    
    # Store result for cleanup
    ctx.obj['CROSS_ACCOUNT_RESULT'] = result

@cli.command()
@click.pass_context
def cross_account_detect(ctx):
    """Detect cross-account abuse via CloudTrail"""
    found, events = detect_cross_account_abuse(ctx.obj['PROFILE'], ctx.obj['REGION'])
    generate_report('cross_account_abuse', found, events)
    if found:
        echo(f"✅ Detection: Cross-account abuse found ({len(events)} events)")
    else:
        echo("❌ Detection: No cross-account abuse detected")

@cli.command()
@click.pass_context
def cross_account_cleanup(ctx):
    """Cleanup cross-account abuse artifacts"""
    result = ctx.obj.get('CROSS_ACCOUNT_RESULT', {})
    cleanup_cross_account(
        ctx.obj['PROFILE'], ctx.obj['REGION'],
        role_name=result.get('role_name'),
        policy_name=result.get('policy_name')
    )

# Advanced Threat Detection
@cli.command()
@click.pass_context
def advanced_detect(ctx):
    """Run comprehensive threat detection across all scenarios"""
    result = detect_advanced_threats(ctx.obj['PROFILE'], ctx.obj['REGION'])
    
    echo(f"🔍 Advanced Threat Detection Results:")
    echo(f"Threat Score: {result['threat_score']}/5")
    echo(f"Total Events: {result['total_events']}")
    
    if result['high_risk']:
        echo("🔴 HIGH RISK: Multiple attack vectors detected!")
    elif result['medium_risk']:
        echo("🟡 MEDIUM RISK: Some suspicious activities detected")
    else:
        echo("🟢 LOW RISK: No immediate threats detected")
    
    echo("\nDetection Breakdown:")
    for detection_name, detection_result in result['detections'].items():
        status = "✅ DETECTED" if detection_result['detected'] else "❌ NOT DETECTED"
        event_count = detection_result['event_count']
        echo(f"  {detection_name}: {status} ({event_count} events)")
    
    # Generate comprehensive report
    generate_report('advanced_threat_detection', result['threat_score'] > 0, result)

# Cleanup All
@cli.command()
@click.pass_context
def cleanup_all(ctx):
    """Cleanup all scenario artifacts"""
    echo("🧹 Cleaning up all scenarios...")
    
    # Cleanup in reverse order to handle dependencies
    scenarios = [
        ('lambda_backdoor', 'LAMBDA_RESULT', cleanup_lambda_backdoor),
        ('ec2_lateral_movement', 'EC2_RESULT', cleanup_ec2_lateral),
        ('cross_account_abuse', 'CROSS_ACCOUNT_RESULT', cleanup_cross_account),
        ('iam_escalation', None, cleanup_iam_escalation),
        ('s3_exfiltration', None, cleanup_s3_exfil)
    ]
    
    for scenario_name, result_key, cleanup_func in scenarios:
        try:
            echo(f"Cleaning up {scenario_name}...")
            
            if result_key and result_key in ctx.obj:
                result = ctx.obj[result_key]
                if scenario_name == 'lambda_backdoor':
                    cleanup_func(
                        ctx.obj['PROFILE'], ctx.obj['REGION'],
                        function_name=result.get('function_name'),
                        role_name=result.get('role_name'),
                        policy_name=result.get('policy_name')
                    )
                elif scenario_name == 'ec2_lateral_movement':
                    cleanup_func(
                        ctx.obj['PROFILE'], ctx.obj['REGION'],
                        instance_id=result.get('instance_id'),
                        security_group_id=result.get('security_group_id'),
                        role_name=result.get('role_name'),
                        profile_name=result.get('profile_name'),
                        policy_name=result.get('policy_name')
                    )
                elif scenario_name == 'cross_account_abuse':
                    cleanup_func(
                        ctx.obj['PROFILE'], ctx.obj['REGION'],
                        role_name=result.get('role_name'),
                        policy_name=result.get('policy_name')
                    )
            else:
                cleanup_func(ctx.obj['PROFILE'], ctx.obj['REGION'])
                
            echo(f"✅ {scenario_name} cleanup completed")
            
        except Exception as e:
            echo(f"❌ {scenario_name} cleanup failed: {e}")
    
    echo("🎉 Cleanup completed!")



if __name__ == '__main__':
    cli()

