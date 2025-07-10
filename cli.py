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

def display_banner():
    """Display the AWS-ThreatLab banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     █████╗ ██╗    ██╗███████╗      ████████╗██╗  ██╗██████╗ ███████╗ █████╗  ║
║    ██╔══██╗██║    ██║██╔════╝      ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗ ║
║    ███████║██║ █╗ ██║███████╗ █████╗  ██║   ███████║██████╔╝█████╗  ███████║ ║
║    ██╔══██║██║███╗██║╚════██║ ╚════╝  ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║ ║
║    ██║  ██║╚███╔███╔╝███████║         ██║   ██║  ██║██║  ██║███████╗██║  ██║ ║
║    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝         ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ║
║                                                                               ║
║                   ████████╗██╗      █████╗ ██████╗                           ║
║                   ╚══██╔══╝██║     ██╔══██╗██╔══██╗                          ║
║                      ██║   ██║     ███████║██████╔╝                          ║
║                      ██║   ██║     ██╔══██║██╔══██╗                          ║
║                      ██║   ███████╗██║  ██║██████╔╝                          ║
║                      ╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝                           ║
║                                                                               ║
║                             AWS-ThreatLab v1.0                               ║
║                                                                               ║
║               Validate Your Security Detections | Test Your Defenses         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    echo(banner)

@click.group(invoke_without_command=True)
@click.option("--profile", default=None, help="AWS CLI profile to use")
@click.option("--region", default=None, help="AWS region to target")
@click.pass_context
def cli(ctx, profile, region):
    """
    AWS-ThreatLab CLI
    """
    ctx.ensure_object(dict)
    ctx.obj['PROFILE'] = profile
    ctx.obj['REGION'] = region
    
    # Show banner when no command is provided
    if ctx.invoked_subcommand is None:
        display_banner()
        echo("")
        echo("AWS-ThreatLab")
        echo("A professional CLI tool for validating security detections")
        echo("")
        echo("Usage: python cli.py [OPTIONS] COMMAND [ARGS]...")
        echo("")
        echo("Commands:")
        echo("  version                Show version and banner")
        echo("  iam-escalation         Run IAM privilege escalation scenario")
        echo("  iam-detect             Detect IAM escalation attacks")
        echo("  iam-cleanup            Clean up IAM escalation artifacts")
        echo("  s3-exfil               Run S3 data exfiltration scenario")
        echo("  s3-detect              Detect S3 exfiltration attacks")
        echo("  s3-cleanup             Clean up S3 exfiltration artifacts")
        echo("  lambda-backdoor        Deploy Lambda backdoor scenario")
        echo("  lambda-detect          Detect Lambda backdoor activities")
        echo("  lambda-cleanup         Clean up Lambda backdoor artifacts")
        echo("  ec2-lateral            Deploy EC2 lateral movement scenario")
        echo("  ec2-detect             Detect EC2 lateral movement")
        echo("  ec2-cleanup            Clean up EC2 lateral movement artifacts")
        echo("  cross-account          Deploy cross-account abuse scenario")
        echo("  cross-account-detect   Detect cross-account abuse")
        echo("  cross-account-cleanup  Clean up cross-account abuse artifacts")
        echo("  advanced-detect        Run comprehensive threat detection")
        echo("  cleanup-all            Clean up all scenario artifacts")
        echo("")
        echo("Options:")
        echo("  --profile TEXT  AWS CLI profile to use")
        echo("  --region TEXT   AWS region to target")
        echo("  --help          Show this message and exit")
        echo("")
        echo("Examples:")
        echo("  python cli.py version")
        echo("  python cli.py iam-escalation --profile testing --region us-east-1")
        echo("  python cli.py advanced-detect --profile testing --region us-east-1")
        echo("")
        echo("For command-specific help: python cli.py <command> --help")

@cli.command()
def version():
    """Print CLI version and banner"""
    display_banner()
    echo("")
    echo("Version: 1.0.0")
    echo("Tool: AWS-ThreatLab")
    echo("Purpose: Defensive Security Testing")
    echo("")
    echo("Available Commands:")
    echo("  - iam-escalation     : IAM privilege escalation scenario")
    echo("  - s3-exfil          : S3 data exfiltration scenario")
    echo("  - lambda-backdoor   : Lambda backdoor deployment")
    echo("  - ec2-lateral       : EC2 lateral movement simulation")
    echo("  - cross-account     : Cross-account abuse testing")
    echo("  - advanced-detect   : Comprehensive threat detection")
    echo("  - cleanup-all       : Clean up all scenario artifacts")
    echo("")
    echo("Use 'python cli.py <command> --help' for command-specific help")

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
    
    # Show banner for the main detection feature
    display_banner()
    echo("[*] Starting comprehensive threat detection analysis...")
    echo("")
    
    result = detect_advanced_threats(profile, region)
    
    echo("="*79)
    echo("THREAT DETECTION RESULTS")
    echo("="*79)
    echo(f"Threat Score: {result['threat_score']}/5")
    echo(f"Total Events: {result['total_events']}")
    echo("")
    
    if result['high_risk']:
        echo("[!] HIGH RISK: Multiple attack vectors detected!")
    elif result['medium_risk']:
        echo("[!] MEDIUM RISK: Some suspicious activities detected")
    else:
        echo("[+] LOW RISK: No immediate threats detected")
    
    echo("")
    echo("Detection Breakdown:")
    echo("-" * 50)
    for detection_name, detection_result in result['detections'].items():
        status = "[+] DETECTED" if detection_result['detected'] else "[-] NOT DETECTED"
        event_count = detection_result['event_count']
        echo(f"  {detection_name:20}: {status} ({event_count} events)")
    
    echo("")
    echo("="*79)
    
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

