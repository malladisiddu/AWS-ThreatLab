import click
from click import echo
from scenarios.iam_escalation import run as run_iam_escalation

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
    result = run_iam_escalation(ctx.obj.get('PROFILE'), ctx.obj.get('REGION'))
    echo(f"Scenario: {result['scenario']} completed. User: {result['user']}")

if __name__ == '__main__':
    cli()
