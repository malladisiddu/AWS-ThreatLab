import click

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

if __name__ == '__main__':
    cli()
