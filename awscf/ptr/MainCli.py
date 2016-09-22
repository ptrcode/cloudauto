# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import io
import os
import sys
import json
import click
import boto3

from CkanSite import CkanSite


CONFIG_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), 'config'))
LOCAL_SETTINGS = os.path.abspath(os.path.join(os.path.dirname(__file__), 'config.json'))


def read_file(filepath):
    with io.open(filepath) as f:
        return json.loads(f.read())


@click.group()
def cli():
    """Ckan CLI."""

@cli.command()
def version():
    """Display the version and exit."""
    msg = 'There is no version tracking yet.'
    click.echo(msg)

@cli.command()
@click.argument('action', type=click.Choice(['push', 'read']))
@click.argument('config_type', type=click.Choice(['platform', 'cluster', 'app', 'ports']))
def config(action, config_type):
    """Manage config files"""

    filename = '{0}.json'.format(config_type)
    s3 = boto3.resource('s3')
    config = read_file(os.path.join(CONFIG_ROOT, filename))
    local = read_file(LOCAL_SETTINGS)
    bucket = s3.Bucket(local['platform']['config_bucket'])

    if config_type == 'platform':
        pass

    elif config_type == 'cluster':
        config['Resources']['ECSAutoScalingGroup']['Properties']['VPCZoneIdentifier'] = local['cluster']['subnets']
        config['Resources']['ContainerInstances']['Properties']['KeyName'] = local['cluster']['keyname']
        config['Parameters']['VpcId']['Default'] = local['cluster']['vpc']

    elif config_type == 'app':
        config['Mappings']['ENV']['DATABASE_SERVER']['staging'] = local['services']['db']['staging']['server']
        config['Mappings']['ENV']['DATABASE_SERVER']['production'] = local['services']['db']['production']['server']
        config['Mappings']['ENV']['DATABASE_USER']['staging'] = local['services']['db']['staging']['user']
        config['Mappings']['ENV']['DATABASE_USER']['production'] = local['services']['db']['production']['user']
        config['Mappings']['ENV']['DATABASE_PASSWORD']['staging'] = local['services']['db']['staging']['password']
        config['Mappings']['ENV']['DATABASE_PASSWORD']['production'] = local['services']['db']['production']['password']
        config['Mappings']['ENV']['CLUSTER']['staging'] = local['cluster']['names']['staging']
        config['Mappings']['ENV']['CLUSTER']['production'] = local['cluster']['names']['production']
        config['Mappings']['ENV']['DNSZONE']['staging'] = local['services']['dns']['staging']
        config['Mappings']['ENV']['DNSZONE']['production'] = local['services']['dns']['production']
        config['Resources']['EcsElasticLoadBalancer']['Properties']['Subnets'] = local['cluster']['subnets']
        config['Parameters']['VpcId']['Default'] = local['cluster']['vpc']

    elif config_type == 'ports':
        pass

    resp = bucket.put_object(Key=filename, Body=json.dumps(config))
    print(resp)


@cli.command()
@click.argument('image')
@click.argument('siteid')
@click.argument('env', type=click.Choice(['staging', 'production']))
def deploy(image, siteid, env):
    '''
    This will deploy the customer specific services on staging or production cluster
    '''
    deployservice(image, siteid, env)

@cli.command()
@click.argument('action', default='cluster', type=click.Choice(['cluster', 'platform']))
@click.option('--env',default='staging',type=click.Choice(['staging', 'production']))
def create(action,env):
    """Interact with ckan provisioner

    Args:
    * action: one of 'cluster', 'platform'
        * 'cluster' will create production or staging cluster
        * 'platform ' will create the platform like - vpc / network / security etc etc for cluster

    """
    if action == 'cluster':
        click.echo("creating cluster")
    else:
        click.echo("creating platform")

@cli.command()
@click.argument('action', default='cluster', type=click.Choice(['cluster', 'platform','customersite']))
@click.option('--name', default='siteid', type=click.Choice(['clustername', 'platformname','siteid']))
@click.option('--env',default='staging',type=click.Choice(['staging', 'production']))
def delete(action,name,env):
    """Interact with ckan provisioner

    Args:
    * action: one of 'cluster', 'platform', or 'customersite'
    * 'cluster' will delete production or staging cluster
    * 'platform ' will delet the platform like - vpc / network / security etc etc for cluster
    *

    """
    if action == 'cluster':
        click.echo("delete cluster")
    if action == 'platform':
        click.echo("delet platform")
    if action == 'customersite':
        click.echo("delete site ")

@cli.command()
@click.argument('action', default='cluster', type=click.Choice(['cluster', 'platform','customersite']))
@click.option('--name', default='siteid', type=click.Choice(['clustername', 'platformname','siteid']))
@click.option('--env',default='staging',type=click.Choice(['staging', 'production']))
def list(action,name,env):
    """Interact with ckan provisioner

    Args:
    * action: one of 'cluster', 'platform', or 'customersite'
    * 'cluster' will list production or staging cluster
    * 'platform ' will list the platform like - vpc / network / security etc etc for cluster
    *

    """
    if action == 'cluster':
        click.echo("list cluster")
    if action == 'platform':
        click.echo("list platform")
    if action == 'customersite':
        click.echo("list customer resource list")

def deployservice(image, siteid, env):
    config_filepath = os.path.abspath(
        os.path.expanduser(
            './config/config.json'
        )
    )

    local = read_file(LOCAL_SETTINGS)

    runner = CkanSite(local['app']['template'], local['platform']['config_bucket'])
    runner.setInput(image, siteid, env)
    try:
        runner.run()
    except KeyboardInterrupt:
        # We're done. Bail out without dumping a traceback.
        sys.exit(0)
if __name__ == '__main__':
    cli()
