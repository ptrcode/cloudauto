#!/usr/bin/env python

"""
=========================
Boto 3 Ckan AWS Config
=========================
Just a unit level config testing file.
"""

from __future__ import print_function
import json
import os
from boto3.session import Session
import boto3

class CkanConfigError(Exception):
    pass


class CkanConfig(object):


    def __init__(self, AWSAccessKeyId, AWSSecretKey,site_id = 'ckan-demo'):
        super(CkanConfig, self).__init__()

    # Local (filesystem) related.
        self.session= Session(aws_access_key_id='AWSAccessKeyId',
                  aws_secret_access_key='AWSSecretKey',
                  region_name='us-east-1')
        self.site_id = site_id
        self.s3 = self.session.resource('s3')
        self.iam = self.session.resource('iam')
        self.ec2 = self.session.resource('ec2')
        self.ecs = boto3.client('ecs')

    @classmethod
    def load_from_config(cls, config_filepath):
        """
        Load a new master configuration from a JSON config file.
        """
        with open(config_filepath, 'r') as config:
            config_data = json.load(config)
            return CkanConfig(**config_data)

    def run(self):
        """
        Start the main loop. Make sure all the master configuration is in place.
        """
        # Make sure everything we need is setup, both locally & on AWS.
        #print (self.session.get_available_services())
        #print (self.session.get_available_resources())
        self.ecs.create_cluster()
        print (self.ecs.describe_clusters())
        #
        self.ec2.run_instances(ImageId='ami-ecd5e884',MinCount=1,MaxCount=1,InstanceType='t2.micro')

        # Make sure the cluster is created , create a loabalancer , attach with the container .
        #self.client.create_cluster()
        #make the container definitions first.

        #response = self.client.register_task_definition(family='string', containerDefinitions=[...])

if __name__ == '__main__':
    import sys

    config_filepath = os.path.abspath(
        os.path.expanduser(
            './config/config.json'
        )
    )
    # Check if the config file exists.
    # If not, create an empty one & prompt the user to edit it.
    if not os.path.exists(config_filepath):
        print("Cant find the config file.")
        sys.exit(1)

    # If so, load from it & run.
    auto = CkanConfig.load_from_config(config_filepath)

    try:
        auto.run()
    except KeyboardInterrupt:
        # We're done. Bail out without dumping a traceback.
        sys.exit(0)
