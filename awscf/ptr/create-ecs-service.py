#!/usr/bin/env python

"""
=========================
Boto 3 Ckan AWS provisioner
=========================
This application will completely provision the ckan applciation stack
in AWS.See the README for more details.
"""

from __future__ import print_function

import json
import os

import boto3
from botocore.client import ClientError
from boto3.session import Session

import logging
LOG = logging.getLogger(__name__)

class CkanProvisionError(Exception):
    pass


class CkanProvision(object):
    """
    This is the main provisioner class, which exposes a ``run`` method
    to put everything into motion.
    """
    # The following policies are for the IAM role.
    basic_role_policy = {
        'Statement': [
            {
                'Principal': {
                    'Service': ['ckan.amazonecs.com']
                },
                'Effect': 'Allow',
                'Action': ['sts:AssumeRole']
            },
        ]
    }
    more_permissions_policy = {
        'Statement': [
            {
                'Effect':'Allow',
                'Action': [
                    's3:ListBucket',
                    's3:Put*',
                    's3:Get*',
                    's3:*MultipartUpload*'
                ],
                'Resource': '*'
            },
            {
                'Effect': 'Allow',
                'Action': [
                    'sns:*',
                ],
                'Resource': '*',
            },
            {
                'Effect': 'Allow',
                'Action': [
                    'sqs:*',
                ],
                'Resource': '*',
            },
            {
                'Effect': 'Deny',
                'Action': [
                    's3:*Policy*',
                    's3:*Delete*',
                    'sns:*Remove*'
                ],
                'Resource':'*'
            },
        ]
    }

    def __init__(self, AWSAccessKeyId, AWSSecretKey,site_id = 'ckan-demo'):
        super(CkanProvision, self).__init__()

    # Local (filesystem) related.
        self.session= Session(aws_access_key_id='AWSAccessKeyId',
                  aws_secret_access_key='AWSSecretKey',
                  region_name='us-east-1')
        self.bucket_name = site_id+'_s3_bucket'
        self.rdsinstancename = site_id+'_rds'
        self.bucket = None
        self.rds = None
        self.role = None
        self.queue = None

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
            return CkanProvision(**config_data)

    def ensure_local_setup(self):
        """
        Ensures that the local  setup is in place -- currently some dummy code - config files + packages requires
        """

    def ensure_aws_setup(self):
        """
        Ensures that the AWS services, resources, and policies are set
        up so that they can all talk to one another and so that we
        can transcode media files.
        """
        if self.bucket_exists(self.bucket_name):
            self.bucket = self.s3.Bucket(self.bucket_name)
        else:
            self.bucket = self.s3.create_bucket(
                Bucket=self.bucket_name)

        if self.iam_role_exists():
            self.role = self.iam.Role(self.role_name)
        else:
            self.role = self.setup_iam_role()

    # The boto-specific methods.
    def bucket_exists(self, bucket_name):
        """
        Returns ``True`` if a bucket exists and you have access to
        call ``HeadBucket`` on it, otherwise ``False``.
        """
        try:
            self.s3.meta['client'].head_bucket(Bucket=bucket_name)
            return True
        except ClientError:
            return False

    def iam_role_exists(self):
        """
        Returns ``True`` if an IAM role exists.
        """
        try:
            self.iam.meta['client'].get_role(
                RoleName=self.role_name)
            return True
        except ClientError:
            return None

    def setup_iam_role(self):
        """
        Set up a new IAM role and set its policy to allow access to S3 and SNS. Returns the role.
        """
        role = self.iam.create_role(
            RoleName=self.role_name,
            AssumeRolePolicyDocument=json.dumps(self.basic_role_policy))
        role.RolePolicy('more-permissions').put(
            PolicyDocument=json.dumps(self.more_permissions_policy))
        return role


    def run(self):
        """
        Start the main loop. Make sure all the master configuration is in place.
        """
        # Make sure everything we need is setup, both locally & on AWS.
        self.ensure_local_setup()
        self.ensure_aws_setup()
        # Make sure the cluster is created , create a loabalancer , attach with the container .
        response = self.ecs.list_clusters()
        print(response)
        #make the container definitions first.

        #response = self.client.register_task_definition(family='string', containerDefinitions=[...])
        #provision task / service / loadbalancer from individual modules

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
    auto = CkanProvision.load_from_config(config_filepath)

    try:
        auto.run()
    except KeyboardInterrupt:
        # We're done. Bail out without dumping a traceback.
        sys.exit(0)
