#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
=========================
Boto 3 -Ckan Site Creation  file - it will customize the templates as per site id and provision them
=========================
"""
# Import Python Libs
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import json
import os
from boto3.session import Session
import boto3

class CkanSiteError(Exception):
    pass


class CkanSite(object):
    def __init__(self, app_template, config_bucket):
        self.client = boto3.client('cloudformation')
        self.app_template = app_template
        self.config_bucket = config_bucket

    @classmethod
    def create_site_definition(cls,siteid):
        """
        Create a site specific task definition file
        """

        config_filepath = os.path.abspath(
        os.path.expanduser(
            './config/'+'/taskdefinition.json'
        )
        )
        output_filepath = os.path.abspath(
        os.path.expanduser(
            './config/'+siteid+'/taskdefinition.json'
        )
        )
        if not os.path.exists('./config/'+siteid):
            os.makedirs('./config/'+siteid)
        if not os.path.exists(output_filepath):
            open(output_filepath,'w').close()

        with open(config_filepath, 'r') as config:
            data = json.load(config)
            config.close()
            tmp = data["family"]
            data["family"] = "papu"
            with open(output_filepath, 'w') as jsonFile:
                #jsonFile.seek(0)
                jsonFile.write(json.dumps(data ,indent=2))
                jsonFile.close()

    @classmethod
    def print_site_definition(cls, siteid):
        """
        Load a new master configuration from a JSON config file.
        """
        config_filepath = os.path.abspath(
        os.path.expanduser(
            './config/'+siteid+'/taskdefinition.json'
        )
        )

        with open(config_filepath, 'r') as config:
            data = json.load(config)
            config.close()
            print(data['containerDefinitions'][0]['image'])

    def setInput(self, image, siteid, env):
        self.image = image
        self.siteid=siteid
        self.env=env
        self.portNo=getPortNo(self.config_bucket, siteid, env)

    def run(self):
        """
        Start the main loop. Make sure all the master configuration is in place.
        """
        response = self.client.create_stack(
                StackName='{0}-app-{1}'.format(self.env, self.siteid),
                TemplateURL=self.app_template,
                Parameters=[
                {
                'ParameterKey': 'SiteId',
                'ParameterValue': self.siteid,
                'UsePreviousValue': False
                },
                {
                'ParameterKey': 'Image',
                'ParameterValue': self.image,
                'UsePreviousValue': False
                },
                {
                'ParameterKey': 'Environment',
                'ParameterValue': self.env,
                'UsePreviousValue': False
                },
                {
                'ParameterKey': 'HostPort',
                'ParameterValue': self.portNo,
                'UsePreviousValue': False
                }
                ],
            TimeoutInMinutes=10,
            Capabilities=[
                'CAPABILITY_IAM',
            ],
            OnFailure='ROLLBACK',
            Tags=[
                {
                    'Key': 'CustomerId',
                    'Value': self.siteid
                },
            ]
        )

def getPortNo(config_bucket, siteid, env):
    s3 = boto3.resource('s3')
    ports = json.loads(s3.Object(bucket_name=config_bucket, key='ports.json').get()['Body'].read().decode('utf-8'))
    possible = set([v for v in range(ports['range'][0],ports['range'][1])])
    taken = set([v for v in ports['map'].values()])
    available = possible.difference(taken)
    port = available.pop()
    return str(port)

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
    auto = CkanSite.load_from_config(config_filepath)
    try:
        auto.run()
    except KeyboardInterrupt:
        # We're done. Bail out without dumping a traceback.
        sys.exit(0)
