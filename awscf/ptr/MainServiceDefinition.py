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
from botocore.handlers import json_decode_policies


class CkanServiceDefinitionError(Exception):
    pass


class CkanServiceDefinition(object):


    def __init__(self, AWSAccessKeyId, AWSSecretKey,site_id = 'ckan-demo'):
        super(CkanServiceDefinition, self).__init__()

    # Local (filesystem) related.
        self.session= Session(aws_access_key_id='AWSAccessKeyId',
                  aws_secret_access_key='AWSSecretKey',
                  region_name='us-east-1')
        self.site_id = site_id
        self.ecs = boto3.client('ecs')

    @classmethod
    def load_from_config(cls, config_filepath):
        """
        Load a new master configuration from a JSON config file.
        """
        with open(config_filepath, 'r') as config:
            config_data = json.load(config)
            return CkanServiceDefinition(**config_data)

    @classmethod
    def load_task_definition(cls, config_filepath):
        """
        Load a new master configuration from a JSON config file.
        """
        with open(config_filepath, 'r') as config:
            data = json.load(config)
            config.close()
            tmp = data["family"]
            data["family"] = "papu"
            with open(config_filepath, 'w') as jsonFile:
                jsonFile.seek(0)
                jsonFile.write(json.dumps(data , indent=4))
                jsonFile.close()

    def create_service_definition(self,config_filepath):
        """
        Create a site specific task definition file
        """
        sitename = self.site_id
        output_filepath = os.path.abspath(
        os.path.expanduser(
            './config/'+sitename+'/servicedefinition.json'
        )
        )
        if not os.path.exists('./config/'+sitename):
            os.makedirs('./config/'+sitename)
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
    def print_task_definition(cls, config_filepath):
        """
        Load a new master configuration from a JSON config file.
        """
        with open(config_filepath, 'r') as config:
            data = json.load(config)
            config.close()
            print(data['containerDefinitions'][0]['image'])


    def run(self):
        """
        Start the main loop. Make sure all the master configuration is in place.
        """
        config_filepath = os.path.abspath(
        os.path.expanduser(
            './config/servicedefinition.json'
        )
        )
        self.create_service_definition(config_filepath)

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
    auto = CkanServiceDefinition.load_from_config(config_filepath)
    try:
        auto.run()
    except KeyboardInterrupt:
        # We're done. Bail out without dumping a traceback.
        sys.exit(0)
