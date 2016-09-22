from boto.dynamodb2.layer1 import DynamoDBConnection
from boto.dynamodb2 import connect_to_region
from boto.dynamodb2.table import Table
from boto.dynamodb import types
from django.conf import settings
from libs.utils import country_from_ip, geo_connection
import uuid
import time
import json

import logging
from django.contrib.contenttypes.models import ContentType
from clients.models import ProjectAWS
from clients.signals import cloudtrail_notification_signal

LOG = logging.getLogger(__name__)


def dynamodb_connection():
    """
    Create a dynamodb connection as per settings defined
    :return: the connection object for dynamodb
    """
    if settings.IS_DYNAMODB_LOCAL:
        conn = DynamoDBConnection(host=settings.DYNAMODB_HOST,
                                  port=settings.DYNAMODB_PORT,
                                  aws_secret_access_key=settings.DYNAMODB_SECRET,
                                  aws_access_key_id=settings.DYNAMODB_ACCESS,
                                  is_secure=False)

    else:
        conn = connect_to_region(settings.DYNAMODB_REGION,
                                 aws_secret_access_key=settings.DYNAMODB_SECRET,
                                 aws_access_key_id=settings.DYNAMODB_ACCESS)
    return conn


def item_uuid():
    """
    Generate an id for the for the database item
    :return: an unique id
    """
    return str(uuid.uuid4())


def time_now():
    """
    Return the current time as a number (epoch)
    :return: current time in epoch
    """
    return time.time()


class CloudTrailTable():
    """
    Class to represent the cloudtrail table in dynamodb
    """

    def __init__(self, table_name=settings.DYNAMODB_CLOUDTRAIL_TABLE):
        self.conn = dynamodb_connection()
        self.table = Table(table_name, connection=self.conn)

    def save_items(self, items, project_id):
        """
        Saves the items into db after 'dynamizing' them as a batch operation
        :param items: the list of items
        :param project_id: ProjectId hashkey for the table
        :return: None
        """
        # Parse every item in the response, add keys as per dynamodb, and
        # do a batch update
        geo_conn = geo_connection()
        with self.table.batch_write() as batch:
            for item in items:
                ctj = json.loads(item['CloudTrailEvent'])
                item['ProjectId'] = int(project_id)
                ip = ctj['sourceIPAddress']
                item['sourceIPAddress'] = ip
                item['countryCode'] = country_from_ip(ip, geo_conn=geo_conn)
                item['awsRegion'] = ctj['awsRegion']

                project_content_type_id = ContentType.objects.get_for_model(ProjectAWS).pk
                project_object_id = int(project_id)
                # Signal the receiver for event names here
                cloudtrail_notification_signal.send(sender=item['EventId'],
                                                    context_data=ctj,
                                                    project_content_type_id=project_content_type_id,
                                                    project_object_id=project_object_id)


                if settings.IS_DYNAMODB_LOCAL:
                    # We need to dynamize to store data in form of list, map etc
                    dy = types.Dynamizer()
                    for k, v in item.iteritems():
                        item[k] = dy.encode(v)

                batch.put_item(data=item)

    def delete_items(self, project_id, before_time):
        """
        Deletes the items before the given time
        :param before_time: time to query for items and delete
        :return: None
        """
        for item in self.table.query_2(ProjectId__eq=project_id,
                                       EventTime__lt=before_time,
                                       index='EventTime-index'):
            item.delete()

    def query_events(self, project_id):
        """
        Returns the items in the table for a given project id
        :param project_id: The hashkey project_id
        :return: table rows matching  the argument
        """
        return self.table.query_2(ProjectId__eq=project_id)
