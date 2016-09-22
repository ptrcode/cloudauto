import subprocess
from django.conf import settings
import logging
import json
from datetime import timedelta
from clients.models import AwsCloudwatchEc2CpuAverage, AwsCloudwatchElbSum
from .base import project_from_request
LOG = logging.getLogger(__name__)

from boto.ec2 import regions as aws_regions
AWS_REGION_NAMES = [x.name for x in aws_regions()
                    if x.name not in ['us-gov-west-1', 'cn-north-1']]


def configservice_enabled(request=None, aws_access=None, aws_secret=None):
    """
    To know if config-service is enabled for a client
    :param request: The request object containing aws_access and aws_secret
    :param aws_access: aws_access value
    :param aws_secret: aws_secret key value
    :return: Tuple (True, []) if service is enabled, Tuple (False, List of regions) otherwise
    """

    if not(aws_access and aws_secret):
        project = project_from_request(request)
        aws_access = project.aws_access
        aws_secret = project.aws_secret

    cmd1 = "export AWS_ACCESS_KEY_ID=%s && export AWS_SECRET_ACCESS_KEY=%s" % \
           (aws_access, aws_secret)

    errors = []
    success = []
    # For each region
    for region in settings.AWS_CONFIG_REGIONS:
        cmd2 = 'aws configservice get-status --region %s' % region
        cmd = " && ".join([cmd1, cmd2])
        try:
            p = subprocess.check_output([cmd], stdin=subprocess.PIPE, shell=True, stderr=subprocess.PIPE)
            success.append(region)
        except subprocess.CalledProcessError as e:
            LOG.info("Error command %s" % region)
            # this exception is raised when command exits with non-zero code
            LOG.info("Error string %s" % e.output.strip())
            LOG.info("Errors %s" % errors)
            errors.append(region)

    return len(errors) == 0, errors, success


def cloudtrailservice_enabled(request=None, aws_access=None, aws_secret=None):
    """
    To know if config-service is enabled for a client
    :param request: The request object containing aws_access and aws_secret
    :param aws_access: aws_access value
    :param aws_secret: aws_secret key value
    :return: Tuple (True, []) if service is enabled, Tuple (False, List of regions) otherwise
    """

    if not(aws_access and aws_secret):
        project = project_from_request(request)
        aws_access = project.aws_access
        aws_secret = project.aws_secret

    cmd1 = "export AWS_ACCESS_KEY_ID=%s && export AWS_SECRET_ACCESS_KEY=%s" % \
           (aws_access, aws_secret)

    errors = []
    success = []
    # For each region
    for region in AWS_REGION_NAMES:
        cmd2 = 'aws cloudtrail lookup-events --region %s' % region
        cmd = " && ".join([cmd1, cmd2])
        try:
            p = subprocess.check_output([cmd], stdin=subprocess.PIPE, shell=True, stderr=subprocess.PIPE)
            success.append(region)
        except subprocess.CalledProcessError as e:
            LOG.info("Error command %s" % region)
            # this exception is raised when command exits with non-zero code
            LOG.info("Error string %s" % e.output.strip())
            LOG.info("Errors %s" % errors)
            errors.append(region)

    return len(errors) == 0, errors, success


def resource_changes_relationships(request, resource_type, resource_id, region,
                                   limit=10, **kwargs):
    """
    Fetches 'related resource' and recent changes' for a given resource
    :param request:
    :param resource_type: Type of resource (vpc, subnet, etc)
    :param resource_id: ID of the resource (vpc-e5339bb0, etc)
    :param region: AWS region
    :param limit: Number of entries in the response
    :param kwargs: Other kwargs
    :return: Dictionary of recent changes and list of resources
    related to a resource.
    """
    # Resource types (for AWS cli)
    # AWS::EC2::NetworkInterface, AWS::EC2::VPNGateway, AWS::EC2::SecurityGroup, AWS::EC2::InternetGateway, AWS::EC2::Instance, AWS::EC2::CustomerGateway, AWS::EC2::Volume, AWS::EC2::VPC, AWS::EC2::NetworkAcl, AWS::EC2::Subnet, AWS::EC2::EIP, AWS::CloudTrail::Trail, AWS::EC2::VPNConnection, AWS::EC2::RouteTable

    RESOURCE_TYPE_DICT = {'vpc': 'AWS::EC2::VPC',
                          'subnet': 'AWS::EC2::Subnet',
                          'security_group': 'AWS::EC2::SecurityGroup'}

    project = project_from_request(request)
    aws_access = project.aws_access
    aws_secret = project.aws_secret
    project_id = project.project_id

    NUM_ITEMS = 10
    ret_list = []
    resource_type = RESOURCE_TYPE_DICT.get(resource_type, None)
    if not resource_type:
        raise Exception('Unknown resource type')
    run_cmd = ["export AWS_ACCESS_KEY_ID=%s && export AWS_SECRET_ACCESS_KEY=%s" % (aws_access, aws_secret),
               "aws configservice get-resource-config-history --resource-type %s --resource-id %s" \
               " --region %s --limit %s " \
               " --output json" % (resource_type, resource_id, region, limit)]

    cmd = " && ".join(run_cmd)
    p = subprocess.Popen([cmd], stdin=subprocess.PIPE, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    js = json.loads(p.communicate()[0])

    for item in js['configurationItems']:
        ret_list.append(item)
    while len(ret_list) <= NUM_ITEMS:
        next_token = js['nextToken']
        _run_cmd = "%s --next-token %s" % (cmd, next_token)
        p = subprocess.Popen([_run_cmd], stdin=subprocess.PIPE, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        js = json.loads(p.communicate()[0])
        for item in js['configurationItems']:
            ret_list.append(item)

    return ret_list, project_id


def cloudtrail_events(request, region, attribute_key=None,
                      attribute_value=None):
    """
    Fetches cloudtrail events from AWS CLI
    :param request: Request object
    :param region: Region in question
    :param attribute_key: Return results matching only the key
    :param attribute_value: Value for the key
    :return: dictionary of results
    """
    project = project_from_request(request)
    aws_access = project.aws_access
    aws_secret = project.aws_secret
    project_id = project.project_id

    run_cmd = ["export AWS_ACCESS_KEY_ID=%s && export AWS_SECRET_ACCESS_KEY=%s" % (aws_access, aws_secret)]
    sub_cmd = []
    if attribute_key and attribute_value:
        sub_cmd.append("aws cloudtrail lookup-events --lookup-attributes AttributeKey=%s,AttributeValue=%s " % (attribute_key, attribute_value))
    else:
        sub_cmd.append("aws cloudtrail lookup-events ")

    sub_cmd.append(" --region %s --output json " % (region))

    run_cmd.extend([" ".join(sub_cmd)])
    cmd = " && ".join(run_cmd)
    p = subprocess.Popen([cmd], stdin=subprocess.PIPE, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    resp = p.communicate()[0]
    try:
        js = json.loads(resp)
        ret = []
        for event in js['Events']:
            event_details = event.pop('CloudTrailEvent')
            # LOG.info("Event details- %s", event_details)
            event_details_parsed = json.loads(event_details)
            # Append to details dict, items as needed.
            event['EventDetails'] = dict(sourceIPAddress=event_details_parsed.get('sourceIPAddress'))
            ret.append(event)
        return ret
    except Exception as e:
        LOG.error("Exception while parsing cloudtrail data (%s)", str(e))
        return []


def cloudwatch_metric_statistics(region=None, period=None,
                                 start_time=None, end_time=None,
                                 resource_type=None, metric_name=None,
                                 statistics=None, resource_id=None):
    """
    Helper method to fetch the cloudwatch data from DB.
    :param region: Region in which the instance resides
    :param period: Period resolution for the data
    :param start_time: Start time for query
    :param end_time: End time for query
    :param resource_type: EC2 or ELB
    :param metric_name: The metric in question
    :param statistics: Average or Sum
    :param resource_id: The identifier for the resource. id for ec2 instance, name for elbs
    :return: The data set matching the query
    """
    data = []
    if resource_type.lower() == "ec2" and statistics.lower() == "average":
        items = AwsCloudwatchEc2CpuAverage.objects.filter(period=period,
                                                          region=region,
                                                          capture_time__range=(start_time, end_time),
                                                          instance_id=resource_id)

        data = serialize_cloudwatch_data(items, AwsCloudwatchEc2CpuAverage)

    elif resource_type.lower() == "elb" and statistics.lower() == "sum":
        items = AwsCloudwatchElbSum.objects.filter(period=period,
                                                   region=region,
                                                   capture_time__range=(start_time, end_time),
                                                   instance_name=resource_id,
                                                   metric=metric_name)
        data = serialize_cloudwatch_data(items, AwsCloudwatchElbSum)

    return data


def serialize_cloudwatch_data(items, model_klass):
    """
    Serialize the data given the model class
    :param items: list of instances to serialize
    :param model_klass: The model class
    :return: list of serialized data items
    """
    ret = []
    if model_klass == AwsCloudwatchEc2CpuAverage:
        for i in items:
            d = dict(Timestamp=i.capture_time,
                     Unit=i.unit,
                     Average=i.average)
            ret.append(d)
    elif model_klass == AwsCloudwatchElbSum:
        for i in items:
            d = dict(Timestamp=i.capture_time,
                     Unit=i.unit,
                     Sum=i.sum)
            ret.append(d)

    return ret