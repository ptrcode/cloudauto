from boto.ec2 import regions as aws_regions
from boto.ec2 import connect_to_region as ec2_connect
from boto.ec2.elb import connect_to_region as elb_connect
from boto.vpc import connect_to_region as vpc_connect
from boto.ec2.cloudwatch import connect_to_region as cloudwatch_connect_r

from boto.route53.connection import Route53Connection
from boto.rds2 import regions as rds_regions
from boto.rds2.layer1 import RDSConnection
from boto.route53.healthcheck import HealthCheck
from boto.sns import SNSConnection
from boto.route53.exception import DNSServerError

from boto.ec2.cloudwatch import CloudWatchConnection
from boto.cloudtrail import connect_to_region as cloudtrail_connect_r
from boto.cloudtrail.layer1 import CloudTrailConnection
from boto.cloudtrail import regions as cloudtrail_regions
from boto.vpc import VPCConnection
from django.contrib.contenttypes.models import ContentType

from .base import ObjectDict, project_from_request, run_in_thread, aws_cache_key,\
    gen_fake_req
from libs.base import aws_cache_key_linked_resources
from libs.consts import RESOURCE_PROPERTIES_MAP
from libs.aws_dynamodb import CloudTrailTable
from libs.serializers import serialize_ebs, serialize_elb, serialize_security_group, serialize_eip, serialize_vpc, \
    serialize_subnet
from libs.utils import compare_dict, country_from_ip, geo_connection
from notification.signals import create_notification_signal
from .utils import fqdn_to_ip, datetime_json_encoder, time_from_epoch, parse_whois_data
from clients.models import ProjectAWS, Route53, AwsRds
from django.core.cache import cache
from django.conf import settings
from datetime import datetime, timedelta
from dateutil.tz import tzutc
import dateutil.parser as dparser
from ago import human
from . import _aws_helper
from operator import itemgetter
import json
import time

import logging
LOG = logging.getLogger(__name__)

AWS_REGIONS = aws_regions()
AWS_REGION_NAMES = [x.name for x in AWS_REGIONS]
CTRAIL_REGION_NAMES = [x.name for x in cloudtrail_regions()]
WAIT_TIME = 20
HEALTHCHECK_METRIC_NAME = "HealthCheckStatus"
ELB_TRAFFIC_METRICS = ['HTTPCode_Backend_2XX', 'HTTPCode_Backend_3XX',
                       'HTTPCode_Backend_4XX', 'HTTPCode_Backend_5XX',
                       'HTTPCode_ELB_5XX', 'RequestCount']
CLOUDWATCH_PERIODS = [60, 300, 600]
SNAPSHOT_LIMIT = 10


def use_cache(fn):
    def _wrapper(*args, **kwargs):
        if not 'use_cache' in kwargs.keys():
            kwargs['use_cache'] = True
        return fn(*args, **kwargs)
    return _wrapper


def valid_region(name):
    if name in [region.name for region in AWS_REGIONS]:
        return True
    else:
        raise Exception("Invalid region name")


def valid_cache_item(item):
    if isinstance(item, list):
        return True
    return False


def get_conn(conn_type=None, request=None, **kwargs):
    """
    Method to return connection object for a given Type.
    :param type: Type of connection (SNS, Cloudwatch etc.)
    :param request: Request object
    :param kwargs: All other arguments
    :return: The connection of specified 'type'
    """
    if not conn_type:
        return None

    if request:
        project = project_from_request(request, None)
        aws_access = project.aws_access
        aws_secret = project.aws_secret
    else:
        aws_access = kwargs.get('aws_access', None)
        aws_secret = kwargs.get('aws_secret', None)

    conn = kwargs.get('conn', None)
    region = kwargs.get('region', None)
    if not conn:
        if conn_type == "route53":
            conn = Route53Connection(aws_access_key_id=aws_access,
                                     aws_secret_access_key=aws_secret)

        elif conn_type == "sns":
            conn = SNSConnection(aws_access_key_id=aws_access,
                                 aws_secret_access_key=aws_secret)
        elif conn_type == "elb":
            conn = elb_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        elif conn_type == "cloudwatch":
            if region:
                conn = cloudwatch_connect_r(region,
                                            aws_access_key_id=aws_access,
                                            aws_secret_access_key=aws_secret)
            else:
                conn = CloudWatchConnection(aws_access_key_id=aws_access,
                                            aws_secret_access_key=aws_secret)
        elif conn_type == "cloudtrail":
            if region:
                conn = cloudtrail_connect_r(region,
                                            aws_access_key_id=aws_access,
                                            aws_secret_access_key=aws_secret)
            else:
                conn = CloudTrailConnection(aws_access_key_id=aws_access,
                                            aws_secret_access_key=aws_secret)
        elif conn_type == 'rds':
            conn = RDSConnection(region=region,
                                 aws_access_key_id=aws_access,
                                 aws_secret_access_key=aws_secret)

    return conn


@use_cache
def ec2_instances_info(request, region_name, **kwargs):
    project = project_from_request(request, region_name)
    aws_access = project.aws_access
    aws_secret = project.aws_secret
    project_id = project.project_id

    ec2_instance_list = None
    ebs_volume_list = None
    eip_address_list = None
    elb_balancer_list = None
    vpc_list = None
    subnet_list = None
    security_group_list = None

    use_cache = kwargs.get('use_cache')

    ec2_cache_key = aws_cache_key(project_id, region=region_name, aws_service='ec2')
    ebs_cache_key = aws_cache_key(project_id, region=region_name, aws_service='ebs')
    eip_cache_key = aws_cache_key(project_id, region=region_name, aws_service='eip')
    elb_cache_key = aws_cache_key(project_id, region=region_name, aws_service='elb')
    vpc_cache_key = aws_cache_key(project_id, region=region_name, aws_service='vpc')
    subnet_cache_key = aws_cache_key(project_id, region=region_name, aws_service='subnet')
    security_group_cache_key = aws_cache_key(project_id, region=region_name, aws_service='security_group')

    try:
        try:
            LOG.info(
                "Fetching EC2 instances for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            ec2_instance_list = ec2_instances(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error("Error while fetching EC2 instances for project {0} and region {1}, Error {2}".format(project_id,
                                                                                                            region_name,
                                                                                                            str(e)))
        try:
            LOG.info(
                "Fetching EBS volumes for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            ebs_volume_list = ebs_volumes(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error("Error while fetching EBS volumes for project {0} and region {1}, Error {2}".format(project_id,
                                                                                                          region_name,
                                                                                                          str(e)))
        try:
            LOG.info(
                "Fetching EIP addresses for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            eip_address_list = eip_addresses(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error("Error while fetching EIP addresses for project {0} and region {1}, Error {2}".format(project_id,
                                                                                                            region_name,
                                                                                                            str(e)))
        try:
            LOG.info(
                "Fetching security groups for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            security_group_list = security_groups(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error("Error while fetching security groups addresses for project {0} and region {1}, Error {2}".format(
                project_id, region_name, str(e)))

        try:
            LOG.info(
                "Fetching ELB instances for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            elb_balancer_list = elb_instances(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error(
                "Error while fetching Elbs for project {0} and region {1}, Error {2}".format(project_id, region_name,
                                                                                             str(e)))
        try:
            LOG.info(
                "Fetching VPC instances for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            vpc_list = vpc_instances(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error(
                "Error while fetching vpcs for project {0} and region {1}, Error {2}".format(project_id, region_name,
                                                                                             str(e)))
        try:
            LOG.info(
                "Fetching Subnets for project {0} and region {1}, using cache : {2}".format(project_id, region_name,
                                                                                               use_cache))
            subnet_list = subnets(request, region_name, use_cache=use_cache)
        except Exception as e:
            LOG.error(
                "Error while fetching vpcs for project {0} and region {1}, Error {2}".format(project_id, region_name,
                                                                                             str(e)))

        return ObjectDict(
            ec2_instances=ec2_instance_list,
            ebs_volumes=ebs_volume_list,
            eip_addresses=eip_address_list,
            elb_balancers=elb_balancer_list,
        )

    except Exception as e:
        LOG.error("Exception occurred while getting instances info- %s", str(e))
        raise e


@use_cache
def all_regions_summary(request, project_id=None, **kwargs):
    if project_id:
        project = ProjectAWS.objects.get(pk=project_id)
        request = gen_fake_req(project.name, project.id,
                               project.access_key, project.secret)
    summary = dict(summary=[])
    for region in AWS_REGIONS:
        region_summary_dict = region_summary(request, region.name, **kwargs)
        summary['summary'].append(region_summary_dict)
    return summary


@use_cache
def region_summary(request, region_name, **kwargs):
    region_summary_dict = ec2_instances_info(request, region_name, **kwargs)
    summary_dict = region_summary_report(region_summary_dict, region_name)
    return summary_dict


def region_summary_report(summary, name):
    summary_dict = dict(region_name=name)
    tasks = {}
    ec2_task = dict(name="EC2 Instances")
    elb_task = dict(name="ELB Instances")
    eip_task = dict(name="EIP Addresses")
    ebs_task = dict(name="EBS Volumes")

    # Summarize ec2 instances
    ec2_count = len(summary.ec2_instances) if summary.ec2_instances else 0
    ec2_error_instances = []
    for ec2 in summary.ec2_instances:
        if ec2.state == 'stopped':
            ec2_error_instances.append(ec2)
    ec2_sum = "%d/%d EC2 instances stopped" % (len(ec2_error_instances), ec2_count)
    ec2_task['summary'] = ec2_sum
    ec2_task['error_count'] = len(ec2_error_instances)
    ec2_task['total_count'] = ec2_count
    ec2_task['has_errors'] = len(ec2_error_instances) > 0

    # Summarize elb instances
    elb_count = len(summary.elb_balancers) if summary.elb_balancers else 0
    elb_error_instances = []
    for elb in summary.elb_balancers:
        if not elb.instances:
            elb_error_instances.append(elb)
    elb_sum = "%d/%d ELB instances unused" % (len(elb_error_instances), elb_count)
    elb_task['summary'] = elb_sum
    elb_task['error_count'] = len(elb_error_instances)
    elb_task['total_count'] = elb_count
    elb_task['has_errors'] = len(elb_error_instances) > 0

    # Summarize eip addresses
    eip_count = len(summary.eip_addresses) if summary.eip_addresses else 0
    eip_error_instances = []
    for eip in summary.eip_addresses:
        if not eip.allocation_id:
            eip_error_instances.append(eip)
    eip_sum = "%d/%d EIP addresses unused" % (len(eip_error_instances), eip_count)
    eip_task['summary'] = eip_sum
    eip_task['error_count'] = len(eip_error_instances)
    eip_task['total_count'] = eip_count
    eip_task['has_errors'] = len(eip_error_instances) > 0

    # Summarize ebs Volumes
    ebs_count = len(summary.ebs_volumes) if summary.ebs_volumes else 0
    ebs_error_instances = []
    for ebs in summary.ebs_volumes:
        if not ebs.attach_data.status:
            ebs_error_instances.append(ebs)
    ebs_sum = "%d/%d EBS volumes unattached" % (len(ebs_error_instances), ebs_count)
    ebs_task['summary'] = ebs_sum
    ebs_task['error_count'] = len(ebs_error_instances)
    ebs_task['total_count'] = ebs_count
    ebs_task['has_errors'] = len(ebs_error_instances) > 0

    tasks['ec2'] = ec2_task;
    tasks['elb'] = elb_task;
    tasks['eip'] = eip_task;
    tasks['ebs'] = ebs_task;
    summary_dict['tasks'] = tasks
    summary_dict['has_errors'] = ec2_task['has_errors'] or elb_task['has_errors'] \
                                 or eip_task['has_errors'] or ebs_task['has_errors']

    return summary_dict


def healthchecks(request=None, **kwargs):
    """Return all Route53 healthchecks for a given project
    """
    conn = get_conn(conn_type="route53", request=request, **kwargs)
    return conn.get_list_health_checks()


def create_healthcheck(request=None, **kwargs):
    """Create a healthcheck from given parameters
    """
    ip_addr = kwargs.get('ip_addr', None)
    port = int(kwargs.get('port', None))
    hc_type = kwargs.get('hc_type', None)
    resource_path = kwargs.get('resource_path', None)
    fqdn = kwargs.get('fqdn', None)
    if fqdn == "":
        fqdn = None
    string_match = kwargs.get('string_match', None)
    if string_match == "":
        string_match = None
    # Same defaults as boto
    request_interval = int(kwargs.get('request_interval', 30))
    failure_threshold = int(kwargs.get('failure_threshold', 3))

    conn = get_conn(conn_type="route53", request=request, **kwargs)
    # Create a new healthcheck
    healthcheck = HealthCheck(ip_addr, port, hc_type, resource_path,
                              fqdn=fqdn, string_match=string_match,
                              request_interval=request_interval,
                              failure_threshold=failure_threshold)
    try:
        resp = conn.create_health_check(healthcheck)
    except DNSServerError as e:
        # This may mean that fqdn was not accepted by AWS, hence
        # we should pass an IP address for the fqdn
        # Only if fqdn is present
        if fqdn:
            try:
                ip_addr = fqdn_to_ip(fqdn)
            except Exception as e:
                # TODO: what if hostname cannot be resolved?? Throw error
                pass
        else:
            LOG.error("Error while creating healtcheck (%s)" % str(e))
            raise e

        # retry creating HealthCheck
        healthcheck = HealthCheck(ip_addr, port, hc_type, resource_path,
                                  fqdn=fqdn, string_match=string_match,
                                  request_interval=request_interval,
                                  failure_threshold=failure_threshold)

        resp = conn.create_health_check(healthcheck)

    return healthcheck, resp


def healthcheck_id_from_response(resp):
    return resp.CreateHealthCheckResponse.HealthCheck.Id


@run_in_thread
def create_alarm_for_healthcheck(request, region_name=None, **kwargs):
    """Method to return all the alarms for healthchecks,
    in the given region
    """
    healthcheck_id = kwargs.get('healthcheck_id')
    notification_arns = []
    notification = kwargs.get('notification', None)
    if notification:
        notification_arns = [notification['notification_list']]
    hc_metric = metric_for_healthcheck(healthcheck_id, request=request, **kwargs)
    if hc_metric:
        # Get all the parameters from kwargs
        name = kwargs.get('name', "")
        comparison = kwargs.get('comparison')
        threshold = int(kwargs.get('threshold'))
        period = int(kwargs.get('period'))
        evaluation_periods = kwargs.get('evaluation_periods')
        statistic = kwargs.get('statistic')

        ret = hc_metric.create_alarm(name, comparison, threshold, period,
                                     evaluation_periods, statistic,
                                     enabled=True, description=None,
                                     dimensions=None,
                                     alarm_actions=notification_arns,
                                     ok_actions=notification_arns,
                                     insufficient_data_actions=notification_arns,
                                     unit=None)

        return ret
    return None


def metric_for_healthcheck(healthcheck_id, request=None, conn=None,
                           wait=True, **kwargs):

    conn = get_conn(conn_type="cloudwatch", request=request, **kwargs)
    hc_metric = None
    while not hc_metric:
        # Find the metric from all available ones to create an alarm
        for metric in conn.list_metrics(metric_name=HEALTHCHECK_METRIC_NAME):
            if metric.dimensions['HealthCheckId'][0] == healthcheck_id:
                hc_metric = metric
        if wait:
            time.sleep(WAIT_TIME)
    return hc_metric


def all_healthchecks(request=None, **kwargs):

    conn = get_conn("route53", request, **kwargs)
    hcs = conn.get_list_health_checks()
    if hcs:
        return hcs.ListHealthChecksResponse.HealthChecks
    return []


def all_sns_subscriptions(request=None, protocol=None, **kwargs):

    conn = get_conn(conn_type="sns", request=request, **kwargs)
    sns_subs = conn.get_all_subscriptions()
    if sns_subs:
        sns_list = sns_subs['ListSubscriptionsResponse']['ListSubscriptionsResult'][
            'Subscriptions']
        if protocol:
            sns_list = [x for x in sns_list if x.get('Protocol') == protocol and
                        not x.get('SubscriptionArn') in ['PendingConfirmation', 'Deleted']]
        else:
            sns_list = [x for x in sns_list if not
                        x.get('SubscriptionArn') in ['PendingConfirmation', 'Deleted']]

        ret = dict()
        for item in sns_list:
            item_topic = item['TopicArn']
            if item_topic in ret.keys():
                ret[item_topic].append(item)
            else:
                ret[item_topic] = [item]
        return ret
    return {}


def alarms_for_healthcheck(request, metric_id,
                           metric_name=HEALTHCHECK_METRIC_NAME,
                           **kwargs):
    metric = metric_for_healthcheck(metric_id, request=request, wait=False, **kwargs)
    alarms = metric.describe_alarms(dimensions=metric.dimensions)
    return alarms


def create_sns_topic_with_email(request, topic, email_list, protocol="email", **kwargs):

    conn = get_conn(conn_type="sns", request=request, **kwargs)
    topic_dict = conn.create_topic(topic)
    topic_arn = topic_dict['CreateTopicResponse']['CreateTopicResult']['TopicArn']
    res = []
    for email in email_list:
        res.append(conn.subscribe(topic_arn, protocol, email))

    return res


def delete_healthchecks_with_alarm(request, healthcheck_ids, **kwargs):
    r53_conn = get_conn(conn_type="route53", request=request, **kwargs)
    cw_conn = get_conn(conn_type="cloudwatch", request=request, **kwargs)
    alarms = []
    for healthcheck_id in healthcheck_ids:
        alarms.append(alarms_for_healthcheck(request, healthcheck_id,
                                             conn=cw_conn, **kwargs))
        LOG.info("Deleting healthcheck (%s)")
        r53_conn.delete_health_check(healthcheck_id)

    # Get alarm names from list
    alarm_names = []
    for alarm in alarms:
        if alarm:
            for a in alarm:
                alarm_names.append(a.name)

    LOG.info("List of alarms to be deleted: %s " % str(alarm_names))
    # Delete only when list non-empty
    if alarm_names:
        cw_conn.delete_alarms(alarm_names)


def instances_map(region, project_id=None, request=None):
    ret_dict = dict()
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    ec2_cache_key = aws_cache_key(project_id, region=region, aws_service="ec2")
    ins_list = cache.get(ec2_cache_key)
    for i in ins_list:
        ret_dict[i.id] = serialize_instance(i)

    return ret_dict


def instance_name(ins_id, region, project_id=None, request=None):

    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    ec2_cache_key = aws_cache_key(project_id, region=region, aws_service="ec2")
    ins_list = cache.get(ec2_cache_key)
    name = ""
    for ins in ins_list:
        if ins.id == ins_id:
            name = ins.tags.get('Name', '')
            break
    return name


def instance_sch_events_region(request, region_name):
    project = project_from_request(request, region_name)
    aws_access = project.aws_access
    aws_secret = project.aws_secret
    project_id = project.project_id

    # Check if entry exists in cache
    ec2_events_key = aws_cache_key(project_id, region=region_name, aws_service="event")
    ec2_status = cache.get(ec2_events_key)

    if ec2_status is None:
        # Fetch from AWS if cache does not exist
        LOG.info("Cache does not exists for -Statuses- %s" % ec2_events_key)
        ec2_status = []
        conn = ec2_connect(region_name,
                           aws_access_key_id=aws_access,
                           aws_secret_access_key=aws_secret)

        # If connection object cannot be created
        if not conn:
            LOG.info("Connection cannot be created for region %s" % region_name)
            return ec2_status
        try:
            ins_statuses = conn.get_all_instance_status() or []
        except Exception as e:
            LOG.info("Exception occurred during getting instance status %s" % region_name)
            ins_statuses = []

        LOG.info("Instances statuses = %s" % str(ins_statuses))

        for ins in ins_statuses:
            if ins.events is not None:
                # Time now for calculation
                now = datetime.now(tzutc())
                ins_id = ins.id
                ins_name = instance_name(request=request,
                                         region=region_name,
                                         ins_id=ins_id)
                # Get name for the instance with given id
                for event in ins.events:
                    code = event.code
                    desc = event.description
                    if desc.strip().startswith(('[Canc', '[Comp')):
                        continue
                    after = None
                    before = None
                    if event.not_after:
                        after = dparser.parse(event.not_after, fuzzy=True)
                        after = human(after - now)
                    if event.not_before:
                        before = dparser.parse(event.not_before, fuzzy=True)
                        before = human(now - before)

                    ec2_status.append(dict(code=code, desc=desc, ins_name=ins_name,
                                                 ins_id=ins_id, after=after, before=before))
            '''
            ec2_status.append(dict(code='ins-stop', desc='description',
                                   ins_name='instance name',
                                   ins_id='instance_id',
                                   after='3 days'))
            '''
        # Set the value in cache
        cache.set(ec2_events_key, ec2_status)

    else:
        LOG.info("Fetching values for instance statuses from cache - %s", region_name)
    return ec2_status


def instances_sch_events_all_regions(request, **kwargs):
    """
    Fetches instance information (scheduled events) in all the regions
    :param request:
    :return: A dictionary with key=regionName and value=List of event entries
    """
    ret = {}
    for region in AWS_REGIONS:
        r = instance_sch_events_region(request, region.name)
        ret[region.name] = r
    return ret


def resource_usage_statistics(request, resource_type, resource_id,
                              start_time, end_time, period,
                              region, in_json=True, **kwargs):

    data = _aws_helper.cloudwatch_metric_statistics(region=region,
                                                    period=period,
                                                    start_time=start_time,
                                                    end_time=end_time,
                                                    resource_type='ec2',
                                                    metric_name='CPUUtilization',
                                                    statistics='Average',
                                                    resource_id=resource_id)

    if in_json:
        data = json.dumps(data, default=datetime_json_encoder)

    return data


def instance_details(request, ins_id, region, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    ec2_cache_key = aws_cache_key(project_id, region=region, aws_service="ec2")
    ins_list = cache.get(ec2_cache_key)


    for i in ins_list:
        if i.id == ins_id:
            LOG.info("Found instance %s in region %s (cache)" % (ins_id, region))
            return serialize_instance(i)

    LOG.info("Not Found instance %s in region %s (cache)" % (ins_id, region))
    return None


def resource_details(request, resource_id, resource_type, region, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    # All resources have generic logic of serializing now. EC2 was already there.
    # ToDo Discuss and change ec2 logic to new as well.

    if resource_type == "ec2":
        return instance_details(request, resource_id, region, project_id=project_id)

    resource_cache_key = aws_cache_key(project_id, region=region, aws_service=resource_type)

    resource_list = cache.get(resource_cache_key)

    for i in resource_list:
        if getattr(i, RESOURCE_PROPERTIES_MAP[resource_type]['pk']) == resource_id:
            LOG.info("Found %s %s in region %s (cache)" % (resource_type, resource_id, region))
            return serialize_resource(resource_type, i)

    LOG.info("Not Found instance %s in region %s (cache)" % (resource_id, region))
    return None


def serialize_resource(resource_type, resource):
    """
    Helper method to convert a resource to python dict and json
    :param resource : The resource in question
    :return: Python dict representation of the instance
    """
    if resource_type == "ec2":
        return serialize_instance(resource)

    if resource_type == "elb":
        return serialize_elb(resource)

    if resource_type == "ebs":
        return serialize_ebs(resource)

    if resource_type == "security_group":
        return serialize_security_group(resource)

    if resource_type == "eip":
        return serialize_eip(resource)

    if resource_type == "vpc":
        return serialize_vpc(resource)

    if resource_type == "subnet":
        return serialize_subnet(resource)

    return None


def serialize_instance(ins):
    """
    Helper method to convert an instance to python dict and json
    :param ins: The instance in question
    :return: python dict representation of the instance
    """
    d = dict(
        id=ins.id,
        name=ins.tags.get('Name', ""),
        subnet=ins.subnet_id,
        vpc=ins.vpc_id,
        groups=[x.name for x in ins.groups],
        private_ip_address=ins.private_ip_address,
        ip_address=ins.ip_address,
        key_name=ins.key_name,
        instance_type=ins.instance_type)
    return d


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
    ret_list, project_id = _aws_helper.\
        resource_changes_relationships(request=request,
                                       resource_type=resource_type,
                                       resource_id=resource_id,
                                       region=region,
                                       limit=limit, **kwargs)

    return resource_changes_diff(ret_list, project_id=project_id, region=region)


def configservice_enabled(request=None, aws_access=None, aws_secret=None):
    """
    To know if config-service is enabled for a client
    :param request: The request object containing aws_access and aws_secret
    :param aws_access: aws_access value
    :param aws_secret: aws_secret key value
    :return: Tuple (True, []) if service is enabled, Tuple (False, List of regions) otherwise
    """
    return _aws_helper.configservice_enabled(request=request,
                                             aws_access=aws_access,
                                             aws_secret=aws_secret)


def cloudtrailservice_enabled(request=None, aws_access=None, aws_secret=None):
    """
    To know if cloudtrail-service is enabled for a client
    :param request: The request object containing aws_access and aws_secret
    :param aws_access: aws_access value
    :param aws_secret: aws_secret key value
    :return: Tuple (True, []) if service is enabled, Tuple (False, List of regions) otherwise
    """
    return _aws_helper.cloudtrailservice_enabled(request=request,
                                                 aws_access=aws_access,
                                                 aws_secret=aws_secret)


def cloudtrail_events(request, region=None, attribute_key=None,
                      attribute_value=None):
    """
    Fetches cloudtrail events from AWS Helper module
    :rtype : dict
    :param request: Request object
    :param region: Region in question
    :param attribute_key: Return results matching only the key
    :param attribute_value: Value for the key
    :return: dictionary of results
    """
    project = project_from_request(request)
    ctable = CloudTrailTable()
    items = ctable.query_events(project_id=int(project.project_id))
    resp = []
    geo_conn = geo_connection()
    for item in items:
        # Check if countryCode is in the item, if not add it
        if 'countryCode' not in item.keys():
            ip = item.get('sourceIPAddress', None)
            if ip is not None:
                item['countryCode'] = country_from_ip(ip,
                                                      geo_conn=geo_conn)
        resp.append(_serialize_ctraildata(item))

    # Sort by event time
    return sorted(resp, key=itemgetter('EventTime'), reverse=True)


def _serialize_ctraildata(data):
    ret = dict(EventDetails=dict(sourceIPAddress=data['sourceIPAddress']),
               region=data['awsRegion'],
               sourceIPAddress=data['sourceIPAddress'],
               countryCode=data['countryCode'],
               EventId=data['EventId'],
               EventName=data['EventName'],
               EventTime=int(data['EventTime']),
               Resources=data.get('Resources', []),
               Username=data['Username'])
    return ret


def merge_config_dicts(dict_added, dict_removed):
    """
    Merges two dictionary into a collective response
    :param dict_added: List of items that were added
    :param dict_removed: List of items that were removed
    :return: combined list of both the lists
    """
    ret = []
    for d in dict_added:
        d_item = d.copy()
        capture_time = d['capture_time']
        for dr in dict_removed:
            if dr['capture_time'] == capture_time:
                d_item['removed'] = dr['removed']

        ret.append(d_item)

    return ret


def resource_changes_diff(jsc, region, project_id):
    """
    Finds differences in config list
    :param jsc: The dictionary with list of config changes
    :return: a list of differences in pairs of consecutive config items.
    """

    ret_added = []
    ret_removed = []

    i_map = instances_map(region=region, project_id=project_id)
    # Move forward for 'Added'
    for i in range(0, len(jsc) - 1):
        d = dict(capture_time=time_from_epoch(jsc[i]['configurationItemCaptureTime']),
                 added=[])

        # Added
        for x in jsc[i]['relationships']:
            if x not in jsc[i + 1]['relationships']:
                # Find the name for EC2 Instance and add to dict
                if x['resourceType'] == "AWS::EC2::Instance":
                    resource = i_map.get(x['resourceId'])
                    if resource:
                        x['resourceName'] = resource.get('name', "")
                d["added"].append(x)

        ret_added.extend([d])

    # Move backwards for 'Removed'
    for i in range(len(jsc) - 1, 1, -1):
        d = dict(capture_time=time_from_epoch(jsc[i - 1]['configurationItemCaptureTime']),
                 removed=[])
        # Removed
        for x in jsc[i]['relationships']:
            if x not in jsc[i - 1]['relationships']:
                # Find the name for EC2 Instance and add to dict
                if x['resourceType'] == "AWS::EC2::Instance":
                    resource = i_map.get(x['resourceId'])
                    if resource:
                        x['resourceName'] = resource.get('name', "")
                d["removed"].append(x)

        ret_removed.extend([d])
    return merge_config_dicts(dict_added=ret_added, dict_removed=ret_removed)


@use_cache
def elb_statistics(request=None, project_id=None, days=7, **kwargs):
    ret = []
    for region in AWS_REGIONS:
        ret.append(elb_statistics_region(request=request,
                                         prjoject_id=project_id,
                                         region=region.name,
                                         days=days, **kwargs))
    return ret


@use_cache
def elb_statistics_region(request=None, project_id=None, days=7,
                          region=None, **kwargs):

    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    if request:
        project = project_from_request(request, None)
        aws_access = project.aws_access
        aws_secret = project.aws_secret
    else:
        aws_access = kwargs.get('aws_access', None)
        aws_secret = kwargs.get('aws_secret', None)

    elb_cache_key = aws_cache_key(project_id, region=region, aws_service="elb")

    elb_list = cache.get(elb_cache_key)
    elb_conn = elb_connect(region,
                           aws_access_key_id=aws_access,
                           aws_secret_access_key=aws_secret)

    ret = dict(region=region, items=[])
    for elb in elb_list:
        name = elb.name
        healthy_hosts = len(elb_conn.describe_instance_health(name))
        result = _aws_helper.cloudwatch_metric_statistics(period=600,
                                                          region=region,
                                                          start_time=datetime.utcnow() - timedelta(days=days),
                                                          end_time=datetime.utcnow(),
                                                          resource_type="elb",
                                                          metric_name='RequestCount',
                                                          statistics='Sum',
                                                          resource_id=name)
        request_count = len(result)
        LOG.info("ELB instance %s has number of hosts (%s) and requests (%s)" %
                 (name, healthy_hosts, request_count))
        ret['items'].append(dict(elb_name=name,
                                 num_hosts=healthy_hosts,
                                 request_count=request_count))

    return ret


def elb_traffic_statistics_region(request=None, project_id=None, period=None,
                                  start_time=None, end_time=None, region=None,
                                  resource_name=None, **kwargs):

    d = dict()
    for metric in ELB_TRAFFIC_METRICS:

        stats = _aws_helper.cloudwatch_metric_statistics(period=period,
                                                         region=region,
                                                         start_time=start_time,
                                                         end_time=end_time,
                                                         resource_type="elb",
                                                         metric_name=metric,
                                                         statistics='Sum',
                                                         resource_id=resource_name)

        d[metric] = stats

    data = json.dumps(d, default=datetime_json_encoder)
    return data

@use_cache
def ec2_instances(request, region, **kwargs):
    """
    Helper method to get a list of ec2_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of ec2 instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    ec2_cache_key = aws_cache_key(project.project_id, region=region, aws_service="ec2")
    ec2_insts = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        ec2_insts = cache.get(ec2_cache_key)

    if ec2_insts is None:
        ec2_insts = []
        conn = ec2_connect(region,
                           aws_access_key_id=aws_access,
                           aws_secret_access_key=aws_secret)
        if conn:
            try:
                ec2_insts = conn.get_only_instances()
            except Exception as e:
                LOG.error("Exception occurred while get all EC2 instances for project id(%s)"
                          "in region (%s) : (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(ec2_cache_key, ec2_insts)

    return ec2_insts


@use_cache
def elb_instances(request, region, **kwargs):
    """
    Helper method to get a list of elb_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of elb instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    elb_cache_key = aws_cache_key(project.project_id, region=region, aws_service="elb")
    elb_insts = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        elb_insts = cache.get(elb_cache_key)

    if elb_insts is None:
        elb_insts = []
        elb_conn = elb_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        if elb_conn:
            try:
                elb_insts = elb_conn.get_all_load_balancers()
            except Exception as e:
                LOG.error("Exception occurred while get all ELB instances for project id(%s)"
                          "in region (%s) : (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(elb_cache_key, elb_insts)

    return elb_insts


@use_cache
def ebs_volumes(request, region, **kwargs):
    """
    Helper method to get a list of elb_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of elb instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    ebs_cache_key = aws_cache_key(project.project_id, region=region, aws_service="ebs")
    ebs_vols = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        ebs_vols = cache.get(ebs_cache_key)

    if ebs_vols is None:
        ebs_vols = []
        ebs_conn = ec2_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        if ebs_conn:
            try:
                ebs_vols = ebs_conn.get_all_volumes()
            except Exception as e:
                LOG.error("Exception occurred while get all EBS instances for project id(%s)"
                          "in region (%s) : (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(ebs_cache_key, ebs_vols)

    return ebs_vols


def eip_addresses(request, region, **kwargs):
    """
    Helper method to get a list of elb_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of elb instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    eip_cache_key = aws_cache_key(project.project_id, region=region, aws_service="eip")
    eip_addrs = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        eip_addrs = cache.get(eip_cache_key)

    if eip_addrs is None:
        eip_addrs = []
        eip_conn = ec2_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        if eip_conn:
            try:
                eip_addrs = eip_conn.get_all_addresses()
            except Exception as e:
                LOG.error("Exception occurred while fetching all EIP addresses for project id(%s)"
                          "in region (%s) : (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(eip_cache_key, eip_addrs)

    return eip_addrs


def security_groups(request, region, **kwargs):
    """
    Helper method to get a list of elb_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of elb instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    security_group_cache_key = aws_cache_key(project.project_id, region=region, aws_service="security_group")
    security_grps = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        security_grps = cache.get(security_group_cache_key)

    if security_grps is None:
        security_grps = []
        security_grps_conn = ec2_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        if security_grps_conn:
            try:
                security_grps = security_grps_conn.get_all_security_groups()
            except Exception as e:
                LOG.error("Exception occurred while fetching all security groups for project id(%s)"
                          "in region (%s) : (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(security_group_cache_key, security_grps)

    return security_grps


def vpc_instances(request, region, **kwargs):
    """
    Helper method to get a list of elb_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of elb instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    vpc_cache_key = aws_cache_key(project.project_id, region=region, aws_service="vpc")
    vpcs = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        vpcs = cache.get(vpc_cache_key)

    if vpcs is None:
        vpcs = []
        vpc_conn = vpc_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        if vpc_conn:
            try:
                vpcs = vpc_conn.get_all_vpcs()
            except Exception as e:
                LOG.error("Exception occurred while fetching all vpcs for project id(%s)"
                          "in region (%s) (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(vpc_cache_key, vpcs)

    return vpcs


def subnets(request, region, **kwargs):
    """
    Helper method to get a list of elb_instances, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param region: The AWS region
    :return: List of elb instances
    """

    project = project_from_request(request, None)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    subnet_cache_key = aws_cache_key(project.project_id, region=region, aws_service="subnet")
    subnet_list = None
    use_cache = kwargs.get('use_cache')

    if use_cache:
        # Fetch from aws if not present in cache
        subnet_list = cache.get(subnet_cache_key)

    if subnet_list is None:
        subnet_list = []
        vpc_conn = vpc_connect(region,
                               aws_access_key_id=aws_access,
                               aws_secret_access_key=aws_secret)
        if vpc_conn:
            try:
                subnet_list = vpc_conn.get_all_subnets()
            except Exception as e:
                LOG.error("Exception occurred while fetching all subnets for project id(%s)"
                          "in region (%s) : (%s)" % (project.project_id, region, str(e)))
            finally:
                cache.set(subnet_cache_key, subnet_list)

    return subnet_list


def ebs_snapshot_all_regions(project_id=None, request=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    if project_id:
        project = ProjectAWS.objects.get(pk=project_id)
        request = gen_fake_req(project.name, project.id,
                               project.access_key, project.secret)

    for region in AWS_REGIONS:
        ebs_snapshots_for_region(request, region)


def ebs_snapshots_for_region(request, region, **kwargs):
    """
    Helper method to fetch list of ebs snapshots in cache, if the result does not
    exist in the cache, then it is fetched from the backend
    :param request:  The request object, containing project and aws keys
    :param project_id:  the project_id to get snapshots for
    """
    project = project_from_request(request, region)
    aws_access = project.aws_access
    aws_secret = project.aws_secret

    ebs_cache_key = aws_cache_key(project.project_id, region=region.name, aws_service="ebs")
    ebs_volumes = cache.get(ebs_cache_key)

    if not valid_cache_item(ebs_volumes):
        LOG.info("Cache for EBS volume does not exists hence, can not set cache for snapshots")
        return

    volume_cache_keys = {}
    volume_snapshots = {}

    conn = ec2_connect(region.name,
                       aws_access_key_id=aws_access,
                       aws_secret_access_key=aws_secret)

    ebs_snapshots = []

    try:
        ebs_snapshots = conn.get_all_snapshots()
    except Exception as e:
        LOG.error("Error while fetching EBS snapshots Project-region(%s:%s),\
              fetching values from AWS %s" % (project.project_id, region.name, e))

    if ebs_snapshots:
        for snapshot in ebs_snapshots:
            if snapshot.volume_id in volume_snapshots.keys():
                volume_snapshots[snapshot.volume_id].append(snapshot)
            else:
                volume_snapshots[snapshot.volume_id] = [snapshot]

    for volume_id in volume_snapshots:
        if volume_snapshots[volume_id]:
            if volume_snapshots[volume_id]:
                cache.set(aws_cache_key_linked_resources(project.project_id, region.name, "ebs", volume_id, 'snapshot'),
                          volume_snapshots[volume_id][:10], settings.EBS_SNAPSHOTS_TIMEOUT)

def get_snapshots_for_volume(request, region_name, volume_id):
    project = project_from_request(request, region_name)
    ebs_snapshot_cache_key = aws_cache_key_linked_resources(project.project_id, region_name, "ebs", volume_id, 'snapshot')

    snapshots_for_vol = cache.get(ebs_snapshot_cache_key)

    if snapshots_for_vol:
        snapshots_for_vol = snapshots_for_vol[:SNAPSHOT_LIMIT]

    return snapshots_for_vol


def snapshot_available(request, region_name, volume_id):
    project = project_from_request(request, region_name)
    ebs_snapshot_cache_key = aws_cache_key_linked_resources(project.project_id, region_name, "ebs", volume_id, 'snapshot')

    snapshots_for_vol = cache.get(ebs_snapshot_cache_key)

    if valid_cache_item(snapshots_for_vol):
        if snapshots_for_vol:
            return True
        else:
            return False

    return None

def update_route53_information(request, project_id=None):
    if project_id:
        project = ProjectAWS.objects.get(pk=project_id)
        aws_access = project.access_key
        aws_secret = project.secret

        hosted_zones = {}
        try:
            rout53_connection = get_conn(conn_type="route53", request=None, aws_access=aws_access, aws_secret=aws_secret)
            hosted_zones = rout53_connection.get_all_hosted_zones()["ListHostedZonesResponse"]["HostedZones"]
        except Exception as e:
            LOG.error(
                "Exception occurred while getting hosted zones for route53 domain information for project id(%s) : (%s)"
                % (project_id, str(e))
            )

        context_data = dict()
        context_data["route53"] = {}
        for hosted_zone in hosted_zones:
            domain_name = str(hosted_zone["Name"][:-1])  # remove trailing "."

            parsed_whois_data, expire_days, is_expire = parse_whois_data(domain_name)
            serialized_whois_data = json.dumps(parsed_whois_data,
                                               default=datetime_json_encoder)

            try:
                route53, created = Route53.objects.get_or_create(project=project, domain_name=domain_name)
                content_type_id = ContentType.objects.get_for_model(Route53).id

                if created:
                    # if entry is new then store the information only
                    route53.is_expire = is_expire
                    route53.whois_data = serialized_whois_data
                    route53.save()
                    continue
                else:
                    if is_expire and is_expire != route53.is_expire:
                        route53.is_expire = is_expire
                        route53.save()

                    if route53.is_expire:
                        LOG.info("If domain is already Expire then skip it.")
                        continue

                    # compare whole dictionary for change
                    # encode/decode the dict for comaprison, for format consistency
                    parsed_encoded_data = json.loads(serialized_whois_data)
                    changed_data = compare_dict(parsed_encoded_data,
                                                json.loads(route53.whois_data))

                    # update whois data in DB
                    route53.whois_data = serialized_whois_data
                    route53.save()

                expire_days = expire_days if expire_days is not None and \
                                             settings.ROUTE53_DOMAIN_EXPIRY_DAYS_NOTIFICATION >= expire_days else None

                if expire_days or changed_data["removed_items"] or changed_data["added_items"]:
                    context_data["route53"][domain_name] = {
                        "added_items": changed_data["added_items"],
                        "removed_items": changed_data["removed_items"],
                        "expire_days": expire_days
                    }
            except Exception as e:
                LOG.error("Exception occurred while checking route53 domain information for project id(%s)"
                          " : (%s)" % (project_id, str(e)))

        if context_data["route53"]:
            project_content_type_id= ContentType.objects.get_for_model(ProjectAWS).pk
            project_object_id = project_id
            create_notification_signal.send(sender=route53, content_type_id=content_type_id,
                                            content_type_object_id=-1, context_data=context_data,
                                            project_content_type_id=project_content_type_id,
                                            project_object_id=project_object_id)


def update_rds_events(request, project_id=None):
    if project_id:
        project = ProjectAWS.objects.get(pk=project_id)
        aws_access = project.access_key
        aws_secret = project.secret

        for region in rds_regions():

            try:
                rds_connection = get_conn(conn_type="rds", request=None, region=region, aws_access=aws_access,
                                          aws_secret=aws_secret)
            except Exception as e:
                LOG.error(
                    "Exception occurred while connecting RDS for project id(%s) : (%s)"
                    % (project_id, str(e))
                )
                continue

            try:
                last_event = AwsRds.objects.filter(project=project).latest('event_date')
            except AwsRds.DoesNotExist:
                last_event = None

            start_time = None
            if last_event:
                start_time = last_event.event_date

            marker = None
            while True:
                try:
                    rds_events = rds_connection.describe_events(start_time=start_time, marker=marker)

                    if 'Error' in rds_events:
                        LOG.error(
                            "Exception occurred while getting RDS events for project id(%s) : (%s)"
                            % (project_id, rds_events['Error'])
                        )
                        break

                    rds_events = rds_events['DescribeEventsResponse']['DescribeEventsResult']

                    marker = rds_events['Marker']
                    events = rds_events['Events']

                    for event in events:
                        event_date = datetime.utcfromtimestamp(event['Date']).strftime('%Y-%m-%dT%H:%M:%S')
                        rds_event, is_new = AwsRds.objects.get_or_create(project=project,
                                                                      event_date=event_date,
                                                                      message=event['Message'],
                                                                      source_identifier=event['SourceIdentifier'],
                                                                      source_type=event['SourceType'],
                                                                      event_category=event['EventCategories'][0])
                    if not marker:
                        break
                except Exception as e:
                    LOG.error(
                        "Exception occurred while getting RDS events for project id(%s) : (%s)"
                        % (project_id, str(e))
                    )

                    break