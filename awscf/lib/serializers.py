from boto.ec2.snapshot import Snapshot
import serpy
from libs.consts import SUBNET_PROPERTIES, SECURITY_GROUP_PROPERTIES, VPC_PROPERTIES, EIP_PROPERTIES, ELB_PROPERTIES, \
    EBS_VOLUME_PROPERTIES


class SnapshotSerializer(serpy.Serializer):

    id = serpy.StrField()
    volume_id = serpy.StrField()
    status = serpy.StrField()
    progress = serpy.StrField()
    start_time = serpy.StrField()
    owner_id = serpy.StrField()
    owner_alias = serpy.StrField()
    volume_size = serpy.StrField()
    description = serpy.StrField()
    encrypted = serpy.StrField()


def serialize_ip_permissions(ip):
    d = dict(ip_protocol=ip.ip_protocol,
             from_port=ip.from_port,
             to_port=ip.to_port,
             grants=str(ip.grants))

    return d


def serialize_security_group(sg):
    d = dict()

    for tag in SECURITY_GROUP_PROPERTIES:
        d[tag] = getattr(sg, tag)

    d['rules'] = [serialize_ip_permissions(ip) for ip in sg.rules]
    return d


def serialize_subnet(subnet):
    d = dict()

    for tag in SUBNET_PROPERTIES:
        d[tag] = getattr(subnet, tag)
    return d


def serialize_vpc(vpc):
    d = dict()

    for tag in VPC_PROPERTIES:
        d[tag] = getattr(vpc, tag)
    return d


def serialize_eip(eip):
    d = dict()

    for tag in EIP_PROPERTIES:
        d[tag] = getattr(eip, tag)

    return d


def serialize_elb_healthcheck(hc):
    d = dict(access_point=str(hc.access_point),
             interval = hc.interval,
             target = hc.target,
             healthy_threshold=hc.healthy_threshold,
             timeout = hc.timeout,
             unhealthy_threshold = hc.unhealthy_threshold)
    return d


def serialize_elb(elb):
    d = dict()

    for tag in ELB_PROPERTIES:
        d[tag] = getattr(elb, tag)

    d['listeners'] = str(elb.listeners)
    d['healthcheck'] = serialize_elb_healthcheck(elb.health_check)
    d['policies'] = str(elb.policies)
    d['instances'] = [instance_info.id for instance_info in elb.instances]
    d['availability_zones'] = elb.availability_zones
    d['security_groups'] = elb.security_groups
    return d


def serialize_ebs(ebs):
    d = dict()

    for tag in EBS_VOLUME_PROPERTIES:
        d[tag] = getattr(ebs, tag)
    return d