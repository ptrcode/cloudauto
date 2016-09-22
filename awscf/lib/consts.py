HEALTHCHECK_TYPES_ALL = ['HTTP', 'HTTPS', 'HTTP_STR_MATCH',
                         'HTTPS_STR_MATCH', 'TCP']
HEALTHCHECK_TYPES = ['HTTP', 'HTTPS', 'TCP']
REQUEST_INTERVAL = [10, 30]
FAILURE_THRESHOLD = [x for x in range(1, 11)]
STATISTICS = ['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum']
COMPARISON = ['>=', '>', '<', '<=']
UNIT = [ 'None', 'Seconds', 'Microseconds', 'Milliseconds', 'Bytes',
        'Kilobytes', 'Megabytes', 'Gigabytes', 'Terabytes',
        'Bits', 'Kilobits', 'Megabits', 'Gigabits',
        'Terabits', 'Percent', 'Count', 'Bytes/Second',
        'Kilobytes/Second', 'Megabytes/Second',
        'Gigabytes/Second', 'Terabytes/Second',
        'Bits/Second', 'Kilobits/Second', 'Megabits/Second',
        'Gigabits/Second', 'Terabits/Second', 'Count/Second']
PERIOD_TUPLE = [(60, '1 Minute'), (300, '5 Minutes'), (900, '15 Minutes'),
        (3600, '1 Hour'), (21600, '6 Hours'), (86400, '1 Day')]

EBS_VOLUME_PROPERTIES = ['id', 'create_time', 'status', 'size', 'snapshot_id', 'zone', 'type', 'iops', 'encrypted']

ELB_PROPERTIES = ['name', 'dns_name', 'created_time', 'canonical_hosted_zone_name', 'canonical_hosted_zone_name_id',
                  'subnets', 'vpc_id']

EIP_PROPERTIES = ['public_ip', 'instance_id', 'domain' , 'allocation_id', 'association_id', 'network_interface_id',
                  'network_interface_owner_id', 'private_ip_address']

VPC_PROPERTIES = ['id', 'dhcp_options_id', 'state', 'cidr_block', 'is_default', 'instance_tenancy']

SUBNET_PROPERTIES = ['id', 'vpc_id', 'state', 'cidr_block', 'available_ip_address_count', 'availability_zone']

SECURITY_GROUP_PROPERTIES = ['id', 'vpc_id', 'owner_id', 'name']

RESOURCE_PROPERTIES_MAP = {'ebs': {
                                'properties': EBS_VOLUME_PROPERTIES,
                                'pk': 'id',
                                'tag' : 'elastic block store'
                            },
                           'elb': {
                               'properties': ELB_PROPERTIES,
                               'pk': 'name',
                               'tag' : 'load balancer'
                           },
                           'eip': {
                               'properties': EIP_PROPERTIES,
                               'pk': 'public_ip',
                               'tag' : 'elastic ip',
                           },
                           'vpc': {
                               'properties': VPC_PROPERTIES,
                               'pk': 'id',
                               'tag' : 'vpc',
                           },
                           'subnet' : {
                               'properties' : SUBNET_PROPERTIES,
                               'pk' : 'id',
                               'tag' : 'subnet'
                           },
                           'security_group' : {
                               'properties' : SECURITY_GROUP_PROPERTIES,
                               'pk' : 'id',
                               'tag' : 'security group'
                           }
}


BROWSER_CACHE_VERSION = '0.1.1' # major.minor.patch - Not to worried about naming convention, but I thought it would look nicer?



