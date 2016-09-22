import json
from boto.vpc import subnet
from django.conf import settings
from django.core.cache import cache
from elasticsearch import helpers
from elasticsearch.client import Elasticsearch
from elasticsearch.exceptions import TransportError
from .base import project_from_request, run_in_thread, aws_cache_key
from .aws import AWS_REGIONS
from walrus import Database
import logging
from libs.aws import serialize_resource
from libs.base import elastic_cache_key

LOG = logging.getLogger(__name__)

ec2_tags = ['ins_id', 'ins_name', 'private_ip_address', 'ip_address']


def namespace(project_id):
    ac_key_tag = 'ac_%s_ec2' % project_id
    return ac_key_tag


def autocomplete_elastic_tags(request):
    client = Elasticsearch(hosts=settings.ELASTIC_SEARCH_NODES)
    index_name = elastic_cache_key(request.session['project_id'], 'ec2')

    if not client.indices.exists(index_name):
        try:
            populate_elastic_search(project_id=request.session['project_id'])
        except:
            import traceback
            LOG.error("Cannot build index: %s" % traceback.format_exc())
            raise Exception('Cache values not present')

    return dict(id='ins_id', name='ins_name',
                private_ip_address='private_ip_address',
                ip_address='ip_address')


def populate_ec2_indexes(request=None, project_id=None):

    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'ec2')
    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing elastic search for project : {0} region : "
                 "{1}".format(project_id, reg.name))
        region = reg.name

        ec2_cache_key = aws_cache_key(project_id, region, aws_service="ec2")

        ins_list = cache.get(ec2_cache_key)

        for i in ins_list:
            # Generate key for each instance (i.id)
            # Generate Metadata
            # obj_type = "ec_instance_ids"
            # title = id/name/private_ip/public_ip
            # Put it to elastic index

            obj_id = str(i.id) if i.id else None
            id_title = str(i.id) if i.id else None

            # Handle the case when name not assigned to an instance

            if 'Name' in i.tags.keys():
                name_title = str(i.tags['Name'])
            else:
                name_title = None

            prip_title = str(i.private_ip_address) if i.private_ip_address else None
            puip_title = str(i.ip_address) if i.ip_address else None

            metadata = dict(ins_id=str(i.id), region=str(region), resource_id=str(i.id), resource_type="ec2")

            if obj_id:
                id_metadata = metadata.copy()
                id_metadata['title'] = obj_id
                id_metadata['tag'] = 'id'
                document_body = dict(obj_id=obj_id,
                                     title=obj_id,
                                     data=id_metadata,
                                     obj_type='ec2_instance_id')
                action = {
                    "_index": index_name,
                    "_type": "instance_id",
                    "_source": document_body
                }

                obj_list.append(action)

            if name_title:
                name_metadata = metadata.copy()
                name_metadata['title'] = name_title
                name_metadata['tag'] = 'name'

                document_body = dict(obj_id=obj_id,
                                     title=name_title,
                                     data=name_metadata,
                                     obj_type='ec2_instance_name')

                action = {
                    "_index": index_name,
                    "_type": "name_title",
                    "_source": document_body
                }

                obj_list.append(action)

            if prip_title:
                prip_metadata = metadata.copy()
                prip_metadata['title'] = prip_title
                prip_metadata['tag'] = 'private_ip_address'

                document_body = dict(obj_id=obj_id,
                                     title=prip_title,
                                     data=prip_metadata,
                                     obj_type='private_ip')
                action = {
                    "_index": index_name,
                    "_type": "prip_title",
                    "_source": document_body
                }

                obj_list.append(action)

            if puip_title:
                puip_metadata = metadata.copy()
                puip_metadata['title'] = puip_title
                puip_metadata['tag'] = 'ip_address'

                document_body = dict(obj_id=obj_id,
                                     title=puip_title,
                                     data=puip_metadata,
                                     obj_type='public_ip')

                action = {
                    "_index": index_name,
                    "_type": "puip_title",
                    "_source": document_body
                }

                obj_list.append(action)
    return obj_list


def populate_ebs_indexes(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'ec2')

    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing ebs volumes for project : {0} region : "
                 "{1}".format(project_id, reg.name))

        region = reg.name

        ebs_cache_key = aws_cache_key(project_id, region, aws_service='ebs')
        ebs_index_name = elastic_cache_key(project_id, 'ebs')

        ebs_volumes = cache.get(ebs_cache_key)


        for ebs_volume in ebs_volumes:

            ebs_tags = ['id', 'create_time', 'status', 'size', 'snapshot_id', 'zone', 'type', 'iops', 'encrypted']

            volume_dict = dict(title=ebs_volume.id, tag="id", region=region)
            volume_dict.update(resource_id=ebs_volume.id, resource_type="ebs")

            document_body = dict(obj_id=ebs_volume.id,
                                 title=ebs_volume.id,
                                 data=volume_dict,
                                 obj_type='ebs')

            action = {
                    "_index": ebs_index_name,
                    "_type": "ebs",
                    "_source": document_body
                }

            obj_list.append(action)

    return obj_list


def populate_elb_indexes(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'elb')

    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing elbs for project : {0} region : "
                 "{1}".format(project_id, reg.name))

        region = reg.name

        ebs_cache_key = aws_cache_key(project_id, region, aws_service='elb')
        elb_index_name = elastic_cache_key(project_id, 'elb')

        elbs = cache.get(ebs_cache_key)


        for elb in elbs:

            volume_dict = dict(title=elb.name, tag="name", region=region)
            volume_dict.update(resource_id=elb.name, resource_type="elb")

            document_body = dict(obj_id=elb.name,
                                 title=elb.name,
                                 data=volume_dict,
                                 obj_type='elb')

            action = {
                    "_index": elb_index_name,
                    "_type": "elb",
                    "_source": document_body
                }

            obj_list.append(action)

    return obj_list


def populate_eip_indexes(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'eip')

    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing eips for project : {0} region : "
                 "{1}".format(project_id, reg.name))

        region = reg.name

        eip_cache_key = aws_cache_key(project_id, region, aws_service='eip')
        eip_index_name = elastic_cache_key(project_id, 'eip')

        eips = cache.get(eip_cache_key)

        for eip in eips:

            volume_dict = dict(title=eip.public_ip, tag="eip", region=region)
            volume_dict.update(resource_id=eip.public_ip, resource_type="eip")

            document_body = dict(obj_id=eip.public_ip,
                                 title=eip.public_ip,
                                 data=volume_dict,
                                 obj_type='eip')

            action = {
                    "_index": eip_index_name,
                    "_type": "eip",
                    "_source": document_body
                }

            obj_list.append(action)

    return obj_list


def populate_vpc_indexes(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'vpc')

    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing vpcs for project : {0} region : "
                 "{1}".format(project_id, reg.name))

        region = reg.name

        vpc_cache_key = aws_cache_key(project_id, region, aws_service='vpc')
        vpc_index_name = elastic_cache_key(project_id, 'vpc')

        vpcs = cache.get(vpc_cache_key)

        for vpc in vpcs:
            volume_dict = dict(title=vpc.id, tag="id", region=region)
            volume_dict.update(resource_id=vpc.id, resource_type="vpc")

            document_body = dict(obj_id=vpc.id,
                                 title=vpc.id,
                                 data=volume_dict,
                                 obj_type='vpc')

            action = {
                    "_id" : vpc.id,
                    "_index": vpc_index_name,
                    "_type": "vpc",
                    "_source": document_body
                }

            obj_list.append(action)

    return obj_list

def populate_subnet_indexes(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'subnet')

    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing subnets for project : {0} region : "
                 "{1}".format(project_id, reg.name))

        region = reg.name

        subnet_cache_key = aws_cache_key(project_id, region, aws_service='subnet')
        subnet_index_name = elastic_cache_key(project_id, 'subnet')

        subnets = cache.get(subnet_cache_key)

        for subnet in subnets:

            volume_dict = dict(title=subnet.id, tag="id", region=region)
            volume_dict.update(resource_id=subnet.id, resource_type="subnet")

            document_body = dict(obj_id=subnet.id,
                                 title=subnet.id,
                                 data=volume_dict,
                                 obj_type='subnet')

            action = {
                    "_id" : subnet.id,
                    "_index": subnet_index_name,
                    "_type": "subnet",
                    "_source": document_body
                }

            obj_list.append(action)

    return obj_list


def populate_security_group_indexes(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'subnet')

    obj_list = []

    for reg in AWS_REGIONS:
        LOG.info("Indexing security groups for project : {0} region : "
                 "{1}".format(project_id, reg.name))

        region = reg.name

        security_group_cache_key = aws_cache_key(project_id, region, aws_service='security_group')
        security_group_index_name = elastic_cache_key(project_id, 'security_group')

        security_groups = cache.get(security_group_cache_key)

        for security_group in security_groups:
            volume_dict = dict(title=security_group.id, tag="id", region=region)
            volume_dict.update(resource_id=security_group.id, resource_type="security_group")

            document_body = dict(obj_id=security_group.id,
                                 title=security_group.id,
                                 data=volume_dict,
                                 obj_type='security_group_id')

            action = {
                    "_id" : security_group.id,
                    "_index": security_group_index_name,
                    "_type": "security_group_id",
                    "_source": document_body
                }


            obj_list.append(action)

            volume_dict = dict(title=security_group.name, tag="name", region=region)
            volume_dict.update(resource_id=security_group.id, resource_type="security_group")

            document_body = dict(obj_id=security_group.name,
                             title=security_group.name,
                             data=volume_dict,
                             obj_type='security_group_name')

            action = {
                "_id" : security_group.id,
                "_index": security_group_index_name,
                "_type": "security_group_name",
                "_source": document_body
                }

            obj_list.append(action)

    return obj_list


def populate_elastic_search(request=None, project_id=None):
    # 1. Create tag from "project_id" + "type" + "tag"
    #2. Get from all region cache, instances.
    #3. Generate index for each project
    #4. List the tag in the respective project index and doc type.
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'ec2')
    ebs_index_name = elastic_cache_key(project_id, 'ebs')
    elb_index_name = elastic_cache_key(project_id, 'elb')
    eip_index_name = elastic_cache_key(project_id, 'eip')
    vpc_index_name = elastic_cache_key(project_id, 'vpc')
    subnet_index_name = elastic_cache_key(project_id, 'subnet')
    security_group_index_name = elastic_cache_key(project_id, 'security_group')

    client = Elasticsearch(hosts=settings.ELASTIC_SEARCH_NODES)

    try:
        # First try to delete the index for this project if already exists
        client.indices.delete(
            index=[index_name, ebs_index_name, elb_index_name, eip_index_name, vpc_index_name, security_group_index_name, subnet_index_name])
    except TransportError as e:
        LOG.error("Error while deleting the index {0} error : "
                  "{1}".format(index_name, e))

    try:
        obj_list = []
        obj_list.extend(populate_ec2_indexes(request=request, project_id=project_id))
        obj_list.extend(populate_ebs_indexes(request=request, project_id=project_id))
        obj_list.extend(populate_elb_indexes(request=request, project_id=project_id))
        obj_list.extend(populate_eip_indexes(request=request, project_id=project_id))
        obj_list.extend(populate_vpc_indexes(request=request, project_id=project_id))
        obj_list.extend(populate_subnet_indexes(request=request, project_id=project_id))
        obj_list.extend(populate_security_group_indexes(request=request, project_id=project_id))

        if obj_list:
            elastic_index_res = helpers.bulk(client, obj_list, stats_only=True)  # Index elastic search in bulk
            LOG.info("Indexed {0} items Failed {1} items".format(elastic_index_res[0], elastic_index_res[1]))

    except Exception as e:
        LOG.error("Error while indexing project {0} error {1}".format(project_id, e))


def search_fuzzy(request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    index_name = elastic_cache_key(project_id, 'ec2')
    ebs_index_name = elastic_cache_key(project_id, 'ebs')
    elb_index_name = elastic_cache_key(project_id, 'elb')
    eip_index_name = elastic_cache_key(project_id, 'eip')
    vpc_index_name = elastic_cache_key(project_id, 'vpc')
    subnet_index_name = elastic_cache_key(project_id, 'subnet')
    security_group_index_name = elastic_cache_key(project_id, 'security_group')

    st = request.GET.get('st', None)
    client = Elasticsearch(hosts=settings.ELASTIC_SEARCH_NODES)

    query = {
        "query": {
            "query_string": {
                "fields" : ["title"],
                "query": "*" + st + "*",
            }
        },
    }

    total = client.search(
        index=[index_name, ebs_index_name, elb_index_name, eip_index_name, vpc_index_name, subnet_index_name,
               security_group_index_name],
        doc_type=["instance_id", "name_title",
                  "prip_title", "puip_title", "ebs", "eip", "elb", "vpc", "subnet", "security_group_id",
                  "security_group_name"],
        body=query, ignore_unavailable=True)['hits']['total']

    # Get Total search result and set size parameter equal to that, to get all results
    # ToDo Discuss and Optimize
    query['size'] = total

    search_results = client.search(
        index=[index_name, ebs_index_name, elb_index_name, eip_index_name, vpc_index_name, subnet_index_name,
               security_group_index_name],
        doc_type=["instance_id", "name_title",
                  "prip_title", "puip_title", "ebs", "eip",  "elb", "vpc", "subnet", "security_group_id",
                  "security_group_name"],
        body=query, ignore_unavailable=True)
    return search_results


def query_cache(key=None, st=None, request=None, project_id=None):
    project_id = project_id if project_id \
        else json.loads(request.session['project_id'])

    database = Database()
    ac_key_tag = namespace(project_id)
    ac_ids = database.autocomplete(namespace=ac_key_tag)
    return ac_ids.search(str(st))

