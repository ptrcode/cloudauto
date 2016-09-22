import json
import threading


def run_in_thread(fn):
    def run(*k, **kw):
        t = threading.Thread(target=fn, args=k, kwargs=kw)
        t.start()
    return run


class ObjectDict(dict):
    """ Helper class to access dictionary items easily with
    '.' notation
    """
    def __getattr__(self, key):
        if key in self:
            return self[key]
        return None

    def __setattr__(self, key, value):
        self[key] = value


def project_from_request(request, region_name=None):
    """ Helper function to get project info from request/session
    """
    project = json.loads(request.session['project'])
    project_id = request.session['project_id']
    aws_access = project['access_key']
    aws_secret = project['secret']

    region_cache_key = None
    if region_name:
        region_cache_key = "%s_%s" % (project['name'],
                                      region_name)

    return ObjectDict(aws_access=aws_access,
                      aws_secret=aws_secret,
                      project_id=project_id,
                      region_cache_key=region_cache_key)


def aws_cache_key(project_id, region, aws_service, service_id=None):
    if service_id:
        aws_service_key = "%s#%s" % (aws_service, service_id)
    else:
        aws_service_key = "%s" % aws_service
    return "project#%s:aws:region#%s:%s" % (project_id, region, aws_service_key)


def aws_cache_key_linked_resources(project_id, region, aws_service, resource_id, nested_resource_type, service_id=None):

    if service_id:
        aws_service_key = "%s#%s" % (aws_service, service_id)
    else:
        aws_service_key = "%s" % aws_service

    aws_cache_key = "project#%s:aws:region#%s:%s" % (project_id, region, aws_service_key)

    return "%s:%s:%s" % (aws_cache_key, resource_id, nested_resource_type)

def elastic_cache_key(project_id, aws_service, service_id=None):
    if service_id:
        aws_service_key = "%s_%s" % (aws_service, service_id)
    else:
        aws_service_key = "%s" % aws_service
    return "project_%s:aws:%s" % (project_id, aws_service_key)


def gen_fake_req(name, project_id, aws_access, aws_secret):
    return  ObjectDict(session=dict(project_id=str(project_id),
                                    project=json.dumps(dict(access_key=aws_access, secret=aws_secret, name=name))))