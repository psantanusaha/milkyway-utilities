from redis_util import get_global_parameters, RedisConnectionFailure, set_key_value
from spanva_logger import AgentLogger
import logging
import magic
import json
import requests
from email import utils
import time
import datetime
import base64
import hmac
import hashlib

import md5

import urllib

from commons import prepare_rotating_file_logger

from logs_uploader import api_get_auth_headers

# set the logger class to our custom class
logging.setLoggerClass(AgentLogger)

#setup logger for config manager.
logger = logging.getLogger('spanva_diagnostic')
prepare_rotating_file_logger(logger, None, "/var/log/elastica/spanva_diagnostic.log", logging.DEBUG)


def do_signed_request(key_id, key_secret, host_url, method, resource_path, content_type, content=None):
    """
    only GET, POST and PUT support currently
    """

    verb = method.upper()
    string_to_sign = verb + "\n"

    if content:
        string_to_sign += md5.new(content).hexdigest()

    string_to_sign += "\n"
    string_to_sign += content_type + "\n"
    el_date = utils.formatdate(time.mktime(datetime.datetime.now().timetuple()))
    string_to_sign += "x-ela-date:" + el_date + "\n"

    if not resource_path.startswith("/"):
        resource_path = "/" + resource_path

    # if there is no query string then end the resource path with a slash, if
    # its not there
    if resource_path.find('?') == -1 and not resource_path.endswith("/"):
        resource_path += "/"

    string_to_sign += resource_path + "\n"

    headers = {}
    headers['content-type'] = content_type
    headers['x-ela-date'] = el_date
    headers['Authorization'] = "ELA " + key_id + ":" + urllib.quote(base64.b64encode(
        hmac.new(key_secret.encode('utf-8'), string_to_sign, hashlib.sha1).digest()))

    if host_url.endswith("/"):
        host_url = host_url[0:-1]

    if verb == "GET":
        return requests.get(host_url + resource_path, headers=headers, timeout=30)
    elif verb == "POST":
        return requests.post(host_url + resource_path, headers=headers, data=content, timeout=30)
    elif verb == "PUT":
        return requests.put(host_url + resource_path, headers=headers, data=content, timeout=30)
    elif verb == "PATCH":
        return requests.patch(host_url + resource_path, headers=headers, data=content, timeout=30)
    else:
        raise Exception("Unsupport method provided, cannot perform a signed request.")

def api_get_auth_headers(method, discovery_ds_id='', resource_path='', content_type=None, content=None, upload_type='success', spool_subfolder='', amz_headers={}):
    
    headers = {}

    post_body = {}
    post_body['method'] = method
    post_body['resource_path'] = resource_path
    post_body['upload_type'] = upload_type
    post_body['discovery_ds_id'] = discovery_ds_id
    post_body['spool_subfolder'] = spool_subfolder
    post_body['content_type'] = content_type
    post_body['content'] = content
    post_body['amz_headers'] = amz_headers

    try:
        params = get_global_parameters()
    except RedisConnectionFailure:
        return headers

    print params
    print post_body
    
    # agent_key_id = params['agent_key_id']
    # agent_key_secret = params['agent_key_secret']
    # api_endpoint = params['api_endpoint']
    # tenant_db = params['tenant_domain']  

    agent_key_id = "3f5bf8ace65111eab0d202e3173504a7"
    agent_key_secret = "c2AD04Gee34RkXHw8wU2Rt3fYbvLhYGBa0q6fvH7j8U"
    api_endpoint = "https://api-eoe.elastica-inc.com"
    tenant_db = "elasticaco"
     

    if not (api_endpoint and tenant_db and agent_key_id and agent_key_secret):
        # return empty headers, request will fail.
        return headers

    resp = do_signed_request(agent_key_id, agent_key_secret, api_endpoint+"/", "POST", "/"+tenant_db+"/api/admin/v1/sign_request", content_type="application/json", content=json.dumps(post_body))

    if resp.status_code == 200:
        result = json.loads(resp.text)
        if result['status'] == 'success':
            return (result['headers'], result['dest_url'])

    return (headers, '')


def testing_api_call() :
    upload_ctx = {'discovery_ds_id' : 'some_dummy_id'}
    source_file_path = "/tmp/test_file_1.gz"
    file_name = source_file_path

    slash_index = source_file_path.rfind('/')
    if slash_index != -1:
        file_name = source_file_path[slash_index+1:]

    file_name = urllib.quote_plus(file_name)

    mime = magic.Magic(mime=True)
    file_content_type = mime.from_file(source_file_path)
    

    amz_headers = {}
    (headers, dest_url) = api_get_auth_headers("POST", upload_ctx.get('discovery_ds_id', ''), file_name+"?uploads", "application/json",
                                 upload_type=upload_ctx.get('upload_type', 'success'), spool_subfolder=upload_ctx.get('spool_subfolder'), amz_headers=amz_headers)

    print headers
    print dest_url

    resp = requests.post(dest_url+file_name+"?uploads", headers=headers, data=None)
    print resp.text



if __name__ == "__main__":
    testing_api_call()

