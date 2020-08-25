import logging
import magic
import json
import requests
from email import utils
import time
import datetime
import base64
import math
import hmac
import hashlib
import md5
import re
from urlparse import urlparse
from multiprocessing.pool import ThreadPool
import os
import httplib
import threading
import urllib

gbl_parts_upload_status = {}


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


def api_get_auth_headers(method, discovery_ds_id='', resource_path='', content_type=None, content=None,
                         upload_type='success', spool_subfolder='', amz_headers={}):
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

    print post_body

    # agent_key_id = params['agent_key_id']
    # agent_key_secret = params['agent_key_secret']
    # api_endpoint = params['api_endpoint']
    # tenant_db = params['tenant_domain']

    # santanu-eoe-spanva-triaging
    agent_key_id = "3f5bf8ace65111eab0d202e3173504a7"
    agent_key_secret = "c2AD04Gee34RkXHw8wU2Rt3fYbvLhYGBa0q6fvH7j8U"
    api_endpoint = "https://api-eoe.elastica-inc.com"
    tenant_db = "elasticaco"

    #customer spanva
    agent_key_id = "4a0359da264f11e98dff02f471746566"
    agent_key_secret = "uWwSxZa7aFd8LVAVRaIllS7WP2HtO5fd4lBq2IPUUWM"
    api_endpoint = "https://api-vip.elastica.net"
    tenant_db = "usaacom"

    if not (api_endpoint and tenant_db and agent_key_id and agent_key_secret):
        # return empty headers, request will fail.
        return headers

    resp = do_signed_request(agent_key_id, agent_key_secret, api_endpoint + "/", "POST",
                             "/" + tenant_db + "/api/admin/v1/sign_request", content_type="application/json",
                             content=json.dumps(post_body))

    if resp.status_code == 200:
        result = json.loads(resp.text)
        if result['status'] == 'success':
            return (result['headers'], result['dest_url'])

    return (headers, '')


def _upload_part(upload_ctx, file_path, file_name, upload_id, part_num, offset, bytes, resource_path, content_type, current_thread_id, max_retries=10):

    try:

        part_complete = "<Part>\n<PartNumber>{part_num}</PartNumber>\n<ETag>{etag}</ETag>\n</Part>\n"
        fp = open(file_path, 'rb')
        fp.seek(offset)
        chunk_data = fp.read(bytes)
        fp.close()

        (headers, dest_url) = api_get_auth_headers("PUT", upload_ctx.get('discovery_ds_id',''), resource_path, content_type, upload_type=upload_ctx.get('upload_type', 'success'), spool_subfolder=upload_ctx.get('spool_subfolder'))

        dest_host = ''
        dest_path = ''
        if dest_url:
            dest_host = urlparse(dest_url).netloc
            dest_path = urlparse(dest_url).path

        # caller will log the upload failed.
        if not (dest_host and dest_path):
            return None

        headers['content-length'] = str(len(chunk_data))
        headers['content-type'] = content_type

        use_proxy = False
        proxy_host = None
        proxy_port = None
        proxy_user = None
        proxy_password = None

        while max_retries:
            try:
                max_retries -= 1
                """
                we are using httplib here instead of requests, the reason why we are doing this is:
                requests either needs a whole binary file to post to the server , for chunks it can only
                work if the data is plain text. This httplib is inspired by its usage in the AWS boto library
                which works with chunked binary data.
                """

                if use_proxy:
                    requests_rootCA_file = "/usr/lib/python2.7/site-packages/requests/cacert.pem"
                    certifi_rootCA_file = "/usr/lib/python2.7/site-packages/certifi/cacert.pem"

                    # keep the same CA cert as requests; thats what we update when we import new root CA certificates
                    CA_CERTS = certifi_rootCA_file if os.path.exists(certifi_rootCA_file) else requests_rootCA_file

                    # importing it only when required
                    import httplib2

                    # PROXY_TYPE_HTTP is the right proxy type of https connection
                    conn = httplib2.HTTPSConnectionWithTimeout(dest_host, ca_certs=CA_CERTS, \
                                                                proxy_info=httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP, proxy_host, proxy_port,\
                                                                proxy_user=proxy_user, proxy_pass=proxy_password), timeout=600)
                else:
                    conn = httplib.HTTPSConnection(dest_host, timeout=600)
                conn.putrequest("PUT", dest_path+file_name+"?partNumber="+str(part_num)+"&uploadId="+str(upload_id))
                for key in headers:
                    conn.putheader(key, headers[key])
                conn.endheaders()
                conn.send(chunk_data)
                response = conn.getresponse()
                conn.close()
                if response.status == 200:
                    return part_num, part_complete.format(part_num=part_num, etag=response.getheader('etag')), current_thread_id
                else:
                    continue
            except Exception, ex:
                # wait a while, could be a temporary disconnection and then retry
                time.sleep(5)
                continue
        # upload of this part has failed.
        return None
    except Exception, ex:
        print "Exception in _upload_part function : "+str(ex)
        return None

def get_timeout_from_file_size(file_size):
    # assume very conservative 0.5Mbps connection
    # we will compute the total wait time based on file size

    # we give it a maximum of 120 hrs considering that it is the time required for uploading a
    # 13GB file over the link of .250Mbps or 26GB file over a link of .50Mbps or 52GB file over  link
    # of 1Mbps.
    # we wait a minimum of 1800 seconds no matter how small file is; otherwise we may
    # abort the upload too soon; it won't hurt us because it is used as timeout if the upload finishes soon
    # it will return sooner
    return min(120 * 3600, max(math.ceil(float(file_size * 8) / (0.5 * 1024 * 1024)), 1800))

def testing_api_call():
    global gbl_parts_upload_status

    upload_ctx = {'discovery_ds_id': 'some_dummy_id'}
    source_file_path = "/tmp/test1.txt"
    file_name = source_file_path

    slash_index = source_file_path.rfind('/')
    if slash_index != -1:
        file_name = source_file_path[slash_index + 1:]

    file_name = urllib.quote_plus(file_name)

    mime = magic.Magic(mime=True)
    file_content_type = mime.from_file(source_file_path)

    amz_headers = {}
    (headers, dest_url) = api_get_auth_headers("POST", upload_ctx.get('discovery_ds_id', ''), file_name + "?uploads",
                                               "application/json",
                                               upload_type=upload_ctx.get('upload_type', 'success'),
                                               spool_subfolder=upload_ctx.get('spool_subfolder'),
                                               amz_headers=amz_headers)

    print headers
    print dest_url

    resp = requests.post(dest_url + file_name + "?uploads", headers=headers, data=None)

    print resp.text
    if resp.status_code == 200:
        resp_xml = resp.text
        print resp_xml
        match_res = re.search("<UploadId>(.*)</UploadId>", resp_xml)

        if match_res:
            upload_id = match_res.group(1)

            source_size = os.stat(source_file_path).st_size

            bytes_per_chunk = max(int(math.sqrt(5242880) * math.sqrt(source_size)), 5242880)
            chunk_amount = int(math.ceil(source_size / float(bytes_per_chunk)))

            upload_params = []

            for i in range(chunk_amount):
                offset = i * bytes_per_chunk
                remaining_bytes = source_size - offset
                bytes = min([bytes_per_chunk, remaining_bytes])
                part_num = i + 1
                upload_params.append((part_num, offset, bytes))

            upload_complete = "<CompleteMultipartUpload>\n"

            # get the identity of this thread
            current_thread_id = threading.current_thread().ident
            # keep a dictionary in this dictionary for every thread
            gbl_parts_upload_status[current_thread_id] = {}

            # just put the result received into a dictionary in which key is the part number.
            # this is needed, since we have to put the parts together in the asending order.
            def call_back(result):
                if result:
                    part_num, part_result, parent_thread_id = result
                    # retrieve the identity of the thread and put the result in the bucket for the parent thread
                    gbl_parts_upload_status[parent_thread_id][part_num] = part_result

            async_results = []
            # TODO: we can make the parallel processes a function of chunk_amount.
            pool = ThreadPool(processes=6)
            for param in upload_params:
                part_num, offset, remaining_bytes = param
                async_results.append(pool.apply_async(_upload_part, args=(
                upload_ctx, source_file_path, file_name, upload_id, part_num, offset, remaining_bytes,
                file_name + "?partNumber=" + str(part_num) + "&uploadId=" + str(upload_id), file_content_type,
                current_thread_id), callback=call_back))

            maximum_wait_for_upload = get_timeout_from_file_size(source_size)
            wait_per_chunk_upload = math.ceil(float(maximum_wait_for_upload) / len(upload_params))

            start_wait_time = time.time()

            for result in async_results:
                result.wait(wait_per_chunk_upload)

            # print ("time %d start_wait_time %d maximum_wait_for_upload %d" % time.time(), start_wait_time, maximum_wait_for_upload)

            if (time.time() - start_wait_time) >= maximum_wait_for_upload:
                print ("Upload took too long for '%s', going to abort the upload processes - will try to upload again" % source_file_path)
                pool.terminate()
            else:
                pool.close()
            pool.join()

            # print "chunks : "+str(chunk_amount)
            if len(gbl_parts_upload_status[current_thread_id].keys()) == chunk_amount:
                # gather results from all parts
                for x in range(1, len(gbl_parts_upload_status[current_thread_id]) + 1):
                    upload_complete += gbl_parts_upload_status[current_thread_id][x]

                upload_complete += "\n</CompleteMultipartUpload>"

                (headers, dest_url) = api_get_auth_headers("POST", upload_ctx.get('discovery_ds_id', ''),
                                                           file_name + "?uploadId=" + upload_id,
                                                           upload_type=upload_ctx.get('upload_type', 'success'),
                                                           spool_subfolder=upload_ctx.get('spool_subfolder'))
                # headers['content-encoding'] = 'gzip'
                headers['content-length'] = str(len(upload_complete))

                resp = requests.post(dest_url + file_name + "?uploadId=" + upload_id, headers=headers,
                                     data=upload_complete)
                if resp.status_code != 200:
                    print "Could not complete the upload of the log file"
                    return False
            else:
                print "Failed to upload all parts of log file"
                return False
        else:
            print "Unexpected response received while starting upload of the log file"
            print "Upload failed for file: %s, unexpected response received for initiate multipart upload request" % file_name
            return False


if __name__ == "__main__":
    testing_api_call()
