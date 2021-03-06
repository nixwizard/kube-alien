SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'
API_SECRET_PATH = '/api/v1/secret/kube-system/'
API_DAEMONSETS_PATH = '/apis/extensions/v1beta1/namespaces/default/daemonsets'
API_ACCESSREVIEWS_PATH = '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews'
API_DS_AUTHKEYS_PATH = '/apis/extensions/v1beta1/namespaces/default/daemonsets/authorizedkeys'
DASHBOARD_CSRF_PATH = '/api/v1/csrftoken/appdeploymentfromfile/'
DASHBOARD_DEPLOY_PATH = '/api/v1/appdeploymentfromfile'
HEAPSTER_NODES_URL = 'http://heapster.kube-system/api/v1/model/nodes'
HEAPSTER_METRICS_URL = 'http://heapster.kube-system/metrics'
DASHBOARD_URL = 'https://kubernetes-dashboard.kube-system'
DASHBOARD_CLEANUP_PATH = '/api/v1/_raw/daemonset/namespace/kube-system/name/authorizedkeys'
DASHBOARD_PORT = 443
ETCD_PORT = 2379
ETCD_CERT = '--etcd-certfile='
ETCD_KEY = '--etcd-keyfile='
ETCD_PEM = '/tmp/etcd.pem'
ETCD_SECRETS_PATH = '/v2/keys/registry/secrets/kube-system'
ETCD_VERSION_PATH = '/version'
TOKEN_CSV = '--token-auth-file='
BASIC_AUTH_FILE = "--basic-auth-file="
KUBELET_PORT = 10250
JSON_TYPE_ETCD = 0
JSON_TYPE_DASHBOARD = 1
ADD_AUTHKEYS_IMAGE = 'nixwizard/authorizedkeys'
AUTHKEYS_CLEANUP_PARAMS = {"kind":"DeleteOptions","apiVersion":"extensions/v1beta1","orphanDependents":False}
RX_NODE = 'node=\"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"'
FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'