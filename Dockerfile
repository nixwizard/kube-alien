FROM ubuntu:18.04

RUN apt-get -y update \
    && apt-get install -yq \
       apt-utils \
       python3-pip \
       curl \
       inetutils-traceroute \
    && python3 -m pip install --upgrade pip \
    && pip3 install requests netifaces

COPY main.py config.py /root/
COPY templates /root/templates

CMD /usr/bin/env python3 /root/main.py
