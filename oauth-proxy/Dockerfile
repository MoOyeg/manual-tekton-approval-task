FROM registry.access.redhat.com/ubi7
USER root
RUN yum install -y git make gcc && \
curl -L -o go1.16.2.linux-amd64.tar.gz -C - https://golang.org/dl/go1.16.2.linux-amd64.tar.gz && \
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.2.linux-amd64.tar.gz && \
export PATH=$PATH:/usr/local/go/bin && git clone https://github.com/openshift/oauth-proxy.git && \
cd oauth-proxy/ && make 
USER 1001
ENV PATH="$PATH:/opt/app-root/src/oauth-proxy"
ENTRYPOINT ["/usr/bin/oauth-proxy"]
