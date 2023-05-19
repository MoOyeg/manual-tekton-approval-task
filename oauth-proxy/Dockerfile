FROM registry.redhat.io/ubi8/go-toolset@sha256:6740d72db4de99ecb4652cff89a239242afd150d6ccf6ed0ebff89ffcbbc649e AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
USER root
COPY . .
RUN go build .

FROM registry.redhat.io/ubi8/go-toolset@sha256:6740d72db4de99ecb4652cff89a239242afd150d6ccf6ed0ebff89ffcbbc649e
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
USER root
USER 1001
ENTRYPOINT ["/usr/bin/oauth-proxy"]




# FROM registry.access.redhat.com/ubi7
# USER root
# RUN yum install -y git make gcc && \
# curl -L -o go1.16.2.linux-amd64.tar.gz -C - https://golang.org/dl/go1.16.2.linux-amd64.tar.gz && \
# rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.2.linux-amd64.tar.gz && \
# export PATH=$PATH:/usr/local/go/bin && git clone https://github.com/openshift/oauth-proxy.git && \
# cd oauth-proxy/ && make 
# USER 1001
# ENV PATH="$PATH:/opt/app-root/src/oauth-proxy"
# ENTRYPOINT ["/usr/bin/oauth-proxy"]
