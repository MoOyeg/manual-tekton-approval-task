FROM image-registry.openshift-image-registry.svc:5000/openshift/golang:1.17-ubi8 AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
COPY . .
RUN go build .

FROM image-registry.openshift-image-registry.svc:5000/openshift/golang:1.17-ubi8
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
ENTRYPOINT ["/usr/bin/oauth-proxy"]
