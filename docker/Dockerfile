FROM alpine:3.8 as builder

ENV GOPATH /go

RUN apk --no-cache add \
  dep \
  git \
  go \
  libc-dev \
  make

WORKDIR /go/src/github.com/deciphernow/ldapt

COPY . .

RUN make build

FROM alpine:3.8

ENV LDAP_HOST "localhost"
ENV LDAP_PORT "389"
ENV LDAP_SECURE "true"
ENV LDAP_BASE "ou=people,dc=exmple,dc=com"
ENV LDAP_TEMPLATE "(uid=%s)"
ENV LDAP_DISTINGUISHED_NAME "cn=ldapt,ou=services,dc=example,dc=com"
ENV LDAP_PASSWORD "password"

COPY --from=builder /go/src/github.com/deciphernow/ldapt/ldapt /usr/local/bin/ldapt
COPY ./docker/files/ /

RUN chown -R 0:0 /etc/ldapt
RUN chmod g=u /etc/ldapt

EXPOSE 8080
USER 1000
VOLUME /etc/ldapt

ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["/usr/local/bin/ldapt", "-c", "/etc/ldapt/config.json"]
