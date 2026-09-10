FROM alpine:3.20

RUN apk add --no-cache chrony tzdata

COPY chrony.conf.template /etc/chrony/chrony.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
