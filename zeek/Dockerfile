ARG ZEEK_TAG=7.0.4
FROM zeek/zeek:${ZEEK_TAG}

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY node.cfg /usr/local/zeek/etc/node.cfg

ENTRYPOINT ["/entrypoint.sh"]
