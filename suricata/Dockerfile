ARG SURICATA_TAG=7.0.8
FROM jasonish/suricata:${SURICATA_TAG}

# Download ET Open rules at build time so containers start fast
RUN suricata-update --no-test --no-reload || true

COPY entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

ENTRYPOINT ["/custom-entrypoint.sh"]
