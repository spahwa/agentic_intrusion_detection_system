FROM grafana/grafana:11.6.0-ubuntu

USER root
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/grafana/plugins
ADD https://github.com/motherduckdb/grafana-duckdb-datasource/releases/download/v0.4.0/motherduck-duckdb-datasource-0.4.0.zip /tmp/plugin.zip
RUN cd /var/lib/grafana/plugins && unzip /tmp/plugin.zip && rm /tmp/plugin.zip
USER grafana
