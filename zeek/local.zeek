# Agentic IDS — Zeek site policy
# Loaded at runtime via CLI argument

# Base protocol analyzers
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/dhcp
@load base/protocols/ftp
@load base/protocols/smtp

# Community ID for cross-tool correlation with Suricata
@load policy/protocols/conn/community-id-logging

# MAC address logging in conn.log (orig_l2_addr, resp_l2_addr)
@load policy/protocols/conn/mac-logging

# Security-relevant policies
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/http/detect-sqli

# File hash computation
@load policy/frameworks/files/hash-all-files

# JSON output
redef LogAscii::use_json = T;

# Log directory
redef Log::default_logdir = "/var/log/ids/zeek";

# Rotate logs every hour
redef Log::default_rotation_interval = 1hr;
