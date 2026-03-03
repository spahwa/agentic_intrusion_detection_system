# Phase 1 — Regression Test Registry

All automated tests are in `tests/test_phase1.sh`.

## How to Run

```bash
# Static tests only (no running containers needed)
bash tests/test_phase1.sh --static-only

# Runtime tests only (containers must be running)
bash tests/test_phase1.sh --runtime-only

# Full suite
bash tests/test_phase1.sh
```

## Test Inventory

### Infrastructure (Docker Compose)

| ID  | Category       | Description                                            | Auto | Ref            |
|-----|----------------|--------------------------------------------------------|------|----------------|
| S01 | Infrastructure | `docker compose config` parses without error           | Yes  | test_phase1.sh |
| S02 | Infrastructure | `docker compose --profile dual config` parses          | Yes  | test_phase1.sh |
| S03 | Infrastructure | Suricata has capabilities: NET_ADMIN, NET_RAW, SYS_NICE | Yes | test_phase1.sh |
| S04 | Infrastructure | Zeek has NET_ADMIN, NET_RAW (no SYS_NICE)              | Yes  | test_phase1.sh |
| S05 | Infrastructure | Both services use `network_mode: host`                 | Yes  | test_phase1.sh |
| S06 | Infrastructure | Both services use `restart: unless-stopped`             | Yes  | test_phase1.sh |
| S07 | Infrastructure | Image tags are pinned (no `latest`)                    | Yes  | test_phase1.sh |

### Configuration (Environment & Configs)

| ID  | Category      | Description                                             | Auto | Ref            |
|-----|---------------|---------------------------------------------------------|------|----------------|
| S08 | Configuration | Suricata receives NETWORK_INTERFACE and HOME_NET        | Yes  | test_phase1.sh |
| S09 | Configuration | Zeek receives NETWORK_INTERFACE (not HOME_NET)          | Yes  | test_phase1.sh |
| S12 | Configuration | suricata.yaml has `community-id: true`                  | Yes  | test_phase1.sh |
| S13 | Configuration | suricata.yaml has `eve-log: enabled: yes`               | Yes  | test_phase1.sh |
| S14 | Configuration | suricata.yaml loads suricata.rules and custom.rules     | Yes  | test_phase1.sh |
| S15 | Configuration | local.zeek loads `community-id-logging`                 | Yes  | test_phase1.sh |
| S16 | Configuration | local.zeek sets `LogAscii::use_json = T`                | Yes  | test_phase1.sh |

### Dual-Interface (WiFi)

| ID  | Category        | Description                                           | Auto | Ref            |
|-----|-----------------|-------------------------------------------------------|------|----------------|
| S10 | Dual-Interface  | WiFi services use NETWORK_INTERFACE_2                 | Yes  | test_phase1.sh |
| S11 | Dual-Interface  | WiFi services are under `profiles: [dual]`            | Yes  | test_phase1.sh |

### Runtime (Container Health)

| ID  | Category | Description                                              | Auto | Ref            |
|-----|----------|----------------------------------------------------------|------|----------------|
| R01 | Runtime  | ids-suricata is running (not restarting)                  | Yes  | test_phase1.sh |
| R02 | Runtime  | ids-zeek is running (not restarting)                      | Yes  | test_phase1.sh |
| R03 | Runtime  | `/var/log/ids/suricata/` directory exists                 | Yes  | test_phase1.sh |
| R04 | Runtime  | `/var/log/ids/zeek/` directory exists                     | Yes  | test_phase1.sh |
| R05 | Runtime  | Suricata log dir owned by uid 994                         | Yes  | test_phase1.sh |

### JSON Output (Data Validation)

| ID  | Category    | Description                                             | Auto | Ref            |
|-----|-------------|---------------------------------------------------------|------|----------------|
| R06 | JSON Output | `eve.json` exists and is non-empty (up to 45s wait)     | Yes  | test_phase1.sh |
| R07 | JSON Output | `eve.json` first line is valid JSON                      | Yes  | test_phase1.sh |
| R08 | JSON Output | `eve.json` contains `community_id` field                 | Yes  | test_phase1.sh |
| R09 | JSON Output | `eve.json` contains `event_type: "stats"` events         | Yes  | test_phase1.sh |
| R13 | JSON Output | Zeek `packet_filter.log` exists with valid JSON          | Yes  | test_phase1.sh |
| R14 | JSON Output | Zeek `packet_filter.log` shows `success: true`           | Yes  | test_phase1.sh |

### Process Validation (Container Logs)

| ID  | Category           | Description                                        | Auto | Ref            |
|-----|--------------------|----------------------------------------------------|------|----------------|
| R10 | Process Validation | Suricata logs show "Engine started"                | Yes  | test_phase1.sh |
| R11 | Process Validation | Suricata logs show correct interface name          | Yes  | test_phase1.sh |
| R12 | Process Validation | Suricata shows >0 rules loaded                     | Yes  | test_phase1.sh |
| R15 | Process Validation | Zeek logs show "listening on" correct interface    | Yes  | test_phase1.sh |

## Summary

| Category           | Count | Automated |
|--------------------|-------|-----------|
| Infrastructure     | 7     | 7         |
| Configuration      | 7     | 7         |
| Dual-Interface     | 2     | 2         |
| Runtime            | 5     | 5         |
| JSON Output        | 6     | 6         |
| Process Validation | 4     | 4         |
| **Total**          | **31**| **31**    |
