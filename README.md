# THOR APT Scanner → Wazuh

> Stream and normalize THOR scan findings—whether ingested live over TCP or imported from JSON reports - directly into Wazuh for real‑time alerting, threat hunting, and in‑depth incident analysis. This integration ensures that advanced forensic, malware, and indicators of compromise detected by THOR are immediately available for security operations and correlation within Wazuh.

---

## Prerequisites

| Requirement                                                   | Version / Notes              |
| ------------------------------------------------------------- | ---------------------------- |
| [**Wazuh Manager**](https://wazuh.com/)                       | 4.x (tested 4.12)            |
| [**THOR APT Scanner**](https://www.nextron-systems.com/thor/) | JSON formats v1.x.x – v3.x.x |
| [**Python**](https://www.python.org/)                         | 3.9 or newer                 |

> **Note:** Wazuh’s JSON decoder cannot parse [arrays of objects](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html#json-decoder). The ETL scripts flatten these arrays while preserving all other data fields.

---
![THOR Findings Ingestion Methods into Wazuh](ingestion-methods/images/Log%20data%20collection%20and%20analysis%20in%20Wazuh.jpg)

## 1. Method A – Live Streaming Ingestion

### 2.1 How It Works

![Live Streaming Ingestion.png](ingestion-methods/images/Live%20Streaming%20Ingestion.png)

### 2.2 Install ETL Service

Installs the `thor_online_etl.py` script and registers it as a system service, ensuring it restart on failure and starts automatically on boot.

```bash
install -o wazuh -g wazuh -m 750 thor_online_etl.py /opt/thor-json-etl/
cp thor-online-etl.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable thor-online-etl
```

### 2.3 Load Decoders & Rules

Provides Wazuh with necessary decoders and rules for parsing, classifying, and alerting on incoming THOR log events.

```bash
cp thor_decoders.xml /var/ossec/etc/decoders/
cp thor_rules.xml    /var/ossec/etc/rules/
```

### 2.4 Wazuh Syslog Remote Configuration
Since the Wazuh Syslog colelctor is [disabled by default](https://documentation.wazuh.com/current/getting-started/architecture.html#required-ports), this configuration enables Wazuh to accept incoming THOR JSON events over TCP. The ETL script will send normalized logs to Wazuh on port 514.
Configures Wazuh Manager to accept normalized THOR JSON events via TCP from the ETL script. Add the following stanza to your `/var/ossec/etc/ossec.conf` file inside `<ossec_config>`:

```xml
<remote>
  <connection>syslog</connection>
  <protocol>tcp</protocol>
  <port>514</port>
  <queue_size>131072</queue_size>
  <keep_alive>yes</keep_alive>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>
```

### 2.5 Start Services

Starts the ETL service for continuous processing and restarts Wazuh to apply new configurations and load rules.

```bash
systemctl start thor-online-etl.service
systemctl restart wazuh-manager.service
```

---

## 2. Method B – Offline Report Ingestion

### 1.1 How It Works

![Offline Report Ingestion.png](ingestion-methods/images/Offline%20Report%20Ingestion.png)


### 1.2 Install ETL Script
The python script `thor_findings_etl.py` watches for incoming THOR reports in drop_zone, flattens arrays of objects, and writes normalized output to `thor_normalized.json`.

```bash
# Install ETL script with correct permissions
install -o wazuh -g wazuh -m 750 thor_offline_etl.py /opt/thor-json-etl/
```

### 1.3 Directory Structure

```textmate
/var/ossec/logs/thor_json_reports/
├── drop_zone/            # Place THOR JSON reports here (watched by ETL script)
├── monitored_zone/       # ETL writes normalized thor findings here for Wazuh ingestion
│   └── thor_normalized.json
└── archive/              # ETL script archives original reports by date
    └── YYYY-MM-DD/
```

### 1.4 Register systemd Unit
Registers the ETL script as a system service, enabling it to run automatically and start on boot.
```bash
# Copy service definition
cp thor_offline_etl.service /etc/systemd/system/
# Reload systemd and enable service (starts on boot)
systemctl daemon-reload
systemctl enable thor_offline_etl.service
```

### 1.5 Load Decoders & Rules
Provides Wazuh with custom decoders and rules for parsing, classifying, and alerting on normalized THOR log entries.
```bash
# Copy decoders and rules
cp thor_decoders.xml /var/ossec/etc/decoders/
cp thor_rules.xml    /var/ossec/etc/rules/
```

### 1.6 Wazuh ossec.conf Stanza

Tells Wazuh logcollector to monitor the new normalized THOR events to decode, index, and display in the dashboard. Add the following section to your `/var/ossec/etc/ossec.conf` file inside the `<ossec_config>` section:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/thor_json_reports/monitored_zone/thor_normalized.json</location>
</localfile>
```

### 1.7 Log Rotation
Add a logrotate policy to prevent thor_normalized.json from growing too large, compressing and rotating the file at 3GB.
```bash
# Copy logrotate configuration
cp thor_normalized_logrotate /etc/logrotate.d/thor_normalized
```

Example `/etc/logrotate.d/thor_normalized`:

```conf
/var/ossec/logs/thor_json_reports/monitored_zone/thor_normalized.json {
    size 3G
    rotate 1
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 wazuh wazuh
    sharedscripts
}
```

### 1.8 Start Services
Starts the ETL service for continuous processing and restarts Wazuh to load new rules and configuration.
```bash
systemctl start thor_offline_etl.service
systemctl restart wazuh-manager.service
```
