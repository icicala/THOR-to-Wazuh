# THOR → Wazuh

**Purpose:** Stream and normalize **THOR** scan findings into Wazuh SIEM for real-time alerting, threat hunting, and automated incident response.  
This integration ensures that advanced forensic, malware, and compromise indicators detected by **THOR** are immediately available for security operations and correlation in Wazuh.

---

## Prerequisites
| Requirement                                                                                                                                                                                                                                                                                                                                                                                                     | Value                        |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|
| [**Wazuh Manager**](https://wazuh.com/)                                                                                                                                                                                                                                                                                                                                                                         | 4.x (tested 4.12)            |
| [**THOR reports**](https://www.nextron-systems.com/thor/?utm_source=google&utm_medium=cpc&utm_campaign=THOR_APT_Seatch&utm_term=thor%20apt%20scanner&utm_content=Ad1&gad_source=1&gad_campaignid=22495394156&gbraid=0AAAAACRM45lMXyBI7ImsOMlmET2DggnFo&gclid=CjwKCAjw9uPCBhATEiwABHN9K-yTSLWjpnhuihcebIx7-A8N75UKHQH0OC8G_DB_Iz7rd_OSTAAcJhoCQiAQAvD_BwE)                                                       | JSON formats v1.x.x – v3.x.x |
| [**Python**](https://www.python.org/downloads/release/python-390/)                                                                                                                                                                                                                                                                                                                                              | 3.9 or newer                 |

> NOTE: **JSON Array Limitation:** According to [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), Wazuh doesn't support arrays of objects. The ETL script flattens these arrays while preserving all other data types, making THOR findings compatible with Wazuh's JSON decoder.

## 1. **Event-driven Ingestion Pipeline (systemd + inotify)**

### 1.1 Deploy ETL Script
The python script `thor_findings_etl.py` watches for incoming THOR reports in `drop_zone`, flattens arrays of objects, and writes normalized output to `thor_normalized.json`.

```bash
# Install ETL script with correct permissions
install -o wazuh -g wazuh -m 750 thor_findings_etl.py /usr/local/bin/thor_findings_etl.py
```
####  Directory Structure

```
/var/ossec/logs/thor_json_reports/
├── drop_zone/         # Place incoming THOR JSON reports here (watched by ETL script)
├── monitored_zone/    # ETL writes normalized logs here for Wazuh ingestion
│   └── thor_normalized.json
└── archive/           # ETL script archives original reports by date
    └── YYYY-MM-DD/
```

### 1.2 Configure Systemd Service
Registers the ETL script as a system service, enabling it to run automatically in the background and start on boot.
```bash
# Copy service definition
cp thor_etl.service /etc/systemd/system/

# Reload systemd and enable service (starts on boot)
systemctl daemon-reload
systemctl enable thor_etl
```

### 1.3 Install Wazuh Components
Provides Wazuh with custom decoders and rules for parsing, classifying, and alerting on normalized THOR log entries.
```bash
# Copy decoders and rules
cp thor_decoders.xml /var/ossec/etc/decoders/
cp thor_rules.xml /var/ossec/etc/rules/
```

### 1.4 Wazuh Configuration
Tells Wazuh logcollector to monitor the normalized THOR log file for new events to decode, index, and display in the dashboard.
Add the following section to your `/var/ossec/etc/ossec.conf` file inside the `<ossec_config>` section:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/thor_json_reports/monitored_zone/thor_normalized.json</location>
</localfile>
```

### 1.5 Configure Log Rotation
Adds a logrotate policy to prevent `thor_normalized.json` from growing too large, compressing and rotating the file at 3GB.
```bash
# Copy logrotate configuration
cp thor_normalized_logrotate /etc/logrotate.d/thor_normalized
```

**Example `logrotate` entry:**

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
---

### 1.6 Start Services
Starts the ETL service for continuous processing and restarts Wazuh to load new rules and configuration.
```bash
systemctl start thor_etl
systemctl restart wazuh-manager
```





---


## 2. \[Add alternate ingestion method(s) here…]


### 1.8 Verification and Testing

```bash
systemctl status thor_etl                    # Check the ETL service status
tail -f /var/ossec/logs/thor_etl.log         # Watch live ETL processing logs
cp sample_thor_report.json /var/ossec/logs/thor_json_reports/drop_zone/  # Test with a sample file
```

**What it does:**
Confirms that the pipeline is running correctly and processes test THOR reports end-to-end.

---

### 1.9 How It Works

```
THOR report → drop_zone/*.json
            ↓ inotify kernel event triggers
      thor_etl.py processes the file:
            ├── flattens arrays of objects
            ├── appends to monitored_zone/thor_normalized.json
            └── archives original to archive/YYYY-MM-DD/
                     ↓
      Wazuh logcollector ingests normalized JSON
            ↓
      Wazuh rules and dashboard process, alert, and visualize findings
```

**What it does:**
Shows the complete flow: from dropping a new THOR report, flattening and normalizing data, to alerting and visibility in Wazuh.

---