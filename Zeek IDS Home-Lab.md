# Zeek IDS Setup 

## Overview

* **Goal:** Deploy Zeek IDS to monitor mirrored/SPAN traffic, generate JSON logs, and forward to SIEM (Elastic/Splunk/Wazuh).
* **Success:** Logs ingested in SIEM, baseline detections (DNS anomalies, JA3, TLS issues), retention 7–30 days locally.

## Architecture

* **Flow:** SPAN/TAP → Zeek Sensor → Log shipper (Filebeat/UF/Agent) → SIEM.
* **Sizing:** 1–2 Gbps = 8 vCPU/16GB; 5–10 Gbps = 24 vCPU/64GB.

## Install (Ubuntu 22.04)

```bash
sudo apt update && sudo apt -y install git cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-pip
sudo apt -y install cmake libmaxminddb0 libmaxminddb-dev mmdb-bin zlib1g-dev

# Zeek repo
echo "deb [trusted=yes] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" | sudo tee /etc/apt/sources.list.d/zeek.list
sudo apt update && sudo apt -y install zeek

/opt/zeek/bin/zeek --version
```

## Key Configs

* **node.cfg**

```ini
[zeek]
type=standalone
host=localhost
interface=ens8
```

* **networks.cfg**

```
10.0.0.0/8
192.168.0.0/16
172.16.0.0/12
```

* **local.zeek** (sample)

```zeek
@load policy/tuning/json-logs.zeek
@load packages/ja3
@load packages/zeek-community-id
```

Deploy:

```bash
sudo /opt/zeek/bin/zeekctl deploy
```

## Log Shipping

* **Elastic (Filebeat example)**

```yaml
filebeat.inputs:
  - type: filestream
    paths: [/opt/zeek/logs/current/*.log]
    parsers: [{ndjson: {overwrite_keys: true}}]
output.elasticsearch:
  hosts: ["https://ELASTIC:9200"]
```

* Splunk: Monitor logs as `zeek:json`.
* Wazuh: Use agent `localfile` for JSON logs.

## Validation

* Test with PCAP: `zeek -r test.pcap local.zeek`.
* Replay traffic with `tcpreplay`.
* Confirm logs in SIEM dashboards.

## Detection Examples

* Suspicious TLS: self-signed/expired certs, rare JA3.
* DNS: excessive NXDOMAIN, DoH.
* HTTP: unusual user-agents, large data exfil.
* Beaconing: periodic low-byte flows.

## Ops Notes

* Rotate logs hourly; monitor disk.
* Use AF\_Packet + RSS for >1Gbps.
* Daily check: `zeekctl status`, SIEM ingestion.
* Weekly: `zkg upgrade`, validate detections.

---

**Quick Start:** Install Zeek → Configure (`node.cfg`, `local.zeek`) → Enable JSON logs → Ship with Filebeat → Validate with test PCAPs.
