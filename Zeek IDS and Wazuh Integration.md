# Zeek → Wazuh Integration 

## 1) Objectives & Success Criteria

* **Objective:** Ingest Zeek JSON logs into Wazuh, parse with decoders/rules, and surface alerts/dashboards in Wazuh Dashboard.
* **Success:** Zeek logs visible in Wazuh within 15 min; base detections fire (DNS anomalies, TLS issues, weird.log); searchable by asset, user, JA3, domain.

---

## 2) Reference Architecture

```
SPAN/TAP → Zeek Sensor (JSON logs) → Wazuh Agent (localfile) → Wazuh Manager → Wazuh Indexer/Dashboard
```

* **Placement:** Wazuh *agent* runs on the Zeek sensor host and tails Zeek logs locally.
* **Alternatives:** If agents are disallowed, forward via Fluent Bit/Vector to a syslog receiver on Wazuh Manager (JSON intact) and adapt inputs.

---

## 3) Prerequisites

* Zeek installed (JSON logging enabled via `@load policy/tuning/json-logs.zeek`).
* Wazuh Manager + Indexer + Dashboard running (v4.x).
* Network path from Zeek sensor → Wazuh Manager (1514/udp or 1514/tcp as configured).

---

## 4) Deploy Wazuh Agent on Zeek Sensor

**Ubuntu example**

```bash
curl -sO https://packages.wazuh.com/4.x/apt/wazuh-agent_4.x_latest_amd64.deb
sudo WAZUH_MANAGER="<manager_ip>" dpkg -i wazuh-agent_4.x_latest_amd64.deb
sudo systemctl enable --now wazuh-agent
```

---

## 5) Configure Agent to Read Zeek Logs

Edit `/var/ossec/etc/ossec.conf` on the sensor and add **one** `localfile` block per Zeek log you need (safer than wildcards):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/notice.log</location>
  <tag>zeek</tag>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/weird.log</location>
  <tag>zeek</tag>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/dns.log</location>
  <tag>zeek</tag>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/ssl.log</location>
  <tag>zeek</tag>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/http.log</location>
  <tag>zeek</tag>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/conn.log</location>
  <tag>zeek</tag>
</localfile>
```

Restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

> Tip: If you rotate logs hourly, always monitor the `current/` symlink as above.

---

## 6) (Optional) Zeek-Specific Decoders

Create `/var/ossec/etc/decoders/zeek_decoders.xml` on the **Manager**:

```xml
<decoders>
  <!-- Generic JSON passthrough is built-in when <log_format>json</log_format> is used. -->
  <!-- Helper decoder to tag filetype from agent-reported location -->
  <decoder name="zeek-location">
    <prematch>^</prematch>
    <parent>json</parent>
    <field name="location">([^\n]+)</field>
  </decoder>
</decoders>
```

Reload manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## 7) Rules: Classify & Alert on Zeek Events

Create `/var/ossec/etc/rules/zeek_rules.xml` on the **Manager**:

```xml
<group name="zeek,syslog,">
  <!-- Base rule: any Zeek JSON event -->
  <rule id="100100" level="3">
    <if_group>json</if_group>
    <field name="tags">zeek</field>
    <description>Zeek event ingested</description>
  </rule>

  <!-- NOTICE log high-severity events -->
  <rule id="100110" level="8">
    <if_group>json</if_group>
    <field name="location">notice.log</field>
    <description>Zeek NOTICE: $(msg)</description>
    <options>no_full_log</options>
  </rule>

  <!-- WEIRD protocol anomalies -->
  <rule id="100120" level="6">
    <if_group>json</if_group>
    <field name="location">weird.log</field>
    <description>Zeek WEIRD: $(name)</description>
  </rule>

  <!-- DNS anomalies: excessive NXDOMAIN, suspicious TLDs -->
  <rule id="100130" level="7">
    <if_group>json</if_group>
    <field name="location">dns.log</field>
    <regex field="rcode_name">NXDOMAIN</regex>
    <description>Zeek DNS: NXDOMAIN observed (potential DGA/misconfig)</description>
  </rule>
  <rule id="100131" level="8">
    <if_group>json</if_group>
    <field name="location">dns.log</field>
    <regex field="query">\.(onion|top|xyz)$</regex>
    <description>Zeek DNS: Suspicious TLD in query $(query)</description>
  </rule>

  <!-- TLS issues: self-signed/expired -->
  <rule id="100140" level="8">
    <if_group>json</if_group>
    <field name="location">ssl.log</field>
    <regex field="validation_status">(self\-signed|certificate\s+expired)</regex>
    <description>Zeek TLS: Certificate problem ($(validation_status)) for $(server_name)</description>
  </rule>

  <!-- HTTP: executable over HTTP or rare UA -->
  <rule id="100150" level="7">
    <if_group>json</if_group>
    <field name="location">http.log</field>
    <regex field="resp_mime_types">application/x-dosexec</regex>
    <description>Zeek HTTP: Executable downloaded over HTTP $(uri)</description>
  </rule>

  <!-- Beaconing heuristic from conn.log: short, periodic connections (simple) -->
  <rule id="100160" level="5" frequency="10" timeframe="300">
    <if_group>json</if_group>
    <field name="location">conn.log</field>
    <description>Zeek CONN: Potential beaconing (multiple short-lived flows)</description>
  </rule>
</group>
```

Then enable it in `/var/ossec/etc/ossec.conf` (manager):

```xml
<ruleset>
  <rule_dir>/var/ossec/etc/rules</rule_dir>
  <rule_exclude>0215-policy_rules.xml</rule_exclude>
  <rule_file>zeek_rules.xml</rule_file>
</ruleset>
```

Reload manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## 8) Wazuh Dashboard (Search & Panels)

* **Search tips:**

  * `data.tags: "zeek" AND location: dns.log`
  * `data.location: notice.log AND rule.level: >=8`
* **Panels to add:** Top domains (dns.log `query`), JA3/JA3S from ssl.log (`ja3`, `ja3s`), Top weirds (`name`), Executables over HTTP (`resp_mime_types`).

---

## 9) Validation Plan

1. Generate events on a test host:

   * DNS NXDOMAIN: query `doesnotexist.examplexyz.`
   * TLS warning: browse to a site with expired/self-signed cert.
   * HTTP exe: download a benign `.exe` over HTTP.
2. Confirm **agent** is sending (agent log `ossec.log`), and **manager** receives alerts.
3. Verify Dashboard searches/panels populate within 5–10 minutes.

---

## 10) Operations

* **Daily:** Check agent status, disk usage on Zeek box, alert volumes for `zeek` tag.
* **Weekly:** Review false positives, update Zeek packages (`zkg upgrade`), refine rules.
* **Incident:** Pivot from Wazuh alert → filter by `uid`, `id.orig_h`, `id.resp_h` across Zeek logs.

---

## 11) Timeline (Example)

* **Day 1:** Install agent; add localfile; restart components.
* **Day 2:** Add rules, build dashboard panels.
* **Day 3:** Validation & tuning; handover.

---

## 12) Next Steps

Share your Wazuh version and Zeek log paths; I’ll tailor decoders/rules to your schema and ship ready-to-import XML files.
