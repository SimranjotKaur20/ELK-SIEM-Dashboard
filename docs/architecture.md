# SIEM Architecture Diagram & Log Flow

This document details the log ingestion pipeline and architecture for our Security Information and Event Management (SIEM) dashboard.

## Log Flow Architecture

The data pipeline follows a hierarchical flow from the edge systems to the central analyst visualization console.

```mermaid
graph TD
    %% Endpoint Agents
    subgraph Endpoints [Monitored Endpoints]
        WA[Windows Server / Client VM] -->|Sec Auditing logs| WB[Winlogbeat / Elastic Agent]
        LA[Linux Server / Kali VM] -->|auth.log & syslog| FB[Filebeat]
    end

    %% Ingestion & Parsing
    subgraph LogstashPipeline [Ingestion & Processing]
        WB -->|Port 5044 / Encrypted Beats| LS[Logstash Engine]
        FB -->|Port 5044 / Encrypted Beats| LS
        LS -->|1. Grok Parsing| LS_F[Filter & Normalize]
        LS_F -->|2. GeoIP enrichment| LS_G[GeoIP Processor]
        LS_G -->|3. ECS Mapping| LS_O[Output Stage]
    end

    %% Storage & Indexing
    subgraph Storage [Storage & Indexing]
        LS_O -->|Port 9200 / Bulk API| ES[(Elasticsearch Cluster)]
        ES -->|Rule evaluation| WA_R{Elastic Watcher}
        WA_R -->|Alert trigger| AL[Alerts Index: siem-alerts]
        WA_R -->|Outbound webhook| SL[Slack / Email Notifications]
    end

    %% Visualization & Analytics
    subgraph Visuals [Visualization & Analytics]
        KB[Kibana Panel] -->|KQL Queries| ES
        KB -->|SIEM Dashboard UI| ANA[Security Analysts]
    end

    style Endpoints fill:#1a1c23,stroke:#34495e,stroke-width:2px,color:#fff
    style LogstashPipeline fill:#2c3e50,stroke:#2980b9,stroke-width:2px,color:#fff
    style Storage fill:#1e272c,stroke:#27ae60,stroke-width:2px,color:#fff
    style Visuals fill:#2d1b33,stroke:#8e44ad,stroke-width:2px,color:#fff
```

## Component Breakdowns

### 1. Endpoint Logging Agents
- **Winlogbeat / Elastic Agent**: Installed on Windows systems. Configured to monitor the Security event log (focusing on Logon events 4624/4625 and Process Creation 4688).
- **Filebeat**: Installed on Linux endpoints. Monitored log paths:
  - `/var/log/auth.log` (Ubuntu/Debian) or `/var/log/secure` (CentOS/RHEL) for authentication attempts.
  - `/var/log/syslog` or `/var/log/messages` for system events.

### 2. Logstash Log Processing
- **Port 5044 Listener**: Ingests incoming Beats payloads securely.
- **Grok Parser**: Regular expression engine matching unstructured Linux system logs and converting them into structured attributes.
- **GeoIP Processor**: Interrogates public client IP fields using a GeoLite database, inserting latitude, longitude, and country configurations.
- **ECS Normalization**: Re-maps logs to the standardized **Elastic Common Schema (ECS)** format (e.g., source host IP becomes `source.ip`, process commands map to `process.command_line`).

### 3. Elasticsearch Storage Engine
- **Index Strategy**: Ingested events write to daily indexes `siem-logs-YYYY.MM.dd`.
- **Search Engine**: Index mappings use keyword types for filtering, IP types for CIDR range lookups, and geo-point types for map plotting.
- **Elastic Watcher**: Evaluates threshold triggers continuously (e.g. brute force triggers) and logs alert events to `siem-alerts` while issuing Webhook notifications.

### 4. Kibana Visualization Portal
- **Dashboard Interface**: Provides a dashboard containing maps, timeseries login timelines, threat rankings, and alert statistics.
- **Analyst Queries**: Supports near-real-time querying via Kibana Query Language (KQL) and Lucene queries.
