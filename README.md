# CTI-Project

> An automated Cyber Threat Intelligence platform that collects, enriches, scores, and disseminates threat intelligence built from scratch without any pre-built CTI frameworks.

---

## What This Is

CTI-Project is a full-stack threat intelligence platform that automates the entire CTI lifecycle — from raw OSINT collection to actionable BLOCK/MONITOR/IGNORE decisions served over industry-standard STIX/TAXII feeds.

Built to demonstrate real-world DevOps and cybersecurity engineering: microservice architecture, ML-assisted enrichment, graph-based intelligence correlation, and a custom Shodan-style search interface.

---

## Architecture

```
Internet (RSS / OTX / URLHaus)
         │
         ▼
  [ rss-ingestor ]      — collects raw threat data, extracts IOCs
         │
         ▼
  [ graph-api ]         — promotes IOCs into PostgreSQL intelligence graph
         │
         ▼
  [ nlp-enricher ]      — extracts malware names, ATT&CK techniques, scores context
         │
         ▼
  [ decision-engine ]   — scores every IOC, outputs BLOCK / MONITOR / IGNORE
         │
         ▼
  [ feedback-loop ]     — self-improving confidence scores (runs every 24h)
         │
         ▼
  [ taxii-server ]      — serves STIX 2.1 feeds, blocklists, executive reports
         │
         ▼
  [ frontend ]          — real-time dashboard + Shodan-style search interface
```

---

## Key Features

**Automated OSINT Collection**
- RSS ingestion from BleepingComputer, SANS ISC, CISA Alerts, Threatpost
- AlienVault OTX integration (250 threat pulses per cycle)
- URLHaus malicious URL feed (live malware delivery infrastructure)
- Automatic IOC extraction: IPv4, domains, URLs, MD5/SHA256 hashes, CVEs

**Intelligence Graph**
- PostgreSQL-backed graph with objects, relationships, and tags
- Campaign nodes linking IOCs to their source threat reports
- Automatic entity extraction: malware families, threat actors, MITRE ATT&CK techniques
- 16,000+ IOC nodes with 16,000+ relationships

**ML-Assisted Enrichment**
- NLP context scoring — distinguishes malicious IOC references from benign ones
- Named entity recognition for 30+ malware families and threat actor groups
- MITRE ATT&CK technique extraction (T-codes) from raw threat text
- Confidence score system (0-100) updated dynamically per IOC

**Decision Engine**
- Multi-factor threat scoring across confidence, severity, recency, and corroboration
- Automated BLOCK / MONITOR / IGNORE decisions with full reasoning
- Domain whitelisting to eliminate false positives
- Outputs: 2,700+ BLOCK decisions from 16,000+ IOCs

**Self-Improving Feedback Loop**
- Campaign feedback: boosts IOCs in high-BLOCK campaigns automatically
- Source reliability tracking: adjusts trust scores based on historical accuracy
- IOC aging: decays stale intelligence to keep blocklists fresh

**STIX 2.1 / TAXII Dissemination**
- Public feed (TLP:CLEAR) — high confidence BLOCK IOCs
- Partner feed (TLP:AMBER) — BLOCK + context, API key protected
- Internal feed (TLP:RED) — full intelligence, internal use only
- Plain text blocklist export for firewall/DNS filter consumption
- Daily executive cyber brief (JSON)

**Custom Frontend**
- Real-time dashboard with decision breakdown charts and source performance
- Shodan-style IOC search across the full intelligence graph
- CVE tracker with NVD links
- Threats page with BLOCK/MONITOR/IGNORE filtering and reasoning display

---

## Tech Stack

| Layer | Technology |
|---|---|
| Collection | Python, feedparser, requests |
| Storage | SQLite (raw), PostgreSQL (graph) |
| Enrichment | Python NLP, regex, transformer-based NER |
| API | FastAPI, uvicorn |
| Frontend | React, Vite, Recharts |
| Infrastructure | Docker, Docker Compose |
| Intel Standard | STIX 2.1, TAXII, TLP |

---

## Services

| Service | Port | Purpose |
|---|---|---|
| frontend | 5173 | Dashboard + search UI |
| graph-api | 8001 | Intelligence graph REST API |
| taxii-server | 9000 | STIX feeds + executive reports |
| postgres | 5432 | Intelligence graph database |
| rss-ingestor | — | OSINT collection loop |
| nlp-enricher | — | Enrichment loop |
| decision-engine | — | Scoring loop |
| feedback-loop | — | 24h self-improvement loop |

---

## Running Locally

**Requirements:** Docker, Docker Compose, Node.js 20+

```bash
# Clone the repo
git clone https://github.com/yourusername/CTI-project
cd CTI-project

# Set up environment variables
cp .env.example .env
# Add your OTX API key to .env

# Start all backend services
docker compose up -d

# Start the frontend
cd services/frontend
npm install
npm run dev
```

Open `http://localhost:5173`

---

## Intelligence APIs

```bash
# Platform stats
curl http://localhost:8001/stats

# Search any IOC
curl "http://localhost:8001/search?q=emotet"

# Get BLOCK decisions
curl "http://localhost:8001/decisions?decision=BLOCK&limit=10"

# Daily executive report
curl http://localhost:9000/reports/daily

# Public STIX feed
curl http://localhost:9000/feeds/public/indicators

# Blocklist for firewall consumption
curl http://localhost:9000/feeds/blocklist
```

---

## Data Sources

| Source | Type | Trust Level |
|---|---|---|
| CISA Alerts | ICS/SCADA advisories, CVEs | 95 |
| URLHaus (abuse.ch) | Live malware delivery URLs | 90 |
| AlienVault OTX | Community threat pulses | 80 |
| SANS ISC | Incident reports, honeypot data | 75 |
| BleepingComputer | Threat news, campaign reports | 60 |

---

## What I Learned Building This

- Microservice architecture and Docker Compose orchestration
- Intelligence graph design (objects, relationships, confidence scoring)
- STIX 2.1 / TAXII — the international standard for CTI sharing
- NLP-based IOC extraction and false positive filtering
- TLP (Traffic Light Protocol) for intelligence classification
- Feedback loop design for self-improving systems
- FastAPI, PostgreSQL, React from scratch

---

## Author

Muhammad Jawad — DevOps Engineer  
UAE | Open to EU opportunities  
[LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)
