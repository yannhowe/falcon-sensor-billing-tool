# Falcon Sensor Billing Tool

Collect CrowdStrike Falcon sensor counts via NGSIEM event search, classify hosts by
license type, and calculate 28-day rolling averages for FCS/EPP/FCSC/FMC licensing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## License Types

| Type | Name | What it covers |
|------|------|---------------|
| **FCS** | Falcon Cloud Security | VMs and servers — cloud or on-prem (any hypervisor or bare-metal server) |
| **EPP** | Endpoint Protection | Physical workstations, laptops, mobile devices |
| **FCSC** | Container Security (hosts) | Hosts running OCI containers (`OciContainerStarted` events, not pods) |
| **FMC** | Falcon Managed Containers | Kubernetes pods (`SensorHeartbeat` with `ProductType=Pod`) |

**Total sensors = FCS + EPP + FCSC + FMC**

---

## Quick Start

```bash
# Set credentials
export FALCON_CLIENT_ID='your_client_id'
export FALCON_CLIENT_SECRET='your_client_secret'
export FALCON_CLOUD_REGION='us-1'  # or us-2, eu-1, us-gov-1

# Step 1: Collect hourly counts (current hour)
falcon-billing collect

# Step 2: Backfill 28 days to build a full rolling average
falcon-billing collect --days 28

# Step 3: Query the summary (reads from local DB — no API call needed)
falcon-billing query

# Step 4: See per-hour breakdown
falcon-billing query --hourly

# Step 5: Start the dashboard
falcon-billing dashboard
# → http://127.0.0.1:8080
```

Or use the all-in-one script (dashboard + background collection every 4h):

```bash
./run.sh                    # collect every 4h
./run.sh --interval 2       # collect every 2h
```

---

## API Scopes Required

| Scope | Falcon Console Name | Required |
|-------|-------------------|----------|
| `devices:read` | Host Management: Read | **Yes** — device query and host metadata (classification) |
| `humio-auth-proxy:write` | Event Search: Write | **Yes** — submit NGSIEM query jobs |
| `humio-auth-proxy:read` | Event Search: Read | **Yes** — poll NGSIEM query job results |
| `sensor-installers:read` | Sensor Download: Read | No — CID auto-detection (falls back to Hosts API if absent) |
| `sensor-usage-api:read` | Sensor Usage API: Read | No — only for `multi-tenant` command |
| `mssp:read` | Flight Control: Read | No — child CID discovery for `multi-tenant` command only |

> **The `query`, `verify`, `tag-report`, and `prune` commands read exclusively from the local SQLite database. No API call is made.**

---

## How It Works

```
NGSIEM (LogScale)
    │
    │  1. Submit hourly query job for each clock hour
    │     - Total active sensors (SensorHeartbeat, NOT pods)
    │     - Container hosts (OciContainerStarted / OciContainerTelemetry)
    │     - Pods / FMC (SensorHeartbeat with ProductType=Pod)
    ▼
  AIDs (FCS+EPP set, FCSC set, FMC set)
    │
    │  2. Hosts API enrichment
    │     For the FCS+EPP set, fetch system_manufacturer (DMI) and
    │     cloud_provider (IMDS) for each AID
    ▼
  Host classification  (see "Classification" below)
    │
    │  3. Per-hour counts → SQLite
    │     hourly_counts: unique_sensor_count, fcs_count, epp_count,
    │                    fcsc_count (FCSC), fmc_count
    ▼
  SQLite (sensor_billing.db)
    │
    │  4. 28-day rolling average
    │     SUM(hourly counts over 672 hours) / 672
    ▼
  falcon-billing query  /  dashboard
```

### Classification

Hosts in the NGSIEM anti-join (SensorHeartbeat, not pod, not OCI events) are
either FCS (VMs/servers) or EPP (user endpoints). The goal is to **maximize FCS**
— any VM or server should be FCS; only physical workstations and laptops are EPP.

| Priority | Signal | Logic |
|----------|--------|-------|
| 1 (highest) | `system_manufacturer` is a hypervisor | VMware, QEMU, KVM, Xen, Hyper-V, VirtualBox, Nutanix → **FCS** (VM, including VDI) |
| 2 | `cloud_provider` (IMDS) | `aws`, `azure`, `gcp`, `oci`, etc. → **FCS** |
| 3 | `system_manufacturer` is a cloud vendor | Amazon, Google, Alibaba, etc. → **FCS** |
| 4 | `product_type_desc` | `Server`, `Domain Controller` → **FCS** (bare-metal server) |
| 5 (fallback) | `sensor_tags` | Tags containing `aws`, `azure`, `cloud`, `vm`, `vdi` → **FCS** |
| 6 (default) | None of the above | → **EPP** (physical workstation, laptop, mobile) |

If none of the signals indicate a VM or server, the host is classified as **EPP**.

### Raw Data vs License Averages

Each row in the hourly CSV is a **snapshot count** — the exact number of sensors
active in that clock hour. The dashboard and summary apply averaging on top:

- **FCS / FCSC / FMC**: 28-day rolling hourly average (sum of 672 hours / 672)
- **EPP**: 7-day weekly average of daily unique sensors

Raw hourly counts will differ from the final averaged license numbers shown on the
dashboard. Both are useful: hourly data for auditing, averages for billing.

---

## CLI Commands

```
falcon-billing collect      Collect sensor data from NGSIEM + Hosts API
falcon-billing query        Show 28-day averages from local DB (no API call)
falcon-billing multi-tenant Multi-tenant chargeback report via Sensor Usage API
falcon-billing tag-report   Per-tag host/license count via NGSIEM
falcon-billing verify       Compare local averages vs Sensor Usage API
falcon-billing prune        Remove old data from database
falcon-billing dashboard    Start the web dashboard
```

### `collect`

```bash
falcon-billing collect                    # current hour only
falcon-billing collect --days 28          # backfill last 28 days
falcon-billing collect --days 7 --prune   # backfill + auto-prune
falcon-billing collect --workers 20       # faster parallel backfill (default: 10)
```

Collects data from NGSIEM and classifies each sensor. Stores per-hour counts in the database.

### `query`

```bash
falcon-billing query              # 28-day summary (FCS / EPP / FCSC / FMC)
falcon-billing query --hourly     # per-hour breakdown table
falcon-billing query --output /tmp/results   # write CSV + JSON to directory
```

Reads **only** from the local SQLite database. No Falcon API call is made.

**Sample output:**

```
======================================================================
USAGE SUMMARY (from local NGSIEM data)
======================================================================

CID:    ABCDEF1234567890ABCDEF1234567890-XX
Period: 2026-05-06 00:00:00 → 2026-06-03 00:00:00
Data:   672/672 hours (100.0% coverage)

28-day rolling averages:
  Total Sensors:    247.54
  FCS (Cloud VMs):  198.20
  EPP (Endpoints):   22.11
  FCSC (Cont Hosts): 18.43
  FMC (Pods):         8.80

CHARGEBACK BREAKDOWN:
  FCS licenses:     198.20
  FCSC licenses:     18.43
  FMC licenses:       8.80
```

**Per-hour breakdown** (`--hourly`):

```
Per-hour breakdown (672 hours):
  Hour                   Total     FCS    FCSC     FMC     EPP
  -------------------- ------- ------- ------- ------- -------
  2026-05-06 00:00:00      245     196      18       9      22
  2026-05-06 01:00:00      248     200      18       8      22
  ...
```

### `prune`

```bash
falcon-billing prune                      # delete data older than 395 days
falcon-billing prune --retain-days 90     # keep only last 90 days
falcon-billing prune --dry-run            # preview without deleting
```

---

## Dashboard

The dashboard at `http://127.0.0.1:8080` shows:

- **Licensing summary** — 28-day avg FCS / EPP / FCSC / FMC, peak hourly, coverage
- **Per-CID breakdown** — licenses required per child CID
- **Per-tag breakdown** — cost allocation by SensorGroupingTags / FalconGroupingTags
- **Hourly trend charts**
- **CSV export** for CID and tag tables

### API Key Authentication

```bash
export DASHBOARD_API_KEY='your-secret-key'
falcon-billing dashboard
```

```bash
# Header (preferred)
curl -s -H "X-API-Key: your-secret-key" http://127.0.0.1:8080/api/fcs/summary

# Query param (for downloads)
curl -s "http://127.0.0.1:8080/api/fcs/export?type=tag&api_key=your-secret-key" -o tags.csv
```

When `DASHBOARD_API_KEY` is not set, auth is disabled (all endpoints open).

---

## CSV Output

### Weekly summary (`query` default)

```csv
period_start,period_end,period_days,hours_with_data,avg_total,avg_fcs,avg_fcsc,avg_fmc,avg_epp,retrieved_at
2026-05-06 00:00:00,2026-06-03 00:00:00,28,672,247.54,198.20,18.43,8.80,22.11,2026-06-03T12:00:00
```

### Hourly breakdown (`query --hourly`)

```csv
hour_timestamp,unique_sensor_count,fcs_count,fcsc_count,fmc_count,epp_count
2026-05-06 00:00:00,245,196,18,9,22
2026-05-06 01:00:00,248,200,18,8,22
```

### Tag report (`tag-report`)

```csv
tag,unique_hosts,28day_avg_licenses,percentage
SensorGroupingTag/prod,59,59,23.9%
SensorGroupingTag/staging,44,44,17.8%
(untagged),22,22,8.9%
```

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FALCON_CLIENT_ID` | Yes* | — | API client ID |
| `FALCON_CLIENT_SECRET` | Yes* | — | API client secret |
| `FALCON_CLOUD_REGION` | No | `us-1` | `us-1`, `us-2`, `eu-1`, `us-gov-1` |
| `FALCON_BILLING_DB` | No | `./sensor_billing.db` | Database path |
| `DASHBOARD_API_KEY` | No | — | Protect dashboard API (disabled if unset) |

\* Or configure a macOS Keychain profile via the `/cid` skill (see below).

### Keychain Credentials (macOS)

```bash
# Store credentials in Keychain — no env vars needed
security add-generic-password -s "falcon-client-id" -a "my_cid" -w "CLIENT_ID" -U
security add-generic-password -s "falcon-client-secret" -a "my_cid" -w "CLIENT_SECRET" -U
security add-generic-password -s "falcon-cloud-region" -a "my_cid" -w "us-1" -U
echo "my_cid" > ~/.falcon_profile
```

---

## NGSIEM Queries

Three queries run per clock hour:

**Total active sensors + FCS/EPP set** (anti-join: no pods, no OCI events):
```
#event_simpleName=SensorHeartbeat ProductType!=Pod
| selfJoinFilter(aid, where=[
    {NOT #event_simpleName=OciContainerStarted},
    {NOT #event_simpleName=OciContainerTelemetry}
  ], prefilter=#event_simpleName=/SensorHeartbeat|OciContainer/)
| groupBy(aid)
```

**Container hosts (FCSC)** — AIDs with OCI container events, not pods:
```
#event_simpleName=OciContainerStarted OR #event_simpleName=OciContainerTelemetry
| selfJoinFilter(aid, where=[{#event_simpleName=SensorHeartbeat ProductType!=Pod}],
    prefilter=#event_simpleName=SensorHeartbeat)
| groupBy(aid)
```

**Pods (FMC)**:
```
#event_simpleName=SensorHeartbeat ProductType=Pod
| groupBy(aid)
```

Each query runs as an async job: `POST /humio/api/v1/repositories/search-all/queryjobs`,
then `GET {endpoint}/{job_id}` until `done: true`.

---

## Installation

### From Source

```bash
git clone <repo>
pip install -r requirements.txt
python -m falcon_billing.cli.main --help
```

### Build Binary (macOS ARM64)

```bash
pip install pyinstaller
pyinstaller --clean falcon_billing.spec
# Output: dist/falcon-billing
```

---

## Project Structure

```
falcon_billing/
  billing.py          # Sensor Usage API queries (multi-tenant command)
  classifier.py       # Host classification: is_cloud_vm(), classify_sensor()
  collector.py        # NGSIEM queries + Hosts API enrichment + DB writes
  credentials.py      # Credential loading (env vars → Keychain)
  database.py         # SQLite schema, migrations, hourly counts, 28-day average
  ngsiem.py           # NGSIEM query job submission and polling
  cli/main.py         # CLI entry point (subcommands)
  web/
    app.py            # Flask dashboard
    auth.py           # API key authentication
    templates/        # Jinja2 templates
    static/           # CSS and JS
tests/                # 40 unit tests
falcon_billing.spec   # PyInstaller build spec
run.sh                # Dashboard + periodic collection script
```

---

## Security

- Credentials from environment variables or macOS Keychain (never hardcoded)
- Constant-time API key comparison (`hmac.compare_digest`)
- Parameterized SQL queries throughout
- CSV exports sanitized against formula injection
- Dashboard binds to `127.0.0.1` only

---

## License

MIT — see [LICENSE](LICENSE)

---

*Unofficial community tool. Not affiliated with CrowdStrike.*
