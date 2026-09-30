# How a tenant in tenants.txt becomes a chargeback line

*falcon-sensor-billing-tool: architecture walkthrough, produced with `/pstack:how` on 2026-09-30 (3 Opus explorers + 1 Opus explainer). It describes commit ab6d950. Tier 1 items 1 to 3 are fixed on branch `fix/tier1-chargeback`; line numbers refer to ab6d950.*

## Overview

`falcon-billing` estimates Falcon sensor consumption per tenant and per tag for internal chargeback. The most important fact is that **tenants.txt feeds only one of three independent report paths, and they share no code**:

1. **Multi-tenant path** (`falcon-billing multi-tenant --cid-file tenants.txt`). It asks the Sensor Usage API for CrowdStrike's own bucket counts per CID and writes a CSV. It never touches SQLite, the classifier or NG-SIEM.
2. **Collected path** (`collect`, then `query`, `tag-report` or `dashboard`). It pulls heartbeat agent IDs from NG-SIEM, enriches them through the Hosts API, classifies them locally into FCSC/FMC/FCS/EPP, stores hourly rows in SQLite and averages them. **It has no tenant list:** whatever one credential set can see gets stored under one `cid` label.
3. **CI report path** (the `report` job in `.gitlab-ci.yml`). It runs raw `sqlite3 AVG(unique_sensor_count)` queries against the database that path 2 built.

**At HEAD, path 1 returns all zeros for every tenant, and path 2 crashes whenever it finds sensors.** Both findings, plus the missing tag columns and the gap-detection bug, were spot-checked against the code.

## How It Works

```
PATH 1 - multi-tenant (the only path tenants.txt feeds)
  tenants.txt -> load_cid_list -> generate_multitenant_report (serial loop per CID)
      -> load_credentials + new SensorUsage client per tenant
      -> get_sensor_usage_weekly_average()     <-- method does not exist in FalconPy
      -> AttributeError swallowed -> None -> ZERO ROW
      -> multitenant_chargeback_weekly_<ts>.csv

PATH 2 - collect -> SQLite (cron / run.sh / CI)
  get_falcon_cid (CCID or 'default')
      -> Q1 NG-SIEM SensorHeartbeat groupBy(aid)   [fallback: Hosts last_seen]
      -> Q2 NG-SIEM Oci* over 24h, intersected with Q1 -> FCSC candidates
                                                  <-- Oci* includes OciContainerTelemetry (fires on every host)
      -> enrich: host_metadata_cache -> Hosts get_device_details (x100)
      -> classify: Pod -> FMC; is_cloud_vm -> FCS / EPP
      -> db.insert_sensor_logs(..., sensor_type_map=...)   <-- TypeError at HEAD
      -.-> hourly_counts, hourly_tag_counts   (never reached for non-empty hours)

  REPORTS reading SQLite (five different averaging denominators):
      query        -> SUM / 672 (fixed)
      tag-report   -> / distinct hours, reads SKU columns that don't exist -> OperationalError
      dashboard    -> per-CID own hours; EPP = 7-day daily-peak avg, ceil
      CSV export   -> / global hours (disagrees with summary)

PATH 3 - GitLab CI report job
      sqlite3 AVG(unique_sensor_count) -> billing_by_cid.csv, billing_by_tag.csv
```

### Path 1: tenants.txt to CSV

1. `load_cid_list` (`billing.py:285`) reads `CID` or `CID,Name` lines and skips blank lines and `#` comments. It does no validation.
2. `generate_multitenant_report` (`billing.py:219`) loops over tenants one at a time. For each tenant it reloads credentials (up to six Keychain subprocesses) and builds a new `SensorUsage` client, which means a new OAuth token each time.
3. It then calls `get_sensor_usage_weekly_average` (`billing.py:129/131`). **That method doesn't exist in FalconPy.** The real name is `get_weekly_usage`, which the unused `get_sensor_usage` at line 80 calls correctly.
4. The `AttributeError` is caught by the `except Exception` at line 140, the function returns `None`, and the tenant gets a zero row. The command still exits 0 and writes the CSV.
5. Even with the right name, the call passes no `selected_cids`. On talon_1 that returns a far larger scope than the tenant (about 114k servers against 378 hosts); with `selected_cids:'<own cid>'` it returns the tenant's own figures (see `docs/oci-event-validation.md`).
6. If the call succeeded, `resources[0]` would be mapped to the CSV columns:
   - `lumos` → `managed_containers`
   - `public_cloud_without_containers` → `cloud_vms`
   - `servers_without_containers` → `servers`
   - `workstations` → `workstations`

Other entry points:
- `--cids a,b` crashes, because it passes plain strings where `(cid, name)` tuples are expected.
- `--auto-discover` calls Flight Control `query_children` and `get_children` without pagination.

### Path 2: collect into SQLite

For each hour, `collect`:

1. Resolves a CID label from SensorDownload, or falls back to `'default'`.
2. **Q1:** queries NG-SIEM for `SensorHeartbeat` agent IDs. There is no CID filter and no `limit=max`.
3. **Q2:** queries `Oci*` events over a 24-hour window, intersected with Q1, to get the FCSC candidates. The wildcard is wrong for this purpose (see Tier 1, item 3).
4. Enriches each agent ID from a 24-hour cache, falling back to the Hosts API.
5. Classifies: `product_type_desc == 'Pod'` makes a host FMC. Everything else goes through `is_cloud_vm`, which is deliberately "maximize FCS", and becomes FCS or EPP.
6. Stores the results. `insert_sensor_logs(..., sensor_type_map=...)` (`collector.py:559/784`) raises `TypeError`, because `database.py:606` has no such parameter. Commit ab6d950 introduced this.

| Table | Key | Write mode | Notes |
|---|---|---|---|
| `sensor_logs` | `UNIQUE(hour, sensor_id)`, no cid | `INSERT OR IGNORE` | First write wins; a partial `--days 0` hour is never corrected |
| `hourly_counts` | `(hour, cid)` | `INSERT OR REPLACE` | total + fcsc/fmc/fcs/epp (added by migration) |
| `hourly_tag_counts` | `(hour, tag, cid)` | `INSERT OR REPLACE` | only `unique_sensor_count`; stale tags never deleted |
| `host_metadata_cache` | `sensor_id` | upsert | 24h TTL |
| `billing_averages` | `(date, cid)` | none | Only writer is dead code, so always empty |

### Falcon APIs called

| Endpoint | FalconPy method | Scope | Call site |
|---|---|---|---|
| `/billing-dashboards-usage/aggregates/{hourly,weekly}-average/v1` | `SensorUsage.get_hourly_usage` / `get_weekly_usage` (**code calls nonexistent names**) | sensor-usage-api:read | billing.py:129/131 |
| `/mssp/queries/children/v1`, `/mssp/entities/children/v1` | `FlightControl.query_children` / `get_children` | mssp:read | billing.py:173/195 |
| `/sensors/queries/installers/ccid/v1` | `SensorDownload.get_sensor_installer_ccid` | sensor-installers:read | collector.py:1054 |
| `/devices/queries/devices/v1`, `POST /devices/entities/devices/v2` | `Hosts.query_devices_by_filter` / `get_device_details` | devices:read | collector.py:161/248 |
| `/humio/api/v1/repositories/search-all/queryjobs` | raw `requests` (new token every attempt) | NG-SIEM (code and CI name three different scopes) | ngsiem.py:200/231 |

## Where Things Live

- `falcon_billing/billing.py`: path 1.
- `falcon_billing/collector.py`: hourly orchestration and classification wiring.
- `falcon_billing/classifier.py`: the FCS/EPP rules.
- `falcon_billing/database.py`: schema and averaging.
- `falcon_billing/ngsiem.py`: LogScale queries.
- `falcon_billing/cli/main.py`: subcommands.
- `falcon_billing/web/`: the Flask dashboard.
- `scripts/legacy/`: about 6.9k lines of dead code. The `docs/` folder describes that older classifier, not the one in the package.

## Gotchas

### Tier 1: the chargeback number is wrong or empty

1. **Multi-tenant reports all zeros.** The method names are wrong and the error is swallowed. *Fixed: `get_hourly_usage` with a normalized `selected_cids`, errors raise, and a `container_hosts` column.*
2. **Collection crashes when sensors exist.** The `sensor_type_map` argument raises `TypeError`. Phase 2 of `parallel_backfill` sits outside the `try`, so one crash aborts the whole backfill. *Fixed: the dead map is gone, and failed hours are stored around and reported with a non-zero exit.*
3. **FCSC counts nearly every Linux host.** Three queries in `ngsiem.py` (lines 36, 48 and 57) match `#event_simpleName=Oci*`. That wildcard includes `OciContainerTelemetry`. *Fixed: `OciContainerInfo` over the 25h ending at the hour's end, every Pod sensor is FMC, and the aged-out fallback is removed.*
   - **Why it's wrong:** `OciContainerTelemetry` is a fleet-wide heartbeat. It fires every 24h on every host unless the `OciContainerTrackingDisabled` system tag is set, even with zero containers (`oci-container-tracking.fcs`, no zero-guard). The 24h lookback catches every such host, so FCS/EPP are under-counted by the same amount FCSC is over-counted. The `_FCS_QUERY` anti-join has the same problem.
   - **What to count instead:**
     - `OciContainerInfo` for "host ran a container in the window". It fires when a container starts and is resent every 24h while the container runs.
     - `OciContainerStarted` for container counts, per the event author.
     - `OciContainerEngineInfo` for "a runtime is present".
   - **Knock-on bug:** `collector.py:384` treats "0 container hosts" as "the data aged out" and switches to the substring classifier. With the correct events, 0 is a normal answer for fleets without containers.
   - **Measured on talon_1, on the licensing basis** (hourly hosts averaged over 28 days, container host = a container ran in the trailing 25h):
     - Oci* gives 131.5 FCSC hosts, against SensorUsage's 72.9.
     - `OciContainerInfo` gives 68.0 and tracks the official rolling average day to day.
     - `OciContainerEngineInfo` matches the level (73.0) but gets the daily moves wrong.
     - Recommendation: use `OciContainerInfo`. It stays about 5 hosts low; the source of the gap is open.
     - Full write-up: `docs/oci-event-validation.md`.
4. **Gap detection never matches.** It compares `isoformat()` strings (`…T01:00:00+00:00`) against the stored format (`… 01:00:00`), so every hour gets re-collected.
5. **No tenant key.** `sensor_logs` has no cid column, and NG-SIEM has no CID filter. On a Flight Control parent, the children probably get merged under one label (inferred, not confirmed).
6. **Averaging.** Licensing averages the hourly readings over the past 28 days, and SensorUsage's `period:'28'` rows are rolling 28-day averages. The tool has five different denominators. The fixed 672 hours is compared against a window of about 695 hours, and the `--days 0` partial hour gets locked in by `INSERT OR IGNORE`.
7. **Heuristic false positives in the fallback classifier.** It matches substrings, so non-cloud hosts get misclassified:
   - The tags `oaks-office`, `geeks` and `worker-laptops` become FCSC.
   - The tags `wifi-1` and `Associates` become FCS.
   - Surface and Pixelbook devices become FCS.
   - Fresh Hosts API tags, which arrive as a list, are silently dropped.

### Tier 2: a feature is broken

- `tag-report` and the dashboard's tag endpoints query SKU columns that don't exist.
- `verify` has its arguments in the wrong order, and it can never pass because `billing_averages` is always empty.
- NG-SIEM 403 and 429 responses skip the Hosts fallback, and there is no 429 handling anywhere.
- The NG-SIEM URL for us-gov-1 is wrong.
- The CloudFormation IAM policy allows `sensor_billing.db`, but CI uses `.db.gz`.
- CI's zero-count grep never matches.
- `app.js` renders fields the API doesn't return.

### Tier 3: cosmetic

- No-op CLI flags.
- Wrong help text.
- Groups are JSON-encoded twice.
- Conflicting Python version floors.

### Tests: covered vs. missed

The suite ran in a throwaway venv: 40 tests, 38 passing, 24% line coverage. The two failures in `test_tag_report.py` are stale tests. CI has no test stage.

| Module | Coverage | Covered | Key miss |
|---|---|---|---|
| billing.py | 0% | nothing | The whole tenants.txt path |
| collector.py | 12% | cache hit/miss | fetch/store/backfill/gap detection |
| ngsiem.py | 19% | retry/timeout | status codes, fallback routing |
| classifier.py | 49% | 5 `classify_sensor` happy paths | `is_cloud_vm` has zero tests; no false-positive cases |
| database.py | 64% | schema, TTL, upsert, prune, 28-day total | `insert_sensor_logs`, tag aggregation |
| credentials.py | 77% | env, Keychain format A | format B (the one the README documents) |
| cli / web | 13% / 0% | nothing | nearly everything |

**Root cause of the gap:** `MagicMock` clients accept any method name, so nothing pins the FalconPy API surface, and nothing runs `collect` end to end against a real SQLite file.

### Open questions

- ~~Is Sensor Usage `resources[0]` the newest period?~~ Yes: rows come newest date first, and each is a rolling 28-day average.
- Does `search-all` on a Flight Control parent return child-tenant events?
- Does a deployed database have hand-added SKU columns?
- Does LogScale accept the `!join(... mode=inner)` anti-join?
- What exact `product_type_desc` and `cloud_provider` values does the Hosts API return?
- A running container defines an FCSC host (per the user). `OciContainerInfo` is the closest event, but about 5 official FCSC hosts on talon_1 send no Info. What does the official count use for them?
- The recommended OCI events only fire when the `OciContainerSupport` system tag is set. Could hosts without it run containers and go uncounted? The 36 container hosts with no Info on talon_1 run older sensor builds.
