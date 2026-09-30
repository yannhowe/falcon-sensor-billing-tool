#!/bin/bash
# Live before/after check of multi-tenant, collect, and re-collect against talon_1.
# Usage: verify-live.sh <code-dir> <out-dir>
# Credentials come from Keychain into this process's env and are never printed. CIDs are masked in output.
# PY defaults to <code-dir>/.venv/bin/python; PYTHONPATH=<code-dir> so a worktree's code is what runs.
set -u
CODE="$(cd "$1" && pwd)"; OUT="$2"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
PY="${PY:-$CODE/.venv/bin/python}"
kc() { security find-generic-password -s "$1" -a talon_1 -w; }
export FALCON_CLIENT_ID="$(kc falcon-client-id)" FALCON_CLIENT_SECRET="$(kc falcon-client-secret)" FALCON_CLOUD_REGION="$(kc falcon-cloud-region)"
export PYTHONPATH="$CODE"
fb() { (cd "$OUT" && "$PY" -m falcon_billing.cli.main "$@"); }
mask() { sed -E 's/[0-9a-fA-F]{32}(-[0-9A-Fa-f]{2})?/<cid>/g'; }

CCID=$("$PY" -c 'import os; from falconpy import SensorDownload; print(SensorDownload(client_id=os.environ["FALCON_CLIENT_ID"], client_secret=os.environ["FALCON_CLIENT_SECRET"]).get_sensor_installer_ccid()["body"]["resources"][0])')
printf '%s,talon_1\n' "$(echo "$CCID" | tr a-f A-F)" > "$OUT/tenants_upper.txt"

echo "== multi-tenant (uppercase CCID in tenants file) =="
fb --db "$OUT/v.db" multi-tenant --cid-file "$OUT/tenants_upper.txt" --output "$OUT/mt" > "$OUT/mt.log" 2>&1
echo "exit=$?"; grep -E "WARNING|ERROR|Error" "$OUT/mt.log" | mask | tail -3
cat "$OUT"/mt/*.csv 2>/dev/null | mask

echo "== multi-tenant with a CID this credential can't see =="
printf '%s,bogus\n' "00000000000000000000000000000000" > "$OUT/tenants_bogus.txt"
fb --db "$OUT/v.db" multi-tenant --cid-file "$OUT/tenants_bogus.txt" --output "$OUT/mt_bogus" > "$OUT/mt_bogus.log" 2>&1
echo "exit=$?"; tail -1 "$OUT/mt_bogus.log" | mask; ls "$OUT/mt_bogus" 2>/dev/null

echo "== collect --days 0 =="
fb --db "$OUT/v.db" collect --days 0 > "$OUT/collect0.log" 2>&1
echo "exit=$?"; grep -E "Stored|Traceback|Error|fallback" "$OUT/collect0.log" | mask | tail -6
sqlite3 -header "$OUT/v.db" "select hour_timestamp, unique_sensor_count total, fcsc_count, fmc_count, fcs_count, epp_count from hourly_counts order by 1;"
sqlite3 "$OUT/v.db" "select 'sensor_logs rows', count(*) from sensor_logs;"

echo "== collect --days 1 (parallel backfill) =="
fb --db "$OUT/v.db" collect --days 1 --workers 4 > "$OUT/collect1.log" 2>&1
echo "exit=$?"; grep -E "Traceback|Error|failed" "$OUT/collect1.log" | mask | tail -4
sqlite3 -header "$OUT/v.db" "select count(*) hours, round(avg(unique_sensor_count),1) avg_total, round(avg(fcsc_count),1) avg_fcsc, round(avg(fmc_count),1) avg_fmc, round(avg(fcs_count),1) avg_fcs, round(avg(epp_count),1) avg_epp, min(fcsc_count) min_fcsc, max(fcsc_count) max_fcsc from hourly_counts;"

# Gap-detection idempotency: on a fresh db, two identical collect runs. The second must
# find every hour already stored and fetch nothing. On the buggy build the second run
# re-collects the whole day because gap detection compares isoformat against the stored
# "YYYY-MM-DD HH:00:00" and never matches.
echo "== re-collect idempotency (collect --days 1, twice, fresh db) =="
rm -f "$OUT/idem.db" "$OUT/idem.db-wal" "$OUT/idem.db-shm"
fb --db "$OUT/idem.db" collect --days 1 --workers 4 > "$OUT/idem1.log" 2>&1
echo "first  exit=$?"
fb --db "$OUT/idem.db" collect --days 1 --workers 4 > "$OUT/idem2.log" 2>&1
echo "second exit=$?"
first_missing=$(grep -oE "Missing hours to collect: [0-9]+" "$OUT/idem1.log" | grep -oE "[0-9]+$" | tail -1)
second_missing=$(grep -oE "Missing hours to collect: [0-9]+" "$OUT/idem2.log" | grep -oE "[0-9]+$" | tail -1)
second_stored=$(grep -oE "Storing [0-9]+ hours" "$OUT/idem2.log" | grep -oE "[0-9]+" | tail -1)
echo "first run missing hours : ${first_missing:-?}"
echo "second run missing hours: ${second_missing:-?}  (expect 0)"
echo "second run stored hours : ${second_stored:-0}  (expect 0)"
[ "${second_missing:-x}" = "0" ] && echo "IDEMPOTENT: second run fetched 0 hours" || echo "NOT IDEMPOTENT: second run re-collected ${second_missing:-?} hours"

# Atomic store: for every re-collected hour, the sensor_logs row count must equal the
# hourly_counts total. A partial store (sensor_logs written, hourly_counts not) or an
# OR IGNORE re-collect that never replaces sensor_logs shows up here as a mismatch.
echo "== sensor_logs vs hourly_counts consistency (all stored hours) =="
sqlite3 -header "$OUT/idem.db" "
  select hc.hour_timestamp,
         hc.unique_sensor_count as hourly_total,
         (select count(*) from sensor_logs sl
            where sl.hour_timestamp = hc.hour_timestamp and sl.cid = hc.cid) as sensor_logs_rows
  from hourly_counts hc order by hc.hour_timestamp desc limit 5;"
mismatch=$(sqlite3 "$OUT/idem.db" "
  select count(*) from hourly_counts hc
  where hc.unique_sensor_count <>
        (select count(*) from sensor_logs sl
           where sl.hour_timestamp = hc.hour_timestamp and sl.cid = hc.cid);")
orphan=$(sqlite3 "$OUT/idem.db" "
  select count(distinct sl.hour_timestamp) from sensor_logs sl
  where not exists (select 1 from hourly_counts hc
                      where hc.hour_timestamp = sl.hour_timestamp and hc.cid = sl.cid);")
echo "hours where sensor_logs count != hourly total: ${mismatch}  (expect 0)"
echo "hours with sensor_logs but no hourly_counts   : ${orphan}  (expect 0)"
[ "${mismatch}" = "0" ] && [ "${orphan}" = "0" ] && echo "CONSISTENT: every stored hour's sensor_logs match its hourly total" || echo "INCONSISTENT: partial or unreplaced store detected"
