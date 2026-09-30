#!/usr/bin/env python3
"""Replay the FCSC licensing rule from NG-SIEM and compare it with SensorUsage.

Licensing counts, for each hour, the sensors seen in that hour and averages the
hourly readings over 28 days. A host seen in hour H counts as a container host
(FCSC) when a container ran on it in the trailing 25h; otherwise it is an FCS
non-container host. This samples one hour per day across the 28-day window
(rotating the hour of day) and, for each candidate container signal, reports the
mean of the per-hour container-host counts. Outputs aggregates only.

    python3 scripts/fcsc_hourly_replay.py --profile talon_1 --event-date 2026-09-28 \
        --diff-days 4 --out docs/fcsc-hourly-replay.json

The step test (--diff-days) is the sharper one: each daily move of the official
rolling average is predicted from the day it adds and the day it drops.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

EVENT_SEARCH = os.environ.get(
    "FALCON_EVENT_SEARCH",
    os.path.expanduser("~/.claude/skills/falcon-api/falcon-event-search.py"),
)

# For hosts with a heartbeat in the sampled hour: which container events each sent in the trailing window.
# i=Info s=Started c=ContainerHeartbeat e=EngineInfo o=any other Oci* (Telemetry, Stopped, ...).
QUERY = """
#event_simpleName=SensorHeartbeat or #event_simpleName=/^Oci/
| ev := #event_simpleName
| case {
    ev="SensorHeartbeat" | test(@timestamp >= {hour_start}) | h := 1;
    ev="SensorHeartbeat" | h := 0;
    ev="OciContainerInfo" | i := 1;
    ev="OciContainerStarted" | s := 1;
    ev="OciContainerHeartbeat" | c := 1;
    ev="OciContainerEngineInfo" | e := 1;
    * | o := 1 }
| groupBy(aid, function=[max(h, as=h), max(i, as=i), max(s, as=s), max(c, as=c), max(e, as=e), max(o, as=o), selectLast(event_platform)], limit=max)
| default(field=[h, i, s, c, e, o], value=0)
| h=1
| groupBy([event_platform, i, s, c, e, o], function=count(as=hosts), limit=max)
"""

# Candidate definitions of "a container ran on this host", over the flag columns.
CANDIDATES = {
    "oci_any (current tool)": lambda r: any(r[k] for k in "isceo"),
    "info": lambda r: r["i"],
    "info_or_started": lambda r: r["i"] or r["s"],
    "info_or_started_or_containerheartbeat": lambda r: r["i"] or r["s"] or r["c"],
    "engineinfo": lambda r: r["e"],
}

SENSOR_USAGE_FIELDS = ["containers", "public_cloud_with_containers", "servers_with_containers",
                       "public_cloud_without_containers", "servers_without_containers",
                       "workstations", "mobile", "lumos"]


def load_event_search():
    spec = importlib.util.spec_from_file_location("falcon_event_search", EVENT_SEARCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def keychain(service, profile):
    return subprocess.run(["security", "find-generic-password", "-s", service, "-a", profile, "-w"],
                          capture_output=True, text=True, check=True).stdout.strip()


def official(profile, event_date):
    """SensorUsage 28-day hourly averages for the profile's own CID, keyed by date. Each date's
    row is the rolling 28-day average ending that date (selected_cids is required: without it
    the API returns a far larger scope than the tenant)."""
    from falconpy import SensorDownload, SensorUsage
    auth = dict(client_id=keychain("falcon-client-id", profile),
                client_secret=keychain("falcon-client-secret", profile))
    cid = SensorDownload(**auth).get_sensor_installer_ccid()["body"]["resources"][0].split("-")[0].lower()
    response = SensorUsage(**auth).get_hourly_usage(
        filter=f"event_date:'{event_date}'+period:'28'+selected_cids:'{cid}'")
    if response["status_code"] != 200:
        raise RuntimeError(f"SensorUsage {response['status_code']}: {response['body'].get('errors')}")
    return {row["date"]: {k: row[k] for k in SENSOR_USAGE_FIELDS} for row in response["body"]["resources"]}


def day(date):
    return datetime.fromisoformat(date).replace(tzinfo=timezone.utc)


def sample_hours(event_date, days):
    """One hour per day for the `days` days ending on event_date, hour of day rotating by 7."""
    return [day(event_date) - timedelta(days=d) + timedelta(hours=(d * 7) % 24) for d in range(days)]


def day_hours(date, per_day):
    """`per_day` evenly spaced hours within one UTC day."""
    return [day(date) + timedelta(hours=h * 24 // per_day) for h in range(per_day)]


def difference_test(run_hours, reference, event_date, diff_days, per_day):
    """Predict each official daily step R_t - R_(t-1) = (D_t - D_(t-28)) / 28 from day means.

    A rolling 28-day mean moves by the day it adds minus the day it drops, so each step
    tests a candidate on two specific days instead of on one 28-day aggregate.
    """
    dates = [(day(event_date) - timedelta(days=d)).date().isoformat() for d in range(diff_days)]
    needed = {t: (day(t) - timedelta(days=28)).date().isoformat() for t in dates}
    all_days = sorted(set(dates) | set(needed.values()))
    samples = run_hours([h for d in all_days for h in day_hours(d, per_day)])
    keys = ["hosts_seen"] + list(CANDIDATES)
    means = {}
    for d in all_days:
        rows = [s for s in samples if s["hour"].startswith(d)]
        means[d] = {k: sum(r[k] for r in rows) / len(rows) for k in keys}
    steps = []
    for t in dates:
        previous = (day(t) - timedelta(days=1)).date().isoformat()
        if previous not in reference:
            continue
        step = {"date": t, "official_containers": reference[t]["containers"] - reference[previous]["containers"]}
        for k in CANDIDATES:
            step[k] = (means[t][k] - means[needed[t]][k]) / 28
        steps.append(step)
    error = {k: sum(abs(s[k] - s["official_containers"]) for s in steps) / len(steps) for k in CANDIDATES}
    return {"per_day": per_day, "day_means": means, "steps": steps, "mean_abs_step_error": error}


class Session:
    """Shared OAuth token, reissued when the API rejects it (another client session
    requesting tokens for the same API client invalidates this one mid-run)."""

    def __init__(self, es, base_url, profile):
        self.es, self.base_url, self.profile = es, base_url, profile
        self.lock = threading.Lock()
        self.token = es.get_oauth_token(base_url, profile)

    def search(self, query, start_ms, end_ms):
        for attempt in range(3):
            token = self.token
            try:
                job_id = self.es.submit_query_job(token, query, start_ms, end_ms, "search-all", self.base_url)
                return self.es.poll_query_results(token, job_id, "search-all", self.base_url, timeout=900)
            except (RuntimeError, urllib.error.HTTPError) as error:
                if "401" not in str(error) and "invalid bearer token" not in str(error) or attempt == 2:
                    raise
                with self.lock:
                    if self.token == token:
                        self.token = self.es.get_oauth_token(self.base_url, self.profile)


def replay_hour(session, hour_start, lookback_hours):
    hour_end = hour_start + timedelta(hours=1)
    window_start = hour_end - timedelta(hours=lookback_hours)
    ms = lambda t: int(t.timestamp() * 1000)
    query = QUERY.replace("{hour_start}", str(ms(hour_start))).strip()
    rows = session.search(query, ms(window_start), ms(hour_end)).get("events", [])
    for r in rows:
        for k in "isceo":
            r[k] = str(r[k]) == "1"
        r["hosts"] = int(r["hosts"])
    counts = {"hosts_seen": sum(r["hosts"] for r in rows)}
    for name, test in CANDIDATES.items():
        counts[name] = sum(r["hosts"] for r in rows if test(r))
    platforms = {}
    for r in rows:
        platforms[r["event_platform"]] = platforms.get(r["event_platform"], 0) + r["hosts"]
    counts["platforms"] = platforms
    print(f"{hour_start:%Y-%m-%dT%H}Z " + " ".join(f"{k}={v}" for k, v in counts.items() if k != "platforms"),
          file=sys.stderr)
    return {"hour": hour_start.isoformat(), **counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", required=True, help="/cid keychain profile, passed explicitly")
    parser.add_argument("--event-date", required=True, help="SensorUsage event_date (last day of the 28-day window)")
    parser.add_argument("--days", type=int, default=28)
    parser.add_argument("--lookback-hours", type=int, default=25)
    parser.add_argument("--base-url", default="https://api.crowdstrike.com")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--diff-days", type=int, default=0,
                        help="also run the rolling-step test for this many days ending on --event-date")
    parser.add_argument("--per-day", type=int, default=6, help="sampled hours per day in the step test")
    parser.add_argument("--out", help="write results JSON here")
    args = parser.parse_args()

    es = load_event_search()
    session = Session(es, args.base_url, args.profile)

    def run_hours(hours):
        with ThreadPoolExecutor(args.workers) as pool:
            return sorted(pool.map(lambda h: replay_hour(session, h, args.lookback_hours), hours),
                          key=lambda s: s["hour"])

    reference = official(args.profile, args.event_date)
    output = {"profile": args.profile, "event_date": args.event_date,
              "lookback_hours": args.lookback_hours, "official": reference}
    if args.days:
        samples = run_hours(sample_hours(args.event_date, args.days))
        keys = ["hosts_seen"] + list(CANDIDATES)
        mean = {k: sum(s[k] for s in samples) / len(samples) for k in keys}
        ref = reference[args.event_date]
        ref_total = sum(ref[k] for k in SENSOR_USAGE_FIELDS if k != "containers")
        output["average_test"] = {
            "method": f"{len(samples)} sampled hours, one per day, vs the official 28-day average",
            "replay_mean": mean,
            "vs_official": {
                "hosts_seen - official total": mean["hosts_seen"] - ref_total,
                **{f"{k} - official containers": mean[k] - ref["containers"] for k in CANDIDATES},
            },
            "samples": samples,
        }
    if args.diff_days:
        output["step_test"] = difference_test(run_hours, reference, args.event_date, args.diff_days, args.per_day)
    text = json.dumps(output, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
