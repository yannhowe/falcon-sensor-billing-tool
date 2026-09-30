#!/usr/bin/env python3
"""Count distinct hosts per OCI event type over one pinned NG-SIEM window.

Evidence for choosing the FCSC (container host) signal: OciContainerTelemetry
fires on every host every 24h, so an Oci* match over-counts container hosts.
Outputs aggregate counts only, never host IDs.

Uses the falcon-api skill's event-search auth (macOS Keychain, /cid profile):
    python3 scripts/oci_event_validation.py --profile talon_1 --out docs/oci-event-validation.json
"""

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone

EVENT_SEARCH = os.environ.get(
    "FALCON_EVENT_SEARCH",
    os.path.expanduser("~/.claude/skills/falcon-api/falcon-event-search.py"),
)

OCI_EVENTS = ["OciContainerTelemetry", "OciContainerInfo", "OciContainerStarted", "OciContainerEngineInfo"]

QUERIES = {
    # The query from the investigation: distinct hosts per Oci* event type.
    "per_event": """
#event_simpleName=/^Oci/
| groupBy([#event_simpleName], function=count(aid, distinct=true, as=hosts), limit=max)
""",
    # Same count without count(distinct=true): one group per (event, host), then count groups.
    "per_event_exact": """
#event_simpleName=/^Oci/
| groupBy([#event_simpleName, aid], limit=max)
| groupBy([#event_simpleName], function=count(as=hosts), limit=max)
""",
    "heartbeat": """
#event_simpleName=SensorHeartbeat
| groupBy([event_platform], function=count(aid, distinct=true, as=hosts), limit=max)
""",
    # One row per combination of events a host sent; o = any other Oci* event.
    "overlap": """
#event_simpleName=SensorHeartbeat or #event_simpleName=/^Oci/
| ev := #event_simpleName
| case {
    ev="SensorHeartbeat" | h := 1;
    ev="OciContainerTelemetry" | t := 1;
    ev="OciContainerInfo" | i := 1;
    ev="OciContainerStarted" | s := 1;
    ev="OciContainerEngineInfo" | e := 1;
    * | o := 1 }
| groupBy(aid, function=[max(h, as=h), max(t, as=t), max(i, as=i), max(s, as=s), max(e, as=e), max(o, as=o), selectLast(event_platform)], limit=max)
| default(field=[h, t, i, s, e, o], value=0)
| groupBy([event_platform, h, t, i, s, e, o], function=count(as=hosts), limit=max)
""",
    # all_retx=1: every Info event from the host was a 24h retransmit (long-running containers only).
    "info_retransmit": """
#event_simpleName=OciContainerInfo
| case { OciContainerInfoRetransmitted=1 | r := 1; * | r := 0 }
| groupBy(aid, function=min(r, as=all_retx), limit=max)
| groupBy([all_retx], function=count(as=hosts))
""",
    # all_rundown=1: every Started event was a sensor-restart rediscovery, not a new container.
    "started_rundown": """
#event_simpleName=OciContainerStarted
| case { OciContainerIsRundown=1 | r := 1; * | r := 0 }
| groupBy(aid, function=min(r, as=all_rundown), limit=max)
| groupBy([all_rundown], function=count(as=hosts))
""",
    # active=1: the host reported at least one container start in a Telemetry event.
    "telemetry_activity": """
#event_simpleName=OciContainerTelemetry
| groupBy(aid, function=max(OciContainersStartedCount, as=started), limit=max)
| case { test(started > 0) | active := 1; * | active := 0 }
| groupBy([active], function=count(as=hosts))
""",
}


def load_event_search():
    spec = importlib.util.spec_from_file_location("falcon_event_search", EVENT_SEARCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(es, token, base_url, name, start_ms, end_ms):
    job_id = es.submit_query_job(token, QUERIES[name].strip(), start_ms, end_ms, "search-all", base_url)
    result = es.poll_query_results(token, job_id, "search-all", base_url, timeout=600)
    print(f"\r{name}: {len(result.get('events', []))} rows" + " " * 20, file=sys.stderr)
    return {
        "query": QUERIES[name].strip(),
        "rows": result.get("events", []),
        "warnings": result.get("metaData", {}).get("extraData", {}),
    }


def cross_check(results):
    """Exact per-event host counts must equal the overlap table's column sums.

    per_event (count(distinct=true)) is not checked: LogScale estimates distinct
    counts, and on talon_1 it was 1 low for 5 of 10 event types.
    """
    per_event = {r["#event_simpleName"]: int(r["hosts"]) for r in results["per_event_exact"]["rows"]}
    overlap = results["overlap"]["rows"]
    column = {"OciContainerTelemetry": "t", "OciContainerInfo": "i",
              "OciContainerStarted": "s", "OciContainerEngineInfo": "e"}
    checks = {}
    for event, col in column.items():
        summed = sum(int(r["hosts"]) for r in overlap if str(r[col]) == "1")
        checks[event] = {"per_event": per_event.get(event, 0), "overlap_sum": summed,
                         "agree": per_event.get(event, 0) == summed}
    hb_rows = results["heartbeat"]["rows"]
    hb = sum(int(r["hosts"]) for r in hb_rows)
    hb_overlap = sum(int(r["hosts"]) for r in overlap if str(r["h"]) == "1")
    checks["SensorHeartbeat"] = {"per_event": hb, "overlap_sum": hb_overlap, "agree": hb == hb_overlap}
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", required=True, help="/cid keychain profile, passed explicitly")
    parser.add_argument("--hours", type=int, default=25)
    parser.add_argument("--end", help="window end, ISO8601 UTC (default: now, floored to the minute)")
    parser.add_argument("--base-url", default="https://api.crowdstrike.com")
    parser.add_argument("--only", nargs="*", choices=list(QUERIES), help="run a subset (skips cross-check)")
    parser.add_argument("--out", help="write results JSON here")
    args = parser.parse_args()

    es = load_event_search()
    token = es.get_oauth_token(args.base_url, args.profile)
    if args.end:
        end = datetime.fromisoformat(args.end).astimezone(timezone.utc)
    else:
        end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = end - timedelta(hours=args.hours)
    start_ms, end_ms = int(start.timestamp() * 1000), int(end.timestamp() * 1000)

    names = args.only or list(QUERIES)
    results = {name: run(es, token, args.base_url, name, start_ms, end_ms) for name in names}
    output = {
        "profile": args.profile,
        "window": {"start": start.isoformat(), "end": end.isoformat(), "hours": args.hours},
        "results": results,
    }
    if not args.only:
        output["cross_check"] = cross_check(results)

    text = json.dumps(output, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
