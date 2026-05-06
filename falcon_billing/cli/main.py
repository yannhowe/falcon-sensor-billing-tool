"""Falcon Billing CLI — single entry point with subcommands.

Usage:
    falcon-billing collect [--hourly] [--days N] [--cid CID] [--prune] [--retain-days N]
    falcon-billing query [--hourly | --weekly] [--cid CID] [--output FILE]
    falcon-billing multi-tenant [--auto-discover | --cids CID1,CID2 | --cid-file FILE]
    falcon-billing tag-report [--days N] [--output FILE] [--cid CID]
    falcon-billing verify --start-date DATE --end-date DATE [--cid CID]
    falcon-billing prune [--retain-days N] [--dry-run]
    falcon-billing dashboard [--port PORT] [--host HOST] [--no-auth]
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from falcon_billing import __version__

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        prog="falcon-billing",
        description="CrowdStrike Falcon sensor billing and cost allocation tool",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", type=Path, default=Path.cwd() / "sensor_billing.db",
                        help="Path to SQLite database (default: ./sensor_billing.db)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- collect ---
    p_collect = subparsers.add_parser("collect", help="Collect sensor data")
    p_collect.add_argument("--hourly", action="store_true", default=True,
                           help="Collect hourly granularity (default)")
    p_collect.add_argument("--days", type=int, default=0,
                           help="Backfill last N days (0 = current hour only)")
    p_collect.add_argument("--cid", default="default", help="Target CID")
    p_collect.add_argument("--prune", action="store_true",
                           help="Auto-prune old data after collection")
    p_collect.add_argument("--retain-days", type=int, default=395,
                           help="Days to retain when pruning (default: 395)")
    p_collect.add_argument("--workers", type=int, default=10,
                           help="Parallel workers for backfill NGSIEM queries (default: 10)")

    # --- query ---
    p_query = subparsers.add_parser("query", help="Query Sensor Usage API")
    p_query_mode = p_query.add_mutually_exclusive_group()
    p_query_mode.add_argument("--hourly", action="store_true",
                              help="FCS/FMC hourly average (672-hour rolling)")
    p_query_mode.add_argument("--weekly", action="store_true", default=True,
                              help="Traditional weekly average (default)")
    p_query.add_argument("--cid", default=None, help="Query specific child CID")
    p_query.add_argument("--output", type=Path, help="Write results to CSV file")

    # --- multi-tenant ---
    p_mt = subparsers.add_parser("multi-tenant", help="Multi-tenant chargeback report")
    p_mt_source = p_mt.add_mutually_exclusive_group(required=True)
    p_mt_source.add_argument("--auto-discover", action="store_true",
                             help="Discover child CIDs from Flight Control")
    p_mt_source.add_argument("--cids", help="Comma-separated CID list")
    p_mt_source.add_argument("--cid-file", type=Path, help="File with one CID per line")
    p_mt.add_argument("--output", type=Path, help="Write chargeback CSV")

    # --- tag-report ---
    p_tag = subparsers.add_parser("tag-report",
                                  help="Hosts/license count by sensor tag (NGSIEM)")
    p_tag.add_argument("--days", type=int, default=28,
                       help="Rolling average window in days (default: 28)")
    p_tag.add_argument("--output", type=Path, help="CSV output path (default: stdout)")
    p_tag.add_argument("--cid", default="default", help="Filter to specific CID")

    # --- verify ---
    p_verify = subparsers.add_parser("verify", help="Compare calculated vs API billing")
    p_verify.add_argument("--start-date", required=True, help="Start date (YYYY-MM-DD)")
    p_verify.add_argument("--end-date", required=True, help="End date (YYYY-MM-DD)")
    p_verify.add_argument("--cid", default="default", help="Target CID")

    # --- prune ---
    p_prune = subparsers.add_parser("prune", help="Remove old data from database")
    p_prune.add_argument("--retain-days", type=int, default=395,
                         help="Days to keep (default: 395)")
    p_prune.add_argument("--dry-run", action="store_true",
                         help="Show what would be deleted without deleting")

    # --- dashboard ---
    p_dash = subparsers.add_parser("dashboard", help="Start the web dashboard")
    p_dash.add_argument("--port", type=int, default=8080, help="Listen port (default: 8080)")
    p_dash.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p_dash.add_argument("--no-auth", action="store_true",
                        help="Disable API key authentication")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Dispatch to command handlers
    handlers = {
        "collect": cmd_collect,
        "query": cmd_query,
        "multi-tenant": cmd_multi_tenant,
        "tag-report": cmd_tag_report,
        "verify": cmd_verify,
        "prune": cmd_prune,
        "dashboard": cmd_dashboard,
    }
    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


def cmd_collect(args):
    from falcon_billing.database import BillingDatabase
    from falcon_billing.collector import process_hourly_collection, get_falcon_client, get_hours_to_collect, parallel_backfill

    db = BillingDatabase(args.db)
    falcon_client = get_falcon_client()

    if args.days > 0:
        hours = get_hours_to_collect(args.days, db)
        logger.info("Backfilling %d hours", len(hours))
        if len(hours) > 1 and args.workers > 1:
            parallel_backfill(db, hours, args.cid, falcon_client, workers=args.workers)
        else:
            for hour in hours:
                process_hourly_collection(db, hour, args.cid, falcon_client)
    else:
        now = datetime.now(timezone.utc)
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        process_hourly_collection(db, current_hour, args.cid, falcon_client)

    db.log_audit("collect", f"days={args.days}, cid={args.cid}", "cli")

    if args.prune:
        result = db.prune(retain_days=args.retain_days)
        logger.info("Pruned: %s", result)
        db.log_audit("prune", f"retain_days={args.retain_days}, result={result}", "cli")

    print("Collection complete.")


def cmd_query(args):
    from falcon_billing.billing import get_sensor_usage, get_sensor_usage_for_cid, print_summary, log_to_csv

    hourly = args.hourly and not args.weekly

    if args.cid:
        data = get_sensor_usage_for_cid(args.cid, hourly=hourly)
    else:
        data = get_sensor_usage(hourly=hourly)

    print_summary(data, hourly=hourly)

    if args.output:
        log_to_csv(data, str(args.output), hourly=hourly)
        print(f"Results written to {args.output}")


def cmd_multi_tenant(args):
    from falcon_billing.billing import auto_discover_child_cids, generate_multitenant_report, load_cid_list

    if args.auto_discover:
        cids = auto_discover_child_cids()
    elif args.cids:
        cids = [c.strip() for c in args.cids.split(",")]
    elif args.cid_file:
        cids = load_cid_list(f"@{args.cid_file}")
    else:
        cids = []

    if not cids:
        print("No CIDs found.", file=sys.stderr)
        sys.exit(1)

    generate_multitenant_report(cids, output_path=args.output)


def cmd_tag_report(args):
    from falcon_billing.credentials import load_credentials
    from falcon_billing.database import BillingDatabase
    from falcon_billing.ngsiem import query_ngsiem_for_sensors, NgsiemQueryFailed
    from falcon_billing.collector import enrich_sensors_with_host_details, get_falcon_client, query_hosts_api_for_active_sensors

    db = BillingDatabase(args.db)
    creds = load_credentials()
    falcon_client = get_falcon_client()
    cid = args.cid

    total_hours = args.days * 24
    now = datetime.now(timezone.utc)
    all_sensor_ids = set()

    print(f"Querying {total_hours} hours of NGSIEM data ({args.days} days)...", file=sys.stderr)
    for i in range(total_hours):
        hour_start = (now - timedelta(hours=total_hours - i)).replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        hour_start_iso = hour_start.strftime("%Y-%m-%dT%H:%M:%SZ")
        hour_end_iso = hour_end.strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            sensor_ids = query_ngsiem_for_sensors(
                hour_start_iso, hour_end_iso, cid,
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                cloud_region=creds["cloud_region"],
            )
        except NgsiemQueryFailed:
            logger.warning("NGSIEM failed for %s, trying Hosts API", hour_start_iso)
            sensor_ids = query_hosts_api_for_active_sensors(falcon_client, hour_start_iso, hour_end_iso, cid)

        all_sensor_ids.update(sensor_ids)

        if (i + 1) % 24 == 0:
            print(f"  Day {(i + 1) // 24}/{args.days}: {len(all_sensor_ids)} unique sensors so far", file=sys.stderr)

    print(f"Total unique sensors: {len(all_sensor_ids)}", file=sys.stderr)
    print("Enriching with host metadata...", file=sys.stderr)
    enriched = enrich_sensors_with_host_details(falcon_client, db, list(all_sensor_ids))

    # Group by SensorGroupingTag
    tag_counts = {}
    untagged = set()

    for sensor_id, metadata in enriched.items():
        tags_json = metadata.get("tags", "[]")
        try:
            tags = json.loads(tags_json) if isinstance(tags_json, str) else (tags_json or [])
        except (json.JSONDecodeError, TypeError):
            tags = []

        sensor_tags = [t for t in tags if t.startswith("SensorGroupingTag/")]

        if not sensor_tags:
            untagged.add(sensor_id)
        else:
            for tag in sensor_tags:
                if tag not in tag_counts:
                    tag_counts[tag] = set()
                tag_counts[tag].add(sensor_id)

    # Build CSV rows
    rows = []
    total = len(all_sensor_ids)

    for tag, sensors in sorted(tag_counts.items(), key=lambda x: len(x[1]), reverse=True):
        count = len(sensors)
        pct = (count / total * 100) if total > 0 else 0
        rows.append({"tag": tag, "unique_hosts": count, "28day_avg_licenses": count, "percentage": f"{pct:.1f}%"})

    if untagged:
        pct = (len(untagged) / total * 100) if total > 0 else 0
        rows.append({"tag": "(untagged)", "unique_hosts": len(untagged), "28day_avg_licenses": len(untagged), "percentage": f"{pct:.1f}%"})

    fieldnames = ["tag", "unique_hosts", "28day_avg_licenses", "percentage"]

    if args.output:
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Tag report written to {args.output}", file=sys.stderr)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    db.log_audit("tag_report", f"days={args.days}, tags={len(tag_counts)}, total={total}", "cli")


def cmd_verify(args):
    from falcon_billing.database import BillingDatabase
    from falcon_billing.collector import generate_verification_report

    db = BillingDatabase(args.db)
    generate_verification_report(db, args.start_date, args.end_date, args.cid)
    db.log_audit("verify", f"start={args.start_date}, end={args.end_date}", "cli")


def cmd_prune(args):
    from falcon_billing.database import BillingDatabase

    if not args.db.exists():
        print(f"Database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    db = BillingDatabase(args.db)
    result = db.prune(retain_days=args.retain_days, dry_run=args.dry_run)

    action = "Would delete" if args.dry_run else "Deleted"
    for table, count in result.items():
        print(f"  {action} {count} rows from {table}")

    if not args.dry_run:
        db.log_audit("prune", f"retain_days={args.retain_days}, result={result}", "cli")


def cmd_dashboard(args):
    import os
    if not args.db.exists():
        print(f"Database not found: {args.db}", file=sys.stderr)
        print("Run 'falcon-billing collect' first to create the database.", file=sys.stderr)
        sys.exit(1)

    os.environ["FALCON_BILLING_DB"] = str(args.db)
    if args.no_auth:
        os.environ["DASHBOARD_NO_AUTH"] = "1"

    from falcon_billing.web.app import create_app
    app = create_app()
    print(f"Starting dashboard at http://{args.host}:{args.port}")
    print(f"Database: {args.db}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
