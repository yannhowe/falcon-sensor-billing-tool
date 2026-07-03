"""Falcon Billing CLI — single entry point with subcommands.

Usage:
    falcon-billing collect [--hourly] [--days N] [--cid CID] [--prune] [--retain-days N]
    falcon-billing query [--hourly | --weekly] [--cid CID] [--output FILE]
    falcon-billing multi-tenant [--auto-discover | --cids CID1,CID2 | --cid-file FILE]
    falcon-billing tag-report [--days N] [--output FILE] [--cid CID] [--format pivot|consolidated]
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
    p_tag.add_argument("--format", choices=["pivot", "consolidated"], default="pivot",
                       help="Output format: pivot (one row per tag) or consolidated (one row per tag+license_type)")

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
    from falcon_billing.database import BillingDatabase

    db = BillingDatabase(args.db)
    hourly = args.hourly
    cid = args.cid or "default"

    # Auto-resolve CID: if 'default', pick the CID with the most rows in the DB
    if cid == "default":
        row = db.get_connection().execute(
            "SELECT cid FROM hourly_counts GROUP BY cid ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        if row:
            cid = row["cid"]

    summary = db.calculate_28day_average(cid=cid)
    avgs = summary["averages"]
    hours_with_data = summary["hours_with_data"]
    period_hours = summary["period_hours"]
    coverage_pct = (hours_with_data / period_hours * 100) if period_hours > 0 else 0

    print("\n" + "=" * 70)
    print("USAGE SUMMARY (from local NGSIEM data)")
    print("=" * 70)
    print(f"\nCID:    {summary['cid']}")
    print(f"Period: {summary['period_start']} → {summary['period_end']}")
    print(f"Data:   {hours_with_data}/{period_hours} hours ({coverage_pct:.1f}% coverage)")
    print(f"\n{summary['period_days']}-day rolling averages:")
    print(f"  Total Sensors:    {avgs['total']:.2f}")
    print(f"  FCS (Cloud VMs):  {avgs['fcs']:.2f}")
    print(f"  EPP (Endpoints):  {avgs['epp']:.2f}")
    print(f"  FCSC (Cont Hosts):{avgs['fcsc']:.2f}")
    print(f"  FMC (Pods):       {avgs['fmc']:.2f}")
    print(f"\nCHARGEBACK BREAKDOWN:")
    print(f"  FCS licenses:     {avgs['fcs']:.2f}")
    print(f"  FCSC licenses:    {avgs['fcsc']:.2f}")
    print(f"  FMC licenses:     {avgs['fmc']:.2f}")

    hourly_rows = []
    if hourly:
        hourly_rows = db.get_hourly_counts_for_range(
            summary["period_start"], summary["period_end"], cid=cid
        )
        print(f"\nPer-hour breakdown ({len(hourly_rows)} hours):")
        print(f"  {'Hour':<20} {'Total':>7} {'FCS':>7} {'FCSC':>7} {'FMC':>7} {'EPP':>7}")
        print(f"  {'-'*20} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")
        for r in hourly_rows:
            print(
                f"  {r['hour_timestamp']:<20} {r['unique_sensor_count']:>7}"
                f" {r.get('fcs_count') or 0:>7} {r.get('fcsc_count') or 0:>7}"
                f" {r.get('fmc_count') or 0:>7} {r.get('epp_count') or 0:>7}"
            )

    print("=" * 70 + "\n")

    if args.output:
        import os
        output_dir = str(args.output)
        os.makedirs(output_dir, exist_ok=True)
        label = "hourly" if hourly else "weekly"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(output_dir, f"falcon_ngsiem_{label}_{ts}.csv")
        json_path = csv_path.replace(".csv", ".json")

        if hourly and hourly_rows:
            fieldnames = ["hour_timestamp", "unique_sensor_count", "fcs_count",
                          "fcsc_count", "fmc_count", "epp_count"]
            rows_out = [dict(r) for r in hourly_rows]
        else:
            fieldnames = ["period_start", "period_end", "period_days", "hours_with_data",
                          "avg_total", "avg_fcs", "avg_fcsc", "avg_fmc", "avg_epp", "retrieved_at"]
            rows_out = [{
                "period_start": summary["period_start"],
                "period_end": summary["period_end"],
                "period_days": summary["period_days"],
                "hours_with_data": hours_with_data,
                "avg_total": round(avgs["total"], 4),
                "avg_fcs": round(avgs["fcs"], 4),
                "avg_fcsc": round(avgs["fcsc"], 4),
                "avg_fmc": round(avgs["fmc"], 4),
                "avg_epp": round(avgs["epp"], 4),
                "retrieved_at": datetime.now().isoformat(),
            }]

        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows_out)

        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"Results written to {csv_path}")


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
    from falcon_billing.database import BillingDatabase

    db = BillingDatabase(args.db)

    # Use pre-aggregated hourly_tag_counts instead of re-querying NGSIEM
    target_hours = args.days * 24
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=target_hours)).strftime("%Y-%m-%d %H:%M:%S")

    conn = db.get_connection()

    # Get collected hours for averaging
    hours_row = conn.execute(
        "SELECT COUNT(DISTINCT hour_timestamp) as total_hours "
        "FROM hourly_counts WHERE hour_timestamp >= ?",
        (cutoff,),
    ).fetchone()
    collected_hours = hours_row["total_hours"] or 1

    # Query per-tag per-SKU aggregates
    cid_filter = args.cid
    if cid_filter and cid_filter != "default":
        cursor = conn.execute(
            "SELECT tag, "
            "SUM(unique_sensor_count) as total, "
            "SUM(COALESCE(fcs_count, 0)) as fcs_total, "
            "SUM(COALESCE(fcsc_count, 0)) as fcsc_total, "
            "SUM(COALESCE(fmc_count, 0)) as fmc_total, "
            "SUM(COALESCE(epp_count, 0)) as epp_total "
            "FROM hourly_tag_counts "
            "WHERE hour_timestamp >= ? AND cid = ? "
            "GROUP BY tag ORDER BY total DESC",
            (cutoff, cid_filter),
        )
    else:
        cursor = conn.execute(
            "SELECT tag, "
            "SUM(unique_sensor_count) as total, "
            "SUM(COALESCE(fcs_count, 0)) as fcs_total, "
            "SUM(COALESCE(fcsc_count, 0)) as fcsc_total, "
            "SUM(COALESCE(fmc_count, 0)) as fmc_total, "
            "SUM(COALESCE(epp_count, 0)) as epp_total "
            "FROM hourly_tag_counts "
            "WHERE hour_timestamp >= ? "
            "GROUP BY tag ORDER BY total DESC",
            (cutoff,),
        )

    rows = []
    for row in cursor.fetchall():
        rows.append({
            "tag": row["tag"],
            "fcs_28day_avg": f"{row['fcs_total'] / collected_hours:.1f}",
            "fcsc_28day_avg": f"{row['fcsc_total'] / collected_hours:.1f}",
            "fmc_28day_avg": f"{row['fmc_total'] / collected_hours:.1f}",
            "epp_28day_avg": f"{row['epp_total'] / collected_hours:.1f}",
            "total_28day_avg": f"{row['total'] / collected_hours:.1f}",
        })

    if not rows:
        print("No tag data found. Run 'falcon-billing collect' first.", file=sys.stderr)
        sys.exit(1)

    if args.format == "consolidated":
        # Flat format: one row per tag + license_type combination
        consolidated_rows = []
        for row in rows:
            for sku, col in [("FCS", "fcs_28day_avg"), ("FCSC", "fcsc_28day_avg"),
                             ("FMC", "fmc_28day_avg"), ("EPP", "epp_28day_avg")]:
                value = float(row[col])
                if value > 0:
                    consolidated_rows.append({
                        "sensor_tag": row["tag"],
                        "license_type": sku,
                        "allot_unit": row[col],
                    })

        fieldnames = ["sensor_tag", "license_type", "allot_unit"]
        output_rows = consolidated_rows
    else:
        # Default pivot format: one row per tag with SKU columns
        fieldnames = ["tag", "fcs_28day_avg", "fcsc_28day_avg", "fmc_28day_avg", "epp_28day_avg", "total_28day_avg"]
        output_rows = rows

    if args.output:
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)
        print(f"Tag report written to {args.output}", file=sys.stderr)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"\n{len(rows)} tags, {collected_hours} hours collected (target: {target_hours})", file=sys.stderr)
    db.log_audit("tag_report", f"days={args.days}, tags={len(rows)}, hours={collected_hours}", "cli")


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
