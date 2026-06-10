"""Flask dashboard for Falcon sensor FCS licensing."""

import math
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


def _csv_safe(value: str) -> str:
    """Sanitize a value for CSV to prevent formula injection in Excel."""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    if "," in s or '"' in s or "\n" in s:
        s = '"' + s.replace('"', '""') + '"'
    return s

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from falcon_billing.web.auth import require_api_key


def create_app(db_path: str = None) -> Flask:
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    # Resolve database path
    app.config["DB_PATH"] = db_path or os.environ.get(
        "FALCON_BILLING_DB", str(Path.cwd() / "sensor_billing.db")
    )

    def get_db():
        """Get a database connection with row factory."""
        db_file = app.config["DB_PATH"]
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row
        return conn

    # ----------------------------------------------------------------
    # Page routes
    # ----------------------------------------------------------------

    @app.route("/")
    def index():
        return redirect(url_for("fcs_licensing"))

    @app.route("/fcs")
    def fcs_licensing():
        return render_template("fcs_licensing.html")

    @app.route("/comparison")
    def comparison():
        return render_template("comparison.html")

    @app.route("/methodology")
    def methodology():
        return render_template("methodology.html")

    # ----------------------------------------------------------------
    # FCS Licensing API routes
    # ----------------------------------------------------------------

    @app.route("/api/fcs/summary")
    @require_api_key
    def api_fcs_summary():
        """28-day rolling averages per CID and per tag for FCS licensing."""
        conn = get_db()
        try:
            target_hours = 672
            cutoff = (datetime.utcnow() - timedelta(hours=target_hours)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # Total hours collected across the system
            hours_row = conn.execute(
                "SELECT COUNT(DISTINCT hour_timestamp) as total_hours "
                "FROM hourly_counts WHERE hour_timestamp >= ?",
                (cutoff,),
            ).fetchone()
            collected_hours = hours_row["total_hours"] or 0

            # Per-CID summary
            cid_cursor = conn.execute(
                "SELECT cid, "
                "SUM(unique_sensor_count) as total, "
                "SUM(COALESCE(fcs_count, 0)) as fcs_total, "
                "SUM(COALESCE(epp_count, 0)) as epp_total, "
                "SUM(COALESCE(fcsc_count, 0)) as fcsc_total, "
                "SUM(COALESCE(fmc_count, 0)) as fmc_total, "
                "MAX(unique_sensor_count) as max_sensors, "
                "MIN(unique_sensor_count) as min_sensors, "
                "COUNT(*) as hours_collected "
                "FROM hourly_counts "
                "WHERE hour_timestamp >= ? "
                "GROUP BY cid",
                (cutoff,),
            )
            cids = []
            overall_total = 0
            overall_max = 0

            # EPP uses weekly averaging (avg of daily peaks over 7 days)
            cutoff_7d = (datetime.utcnow() - timedelta(days=7)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            for row in cid_cursor.fetchall():
                avg = row["total"] / collected_hours if collected_hours else 0
                fcs_avg = row["fcs_total"] / collected_hours if collected_hours else 0
                fcsc_avg = row["fcsc_total"] / collected_hours if collected_hours else 0
                fmc_avg = row["fmc_total"] / collected_hours if collected_hours else 0

                # EPP weekly avg: average of daily peak EPP counts over 7 days
                epp_daily = conn.execute(
                    "SELECT DATE(hour_timestamp) as day, "
                    "MAX(COALESCE(epp_count, 0)) as daily_peak "
                    "FROM hourly_counts "
                    "WHERE hour_timestamp >= ? AND cid = ? AND epp_count IS NOT NULL "
                    "GROUP BY DATE(hour_timestamp)",
                    (cutoff_7d, row["cid"]),
                ).fetchall()
                if epp_daily:
                    epp_avg = sum(r["daily_peak"] for r in epp_daily) / len(epp_daily)
                else:
                    # Fallback to hourly avg if no weekly data available
                    epp_avg = row["epp_total"] / collected_hours if collected_hours else 0

                cids.append({
                    "cid": row["cid"],
                    "avg_sensors": round(avg, 2),
                    "fcs_avg": round(fcs_avg, 2),
                    "epp_avg": round(epp_avg, 2),
                    "fcsc_avg": round(fcsc_avg, 2),
                    "fmc_avg": round(fmc_avg, 2),
                    "max_sensors": row["max_sensors"],
                    "min_sensors": row["min_sensors"],
                    "hours_collected": row["hours_collected"],
                    "licenses_required": math.ceil(avg),
                })
                overall_total += row["total"]
                overall_max = max(overall_max, row["max_sensors"])

            # Per-tag summary
            tag_cursor = conn.execute(
                "SELECT tag, "
                "SUM(unique_sensor_count) as total, "
                "MAX(unique_sensor_count) as max_sensors, "
                "COUNT(*) as hours_active "
                "FROM hourly_tag_counts "
                "WHERE hour_timestamp >= ? "
                "GROUP BY tag "
                "ORDER BY total DESC",
                (cutoff,),
            )
            tags = []
            for row in tag_cursor.fetchall():
                avg = row["total"] / collected_hours if collected_hours else 0
                tags.append({
                    "tag": row["tag"],
                    "avg_sensors": round(avg, 2),
                    "max_sensors": row["max_sensors"],
                    "hours_active": row["hours_active"],
                    "allocation_units": math.ceil(avg),
                })

            return jsonify({
                "overall_avg_sensors": round(overall_total / collected_hours, 2) if collected_hours else 0,
                "overall_max_sensors": overall_max,
                "hours_in_window": collected_hours,
                "target_hours": target_hours,
                "cids": cids,
                "tags": tags,
            })
        finally:
            conn.close()

    @app.route("/api/fcs/tag_detail/<path:tag>")
    @require_api_key
    def api_fcs_tag_detail(tag):
        """Hourly breakdown for a specific tag."""
        conn = get_db()
        try:
            cutoff = (datetime.utcnow() - timedelta(hours=672)).strftime("%Y-%m-%d %H:%M:%S")
            cursor = conn.execute(
                "SELECT hour_timestamp, unique_sensor_count "
                "FROM hourly_tag_counts "
                "WHERE tag = ? AND hour_timestamp >= ? "
                "ORDER BY hour_timestamp",
                (tag, cutoff),
            )
            rows = [
                {"hour": r["hour_timestamp"], "count": r["unique_sensor_count"]}
                for r in cursor.fetchall()
            ]
            return jsonify(rows)
        finally:
            conn.close()

    # ----------------------------------------------------------------
    # Licensing Comparison (EPP-only vs FCS split)
    # ----------------------------------------------------------------

    @app.route("/api/fcs/comparison")
    @require_api_key
    def api_fcs_comparison():
        """Compare licensing: all-EPP (weekly avg) vs FCS split (hourly avg).

        Shows the license savings from proper FCS/FCSC/FMC classification
        versus billing everything as EPP.
        """
        conn = get_db()
        try:
            # --- Scenario B: FCS split (hourly averages, 28-day window) ---
            target_hours = 672
            cutoff_28d = (datetime.utcnow() - timedelta(hours=target_hours)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            hours_row = conn.execute(
                "SELECT COUNT(DISTINCT hour_timestamp) as total_hours "
                "FROM hourly_counts WHERE hour_timestamp >= ?",
                (cutoff_28d,),
            ).fetchone()
            collected_hours_28d = hours_row["total_hours"] or 0

            row_28d = conn.execute(
                "SELECT "
                "SUM(unique_sensor_count) as total, "
                "SUM(COALESCE(fcs_count, 0)) as fcs_total, "
                "SUM(COALESCE(epp_count, 0)) as epp_total, "
                "SUM(COALESCE(fcsc_count, 0)) as fcsc_total, "
                "SUM(COALESCE(fmc_count, 0)) as fmc_total "
                "FROM hourly_counts WHERE hour_timestamp >= ?",
                (cutoff_28d,),
            ).fetchone()

            if collected_hours_28d > 0 and row_28d["total"]:
                fcs_avg = row_28d["fcs_total"] / collected_hours_28d
                epp_avg = row_28d["epp_total"] / collected_hours_28d
                fcsc_avg = row_28d["fcsc_total"] / collected_hours_28d
                fmc_avg = row_28d["fmc_total"] / collected_hours_28d
                total_avg = row_28d["total"] / collected_hours_28d
            else:
                fcs_avg = epp_avg = fcsc_avg = fmc_avg = total_avg = 0

            # FCS split: FCS + FCSC + FMC use hourly avg, EPP uses 7-day weekly avg
            # EPP weekly avg = average of daily unique EPP counts over 7 days
            cutoff_7d = (datetime.utcnow() - timedelta(days=7)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # For EPP weekly: get max epp_count per day, average over days with data
            epp_daily = conn.execute(
                "SELECT DATE(hour_timestamp) as day, MAX(COALESCE(epp_count, 0)) as daily_peak "
                "FROM hourly_counts "
                "WHERE hour_timestamp >= ? AND epp_count IS NOT NULL "
                "GROUP BY DATE(hour_timestamp)",
                (cutoff_7d,),
            ).fetchall()

            if epp_daily:
                epp_weekly_avg = sum(r["daily_peak"] for r in epp_daily) / len(epp_daily)
            else:
                epp_weekly_avg = epp_avg  # fallback to hourly avg if no weekly data

            fcs_split_total = math.ceil(fcs_avg) + math.ceil(epp_weekly_avg) + math.ceil(fcsc_avg) + math.ceil(fmc_avg)

            # --- Scenario A: All-EPP (weekly average of daily peaks) ---
            # If everything were EPP: daily peak of total sensors, averaged over 7 days
            total_daily = conn.execute(
                "SELECT DATE(hour_timestamp) as day, MAX(unique_sensor_count) as daily_peak "
                "FROM hourly_counts "
                "WHERE hour_timestamp >= ? "
                "GROUP BY DATE(hour_timestamp)",
                (cutoff_7d,),
            ).fetchall()

            if total_daily:
                all_epp_weekly_avg = sum(r["daily_peak"] for r in total_daily) / len(total_daily)
            else:
                all_epp_weekly_avg = total_avg

            all_epp_licenses = math.ceil(all_epp_weekly_avg)

            # Delta
            savings = all_epp_licenses - fcs_split_total
            savings_pct = (savings / all_epp_licenses * 100) if all_epp_licenses > 0 else 0

            return jsonify({
                "scenario_a": {
                    "name": "All sensors on EPP",
                    "method": "Weekly avg of daily peaks (7 days)",
                    "licenses": all_epp_licenses,
                    "daily_peaks": [{"day": r["day"], "peak": r["daily_peak"]} for r in total_daily] if total_daily else [],
                },
                "scenario_b": {
                    "name": "FCS/EPP/FCSC/FMC split",
                    "method": "FCS/FCSC/FMC: 28-day hourly avg | EPP: 7-day weekly avg",
                    "fcs_licenses": math.ceil(fcs_avg),
                    "epp_licenses": math.ceil(epp_weekly_avg),
                    "fcsc_licenses": math.ceil(fcsc_avg),
                    "fmc_licenses": math.ceil(fmc_avg),
                    "total_licenses": fcs_split_total,
                },
                "delta": {
                    "savings": savings,
                    "savings_pct": round(savings_pct, 1),
                },
                "data_coverage": {
                    "hours_28d": collected_hours_28d,
                    "days_7d": min(len(epp_daily) if epp_daily else 0, 7),
                },
            })
        finally:
            conn.close()

    # ----------------------------------------------------------------
    # Streaming CSV exports
    # ----------------------------------------------------------------

    @app.route("/api/fcs/export")
    @require_api_key
    def api_fcs_export():
        """FCS licensing CSV export (CID or tag)."""
        export_type = request.args.get("type", "cid")
        conn = get_db()
        cutoff = (datetime.utcnow() - timedelta(hours=672)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Total hours collected for averaging
        hours_row = conn.execute(
            "SELECT COUNT(DISTINCT hour_timestamp) as total_hours "
            "FROM hourly_counts WHERE hour_timestamp >= ?",
            (cutoff,),
        ).fetchone()
        collected_hours = hours_row["total_hours"] or 1

        def generate_cid():
            yield "cid,28day_avg,fcs_avg,epp_weekly_avg,fcsc_avg,fmc_avg,max_hourly,min_hourly,hours_collected,licenses_required\n"
            cutoff_7d = (datetime.utcnow() - timedelta(days=7)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            cursor = conn.execute(
                "SELECT cid, SUM(unique_sensor_count) as total, "
                "SUM(COALESCE(fcs_count, 0)) as fcs_total, "
                "SUM(COALESCE(epp_count, 0)) as epp_total, "
                "SUM(COALESCE(fcsc_count, 0)) as fcsc_total, "
                "SUM(COALESCE(fmc_count, 0)) as fmc_total, "
                "MAX(unique_sensor_count) as max_s, "
                "MIN(unique_sensor_count) as min_s, "
                "COUNT(*) as hours "
                "FROM hourly_counts WHERE hour_timestamp >= ? "
                "GROUP BY cid",
                (cutoff,),
            )
            for row in cursor:
                avg = row["total"] / collected_hours
                fcs_avg = row["fcs_total"] / collected_hours
                fcsc_avg = row["fcsc_total"] / collected_hours
                fmc_avg = row["fmc_total"] / collected_hours
                # EPP uses weekly avg (avg of daily peaks over 7 days)
                epp_daily = conn.execute(
                    "SELECT DATE(hour_timestamp) as day, "
                    "MAX(COALESCE(epp_count, 0)) as daily_peak "
                    "FROM hourly_counts "
                    "WHERE hour_timestamp >= ? AND cid = ? AND epp_count IS NOT NULL "
                    "GROUP BY DATE(hour_timestamp)",
                    (cutoff_7d, row["cid"]),
                ).fetchall()
                if epp_daily:
                    epp_avg = sum(r["daily_peak"] for r in epp_daily) / len(epp_daily)
                else:
                    epp_avg = row["epp_total"] / collected_hours
                yield (
                    f"{_csv_safe(row['cid'])},{avg:.2f},{fcs_avg:.2f},{epp_avg:.2f},"
                    f"{fcsc_avg:.2f},{fmc_avg:.2f},{row['max_s']},"
                    f"{row['min_s']},{row['hours']},{math.ceil(avg)}\n"
                )
            conn.close()

        def generate_tag():
            yield "tag,28day_avg,max_hourly,hours_active,allocation_units\n"
            cursor = conn.execute(
                "SELECT tag, SUM(unique_sensor_count) as total, "
                "MAX(unique_sensor_count) as max_s, "
                "COUNT(*) as hours "
                "FROM hourly_tag_counts WHERE hour_timestamp >= ? "
                "GROUP BY tag ORDER BY total DESC",
                (cutoff,),
            )
            for row in cursor:
                avg = row["total"] / collected_hours
                yield f"{_csv_safe(row['tag'])},{avg:.2f},{row['max_s']},{row['hours']},{math.ceil(avg)}\n"
            conn.close()

        gen_func = generate_cid if export_type == "cid" else generate_tag
        filename = f"fcs_licensing_{export_type}_{datetime.utcnow().strftime('%Y%m%d')}.csv"

        return Response(
            gen_func(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    return app


def main():
    """Standalone entry point for the dashboard (used by cmd_dashboard)."""
    app = create_app()
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="127.0.0.1", port=port, debug=False)
