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

            for row in cid_cursor.fetchall():
                avg = row["total"] / collected_hours if collected_hours else 0
                cids.append({
                    "cid": row["cid"],
                    "avg_sensors": round(avg, 2),
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
            yield "cid,28day_avg,max_hourly,min_hourly,hours_collected,licenses_required\n"
            cursor = conn.execute(
                "SELECT cid, SUM(unique_sensor_count) as total, "
                "MAX(unique_sensor_count) as max_s, "
                "MIN(unique_sensor_count) as min_s, "
                "COUNT(*) as hours "
                "FROM hourly_counts WHERE hour_timestamp >= ? "
                "GROUP BY cid",
                (cutoff,),
            )
            for row in cursor:
                avg = row["total"] / collected_hours
                yield (
                    f"{_csv_safe(row['cid'])},{avg:.2f},{row['max_s']},"
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
