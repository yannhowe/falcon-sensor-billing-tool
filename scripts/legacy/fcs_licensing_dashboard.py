#!/usr/bin/env python3
"""
FCS Licensing Dashboard

Simple, focused dashboard showing 28-day rolling averages for Falcon Cloud Security licensing.
Shows billing by CID and by tag for accurate license calculation.
"""
import os
import sys
import math
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file
import sqlite3
import csv
import io

app = Flask(__name__, template_folder='templates_fcs', static_folder='static_fcs')
DB_PATH = Path(__file__).parent / "sensor_billing.db"


def get_db_connection():
    """Get SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    """Main FCS licensing dashboard."""
    return render_template('fcs_dashboard.html')


@app.route('/api/fcs/summary')
def get_fcs_summary():
    """
    Get FCS licensing summary - 28-day rolling averages per CID and per tag.
    """
    conn = get_db_connection()

    # Calculate 28-day window (672 hours)
    cutoff_date = datetime.now() - timedelta(days=28)

    # Get 28-day average per CID
    cid_averages = conn.execute(
        """
        SELECT cid,
               COUNT(DISTINCT hour_timestamp) as hours_collected,
               AVG(unique_sensor_count) as avg_sensors,
               MAX(unique_sensor_count) as max_sensors,
               MIN(unique_sensor_count) as min_sensors
        FROM hourly_counts
        WHERE hour_timestamp >= ?
        GROUP BY cid
        ORDER BY avg_sensors DESC
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchall()

    # Get 28-day average per tag (across all CIDs)
    tag_averages = conn.execute(
        """
        SELECT tag,
               COUNT(DISTINCT hour_timestamp) as hours_active,
               AVG(unique_sensor_count) as avg_sensors,
               MAX(unique_sensor_count) as max_sensors
        FROM hourly_tag_counts
        WHERE hour_timestamp >= ?
        AND tag IS NOT NULL
        AND tag != ''
        GROUP BY tag
        ORDER BY avg_sensors DESC
        LIMIT 50
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchall()

    # Get overall stats
    total_hours = conn.execute(
        "SELECT COUNT(DISTINCT hour_timestamp) FROM hourly_counts WHERE hour_timestamp >= ?",
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchone()[0]

    # Calculate total 28-day average across all CIDs
    overall_avg = conn.execute(
        """
        SELECT AVG(unique_sensor_count) as avg_sensors,
               MAX(unique_sensor_count) as max_sensors
        FROM hourly_counts
        WHERE hour_timestamp >= ?
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchone()

    conn.close()

    return jsonify({
        'hours_in_window': total_hours,
        'target_hours': 672,
        'overall_avg_sensors': round(overall_avg['avg_sensors'], 2) if overall_avg['avg_sensors'] else 0,
        'overall_max_sensors': overall_avg['max_sensors'] if overall_avg['max_sensors'] else 0,
        'cid_count': len(cid_averages),
        'tag_count': len(tag_averages),
        'cids': [
            {
                'cid': row['cid'],
                'hours_collected': row['hours_collected'],
                'avg_sensors': round(row['avg_sensors'], 2),
                'max_sensors': row['max_sensors'],
                'min_sensors': row['min_sensors'],
                'licenses_required': math.ceil(row['avg_sensors'])  # Always round UP for licensing
            }
            for row in cid_averages
        ],
        'tags': [
            {
                'tag': row['tag'],
                'hours_active': row['hours_active'],
                'avg_sensors': round(row['avg_sensors'], 2),
                'max_sensors': row['max_sensors'],
                'allocation_units': math.ceil(row['avg_sensors'])  # For cost allocation, not total licenses
            }
            for row in tag_averages
        ]
    })


@app.route('/api/fcs/tag_detail/<tag>')
def get_tag_detail(tag):
    """Get detailed 28-day average breakdown for a specific tag."""
    conn = get_db_connection()
    cutoff_date = datetime.now() - timedelta(days=28)

    # Get hourly data for this tag
    hourly_data = conn.execute(
        """
        SELECT hour_timestamp, unique_sensor_count
        FROM hourly_tag_counts
        WHERE tag = ?
        AND hour_timestamp >= ?
        ORDER BY hour_timestamp
        """,
        (tag, cutoff_date.strftime('%Y-%m-%d %H:%M:%S'))
    ).fetchall()

    # Calculate rolling average at each point
    rolling_data = []
    for i, row in enumerate(hourly_data):
        # Get last 672 hours (or all available if less)
        start_idx = max(0, i - 671)
        window = hourly_data[start_idx:i+1]
        window_sum = sum(r['unique_sensor_count'] for r in window)
        rolling_avg = window_sum / len(window)

        rolling_data.append({
            'timestamp': row['hour_timestamp'],
            'count': row['unique_sensor_count'],
            'rolling_avg': round(rolling_avg, 2)
        })

    conn.close()

    return jsonify({
        'tag': tag,
        'data_points': len(rolling_data),
        'hourly_data': rolling_data[-168:]  # Last 7 days for chart
    })


@app.route('/api/fcs/export')
def export_fcs_licensing():
    """Export FCS licensing data as CSV."""
    export_type = request.args.get('type', 'cid')

    conn = get_db_connection()
    cutoff_date = datetime.now() - timedelta(days=28)

    output = io.StringIO()
    writer = csv.writer(output)

    if export_type == 'cid':
        # Export per-CID licensing
        rows = conn.execute(
            """
            SELECT cid,
                   COUNT(DISTINCT hour_timestamp) as hours_collected,
                   AVG(unique_sensor_count) as avg_sensors,
                   MAX(unique_sensor_count) as max_sensors,
                   MIN(unique_sensor_count) as min_sensors
            FROM hourly_counts
            WHERE hour_timestamp >= ?
            GROUP BY cid
            ORDER BY avg_sensors DESC
            """,
            (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
        ).fetchall()

        writer.writerow(['CID', 'Hours Collected', '28-Day Avg Sensors', 'Max Hourly', 'Min Hourly', 'Licenses Required'])
        for row in rows:
            writer.writerow([
                row['cid'],
                row['hours_collected'],
                round(row['avg_sensors'], 2),
                row['max_sensors'],
                row['min_sensors'],
                math.ceil(row['avg_sensors'])  # Always round UP for licensing
            ])

        filename = f'fcs_licensing_by_cid_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    elif export_type == 'tag':
        # Export per-tag licensing
        rows = conn.execute(
            """
            SELECT tag,
                   COUNT(DISTINCT hour_timestamp) as hours_active,
                   AVG(unique_sensor_count) as avg_sensors,
                   MAX(unique_sensor_count) as max_sensors
            FROM hourly_tag_counts
            WHERE hour_timestamp >= ?
            AND tag IS NOT NULL
            AND tag != ''
            GROUP BY tag
            ORDER BY avg_sensors DESC
            """,
            (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
        ).fetchall()

        writer.writerow(['Tag', 'Hours Active', '28-Day Avg Sensors', 'Max Hourly', 'Allocation Units (not total licenses)'])
        for row in rows:
            writer.writerow([
                row['tag'],
                row['hours_active'],
                round(row['avg_sensors'], 2),
                row['max_sensors'],
                math.ceil(row['avg_sensors'])  # For cost allocation
            ])

        filename = f'fcs_licensing_by_tag_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    conn.close()

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}")
        print("Run billing collector first to create database.")
        sys.exit(1)

    # Security: Only enable debug mode via environment variable
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    if debug_mode:
        print("⚠️  WARNING: Running in DEBUG mode (for development only)")

    print("Starting FCS Licensing Dashboard...")
    print(f"Database: {DB_PATH}")
    print("Access dashboard at: http://localhost:5001")
    print()
    print("Showing 28-day rolling average for FCS license calculation")
    print()

    # Security: Bind to localhost only for local use
    app.run(debug=debug_mode, host='127.0.0.1', port=5001)
