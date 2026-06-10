#!/usr/bin/env python3
"""
Falcon Sensor Billing Tool - Web Dashboard

Flask web interface for visualizing sensor billing data and exporting reports.
"""
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file
import sqlite3
import json
import csv
import io

# Add FalconPy to path
FALCONPY_PATH = Path(__file__).parent.parent.parent / "repos" / "falconpy" / "src"
sys.path.insert(0, str(FALCONPY_PATH))

app = Flask(__name__)
DB_PATH = Path(__file__).parent / "sensor_billing.db"


def get_db_connection():
    """Get SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/api/licensing/compliance')
def get_licensing_compliance():
    """
    Calculate licensing compliance based on reserved hourly average licenses.

    Query parameters:
    - reserved_hourly_avg: Reserved Hourly Average Sensor License count (default: 0)
    - days: Number of days to analyze (default: 28)
    """
    reserved_hourly_avg = request.args.get('reserved_hourly_avg', default=0, type=int)
    days = request.args.get('days', default=28, type=int)

    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()

    # Get hourly sensor counts
    hourly_data = conn.execute(
        """
        SELECT hour_timestamp, unique_sensor_count
        FROM hourly_counts
        WHERE hour_timestamp >= ?
        ORDER BY hour_timestamp
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchall()

    # Calculate hourly compliance and rolling averages
    total_hours = len(hourly_data)
    hours_in_compliance = 0
    hours_over_reserved = 0
    total_overage_sensors = 0
    max_hourly_usage = 0
    max_hourly_overage = 0
    peak_rolling_avg_28day = 0  # Track PEAK rolling average

    hourly_compliance = []
    for i, row in enumerate(hourly_data):
        count = row['unique_sensor_count']
        max_hourly_usage = max(max_hourly_usage, count)

        # Calculate rolling average at this point in time (last 672 hours from here)
        start_idx = max(0, i - 671)  # Go back 671 hours (+ current = 672)
        window = hourly_data[start_idx:i+1]
        window_sum = sum(r['unique_sensor_count'] for r in window)
        rolling_avg_at_hour = window_sum / len(window)

        # Track the peak rolling average
        peak_rolling_avg_28day = max(peak_rolling_avg_28day, rolling_avg_at_hour)

        # Determine which license type applies
        if reserved_hourly_avg > 0:
            # Using Reserved Hourly Average Sensor License
            # Compare rolling average against reserved quantity
            if rolling_avg_at_hour <= reserved_hourly_avg:
                status = 'compliant'
                overage = 0
                hours_in_compliance += 1
            else:
                status = 'over_reserved'
                overage = rolling_avg_at_hour - reserved_hourly_avg
                hours_over_reserved += 1
        else:
            # No reserved licenses configured
            status = 'no_licenses'
            overage = 0

        hourly_compliance.append({
            'timestamp': row['hour_timestamp'],
            'count': count,
            'rolling_avg': round(rolling_avg_at_hour, 2),
            'status': status,
            'overage': round(overage, 2)
        })

    # Determine overall compliance status
    if reserved_hourly_avg > 0:
        # Reserved Hourly Average licensing
        if peak_rolling_avg_28day <= reserved_hourly_avg:
            overall_status = 'compliant'
            compliance_message = f'Peak rolling average ({peak_rolling_avg_28day:.1f}) is within reserved hourly average limit ({reserved_hourly_avg})'
        else:
            overall_status = 'over_reserved'
            compliance_message = f'Peak rolling average ({peak_rolling_avg_28day:.1f}) exceeds reserved hourly average limit ({reserved_hourly_avg})'
    else:
        overall_status = 'no_licenses'
        compliance_message = 'No reserved licenses configured'

    conn.close()

    return jsonify({
        'overall_status': overall_status,
        'compliance_message': compliance_message,
        'reserved_hourly_avg_license': reserved_hourly_avg,
        'rolling_avg_28day': round(peak_rolling_avg_28day, 2),  # Return PEAK value
        'max_hourly_usage': max_hourly_usage,
        'hours_analyzed': total_hours,
        'hours_in_compliance': hours_in_compliance,
        'hours_over_reserved': hours_over_reserved,
        'hourly_compliance': hourly_compliance[-168:]  # Last 7 days for chart
    })


@app.route('/api/stats')
def get_stats():
    """Get overall statistics."""
    conn = get_db_connection()

    # Get total sensors, hours collected, date range
    total_sensors = conn.execute(
        "SELECT COUNT(DISTINCT sensor_id) FROM sensor_logs"
    ).fetchone()[0]

    total_hours = conn.execute(
        "SELECT COUNT(DISTINCT hour_timestamp) FROM hourly_counts"
    ).fetchone()[0]

    date_range = conn.execute(
        "SELECT MIN(hour_timestamp) as start, MAX(hour_timestamp) as end FROM hourly_counts"
    ).fetchone()

    # Get 28-day average
    cutoff_date = datetime.now() - timedelta(days=28)
    avg_28day = conn.execute(
        """
        SELECT AVG(unique_sensor_count) as avg_count
        FROM hourly_counts
        WHERE hour_timestamp >= ?
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchone()['avg_count']

    # Get unique tags
    unique_tags = conn.execute(
        "SELECT COUNT(DISTINCT tag) FROM hourly_tag_counts WHERE tag IS NOT NULL AND tag != ''"
    ).fetchone()[0]

    # Get cache stats
    cached_hosts = conn.execute(
        "SELECT COUNT(*) FROM host_metadata_cache"
    ).fetchone()[0]

    conn.close()

    return jsonify({
        'total_sensors': total_sensors,
        'total_hours': total_hours,
        'date_start': date_range['start'],
        'date_end': date_range['end'],
        'avg_28day': round(avg_28day, 2) if avg_28day else 0,
        'unique_tags': unique_tags,
        'cached_hosts': cached_hosts
    })


@app.route('/api/hourly_trend')
def get_hourly_trend():
    """Get hourly sensor count trend."""
    days = request.args.get('days', default=7, type=int)
    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT hour_timestamp, unique_sensor_count
        FROM hourly_counts
        WHERE hour_timestamp >= ?
        ORDER BY hour_timestamp
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchall()
    conn.close()

    return jsonify([
        {'timestamp': row['hour_timestamp'], 'count': row['unique_sensor_count']}
        for row in rows
    ])


@app.route('/api/daily_averages')
def get_daily_averages():
    """Get daily average sensor counts."""
    days = request.args.get('days', default=28, type=int)
    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT DATE(hour_timestamp) as date,
               AVG(unique_sensor_count) as avg_count,
               MAX(unique_sensor_count) as max_count,
               MIN(unique_sensor_count) as min_count
        FROM hourly_counts
        WHERE hour_timestamp >= ?
        GROUP BY date
        ORDER BY date
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchall()
    conn.close()

    return jsonify([
        {
            'date': row['date'],
            'avg': round(row['avg_count'], 2),
            'max': row['max_count'],
            'min': row['min_count']
        }
        for row in rows
    ])


@app.route('/api/tag_breakdown')
def get_tag_breakdown():
    """Get billing breakdown by tag."""
    days = request.args.get('days', default=28, type=int)
    limit = request.args.get('limit', default=20, type=int)
    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT tag,
               AVG(unique_sensor_count) as avg_count,
               COUNT(DISTINCT hour_timestamp) as hours_active
        FROM hourly_tag_counts
        WHERE hour_timestamp >= ?
        AND tag IS NOT NULL
        AND tag != ''
        GROUP BY tag
        ORDER BY avg_count DESC
        LIMIT ?
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'), limit)
    ).fetchall()
    conn.close()

    return jsonify([
        {
            'tag': row['tag'],
            'avg_count': round(row['avg_count'], 2),
            'hours_active': row['hours_active']
        }
        for row in rows
    ])


@app.route('/api/recent_sensors')
def get_recent_sensors():
    """Get most recently active sensors."""
    limit = request.args.get('limit', default=50, type=int)

    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT DISTINCT
            sl.sensor_id,
            hmc.hostname,
            hmc.platform_name,
            hmc.tags,
            MAX(sl.hour_timestamp) as last_seen
        FROM sensor_logs sl
        LEFT JOIN host_metadata_cache hmc ON sl.sensor_id = hmc.sensor_id
        GROUP BY sl.sensor_id
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()
    conn.close()

    return jsonify([
        {
            'sensor_id': row['sensor_id'],
            'hostname': row['hostname'] or 'Unknown',
            'platform': row['platform_name'] or 'Unknown',
            'tags': row['tags'] or '',
            'last_seen': row['last_seen']
        }
        for row in rows
    ])


@app.route('/api/export/csv')
def export_csv():
    """Export data as CSV."""
    export_type = request.args.get('type', 'hourly')
    days = request.args.get('days', default=28, type=int)
    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()

    # Create CSV in memory
    output = io.StringIO()

    if export_type == 'hourly':
        # Export hourly counts with 28-day rolling average
        # First get all rows to calculate rolling average
        all_rows = conn.execute(
            """
            SELECT hour_timestamp, cid, unique_sensor_count, collected_at
            FROM hourly_counts
            ORDER BY hour_timestamp
            """
        ).fetchall()

        # Calculate 28-day rolling average for each hour
        rolling_data = []
        for i, row in enumerate(all_rows):
            # Look back up to 672 hours (28 days)
            start_idx = max(0, i - 671)
            window = all_rows[start_idx:i+1]
            total = sum(r['unique_sensor_count'] for r in window)
            rolling_avg = total / len(window)

            # Only include rows within the requested date range
            row_date = datetime.strptime(row['hour_timestamp'], '%Y-%m-%d %H:%M:%S')
            if row_date >= cutoff_date:
                rolling_data.append({
                    'hour_timestamp': row['hour_timestamp'],
                    'cid': row['cid'],
                    'unique_sensor_count': row['unique_sensor_count'],
                    'collected_at': row['collected_at'],
                    'rolling_avg_28day': round(rolling_avg, 2)
                })

        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'CID', 'Sensor Count', '28-Day Rolling Avg', 'Collected At'])
        for row in rolling_data:
            writer.writerow([
                row['hour_timestamp'],
                row['cid'],
                row['unique_sensor_count'],
                row['rolling_avg_28day'],
                row['collected_at']
            ])

        filename = f'sensor_billing_hourly_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    elif export_type == 'daily':
        # Export daily averages
        rows = conn.execute(
            """
            SELECT DATE(hour_timestamp) as date,
                   AVG(unique_sensor_count) as avg_count,
                   MAX(unique_sensor_count) as max_count,
                   MIN(unique_sensor_count) as min_count,
                   COUNT(*) as hours_collected
            FROM hourly_counts
            WHERE hour_timestamp >= ?
            GROUP BY date
            ORDER BY date
            """,
            (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
        ).fetchall()

        writer = csv.writer(output)
        writer.writerow(['Date', 'Average Count', 'Max Count', 'Min Count', 'Hours Collected'])
        for row in rows:
            writer.writerow([
                row['date'],
                round(row['avg_count'], 2),
                row['max_count'],
                row['min_count'],
                row['hours_collected']
            ])

        filename = f'sensor_billing_daily_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    elif export_type == 'tags':
        # Export tag breakdown
        rows = conn.execute(
            """
            SELECT tag,
                   AVG(unique_sensor_count) as avg_count,
                   SUM(unique_sensor_count) as total_hours,
                   COUNT(DISTINCT hour_timestamp) as hours_active
            FROM hourly_tag_counts
            WHERE hour_timestamp >= ?
            AND tag IS NOT NULL
            AND tag != ''
            GROUP BY tag
            ORDER BY avg_count DESC
            """,
            (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
        ).fetchall()

        writer = csv.writer(output)
        writer.writerow(['Tag', 'Average Count', 'Total Hours', 'Hours Active'])
        for row in rows:
            writer.writerow([
                row['tag'],
                round(row['avg_count'], 2),
                row['total_hours'],
                row['hours_active']
            ])

        filename = f'sensor_billing_tags_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    elif export_type == 'sensors':
        # Export sensor details
        rows = conn.execute(
            """
            SELECT DISTINCT
                sl.sensor_id,
                hmc.hostname,
                hmc.platform_name,
                hmc.os_version,
                hmc.tags,
                MAX(sl.hour_timestamp) as last_seen,
                COUNT(DISTINCT sl.hour_timestamp) as hours_active
            FROM sensor_logs sl
            LEFT JOIN host_metadata_cache hmc ON sl.sensor_id = hmc.sensor_id
            WHERE sl.hour_timestamp >= ?
            GROUP BY sl.sensor_id
            ORDER BY hours_active DESC, last_seen DESC
            """,
            (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
        ).fetchall()

        writer = csv.writer(output)
        writer.writerow(['Sensor ID', 'Hostname', 'Platform', 'OS Version', 'Tags', 'Last Seen', 'Hours Active'])
        for row in rows:
            writer.writerow([
                row['sensor_id'],
                row['hostname'] or 'Unknown',
                row['platform_name'] or 'Unknown',
                row['os_version'] or 'Unknown',
                row['tags'] or '',
                row['last_seen'],
                row['hours_active']
            ])

        filename = f'sensor_details_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    else:
        conn.close()
        return jsonify({'error': 'Invalid export type'}), 400

    conn.close()

    # Prepare CSV for download
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


@app.route('/api/product_breakdown')
def get_product_breakdown():
    """Get billing breakdown by product type (FCS, FCSC, FMC, EPP)."""
    conn = get_db_connection()

    # Simple query: Get unique sensor counts by product type from host cache
    rows = conn.execute(
        """
        SELECT
            product_type,
            COUNT(*) as unique_sensors
        FROM host_metadata_cache
        WHERE product_type IS NOT NULL
        GROUP BY product_type
        ORDER BY product_type
        """
    ).fetchall()

    # Get 28-day rolling average from sensor logs
    product_averages = {}
    for product_type in ['FCSC', 'FMC', 'FCS', 'EPP']:
        # Get all hourly counts for this product type
        hourly_rows = conn.execute(
            """
            SELECT hour_timestamp, COUNT(DISTINCT sensor_id) as count
            FROM sensor_logs
            WHERE product_type = ?
            GROUP BY hour_timestamp
            ORDER BY hour_timestamp
            """,
            (product_type,)
        ).fetchall()

        if len(hourly_rows) > 0:
            # Use last 672 hours (28 days) for rolling average
            recent_data = hourly_rows[-min(672, len(hourly_rows)):]
            total = sum(r['count'] for r in recent_data)
            avg_28day = total / len(recent_data)
            product_averages[product_type] = round(avg_28day, 2)
        else:
            product_averages[product_type] = 0

    conn.close()

    # Build response
    products = []
    for row in rows:
        pt = row['product_type']
        products.append({
            'product_type': pt,
            'unique_sensors': row['unique_sensors'],
            'avg_28day': product_averages.get(pt, 0)
        })

    # Ensure all 4 product types are in response
    existing_types = {p['product_type'] for p in products}
    for pt in ['FCSC', 'FMC', 'FCS', 'EPP']:
        if pt not in existing_types:
            products.append({
                'product_type': pt,
                'unique_sensors': 0,
                'avg_28day': 0
            })

    return jsonify({
        'products': sorted(products, key=lambda x: x['product_type']),
        'total_avg_28day': sum(product_averages.values())
    })


@app.route('/api/product_trend')
def get_product_trend():
    """Get hourly sensor count trend by product type."""
    days = request.args.get('days', default=7, type=int)
    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()

    # Get hourly breakdown by product type
    rows = conn.execute(
        """
        SELECT
            hour_timestamp,
            product_type,
            COUNT(DISTINCT sensor_id) as count
        FROM sensor_logs
        WHERE hour_timestamp >= ?
        AND product_type IS NOT NULL
        GROUP BY hour_timestamp, product_type
        ORDER BY hour_timestamp, product_type
        """,
        (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),)
    ).fetchall()
    conn.close()

    # Organize data by timestamp
    data_by_hour = {}
    for row in rows:
        ts = row['hour_timestamp']
        if ts not in data_by_hour:
            data_by_hour[ts] = {'timestamp': ts, 'FCSC': 0, 'FMC': 0, 'FCS': 0, 'EPP': 0}
        data_by_hour[ts][row['product_type']] = row['count']

    return jsonify(list(data_by_hour.values()))


@app.route('/api/cloud_breakdown')
def get_cloud_breakdown():
    """Get billing breakdown by cloud provider with product type details."""
    conn = get_db_connection()

    # Get unique sensor counts by cloud provider
    rows = conn.execute(
        """
        SELECT
            cloud_provider,
            COUNT(*) as unique_sensors
        FROM host_metadata_cache
        WHERE cloud_provider IS NOT NULL
        GROUP BY cloud_provider
        ORDER BY unique_sensors DESC
        """
    ).fetchall()

    # Get 28-day rolling average and product type breakdown from sensor logs
    cloud_data = {}
    for cloud_provider in ['AWS', 'Azure', 'GCP', 'Oracle', 'Alibaba', 'Others-IMDS', 'On-Premise', 'End-User-Device', 'No-IMDS']:
        # Get all hourly counts for this cloud provider (overall)
        hourly_rows = conn.execute(
            """
            SELECT hour_timestamp, COUNT(DISTINCT sensor_id) as count
            FROM sensor_logs
            WHERE cloud_provider = ?
            GROUP BY hour_timestamp
            ORDER BY hour_timestamp
            """,
            (cloud_provider,)
        ).fetchall()

        # Calculate overall 28-day average
        if len(hourly_rows) > 0:
            recent_data = hourly_rows[-min(672, len(hourly_rows)):]
            total = sum(r['count'] for r in recent_data)
            avg_28day = total / len(recent_data)
        else:
            avg_28day = 0

        # Get product type breakdown for this cloud provider
        product_breakdown = {}
        for product_type in ['FCS', 'FCSC', 'FMC', 'EPP']:
            product_rows = conn.execute(
                """
                SELECT hour_timestamp, COUNT(DISTINCT sensor_id) as count
                FROM sensor_logs
                WHERE cloud_provider = ? AND product_type = ?
                GROUP BY hour_timestamp
                ORDER BY hour_timestamp
                """,
                (cloud_provider, product_type)
            ).fetchall()

            if len(product_rows) > 0:
                recent_product = product_rows[-min(672, len(product_rows)):]
                total_product = sum(r['count'] for r in recent_product)
                avg_product = total_product / len(recent_product)
                product_breakdown[product_type] = round(avg_product, 2)
            else:
                product_breakdown[product_type] = 0

        cloud_data[cloud_provider] = {
            'avg_28day': round(avg_28day, 2),
            'products': product_breakdown
        }

    # Get actual date range from data
    date_range_row = conn.execute("""
        SELECT
            MIN(hour_timestamp) as start_date,
            MAX(hour_timestamp) as end_date,
            COUNT(DISTINCT hour_timestamp) as total_hours
        FROM sensor_logs
    """).fetchone()

    conn.close()

    # Build response
    providers = []
    for row in rows:
        cp = row['cloud_provider']
        cloud_info = cloud_data.get(cp, {'avg_28day': 0, 'products': {}})
        providers.append({
            'cloud_provider': cp,
            'unique_sensors': row['unique_sensors'],
            'avg_28day': cloud_info['avg_28day'],
            'fcs_avg': cloud_info['products'].get('FCS', 0),
            'fcsc_avg': cloud_info['products'].get('FCSC', 0),
            'fmc_avg': cloud_info['products'].get('FMC', 0),
            'epp_avg': cloud_info['products'].get('EPP', 0)
        })

    # Sort providers in preferred order: AWS, Azure, GCP, Others-IMDS, No-IMDS, On-Premise, End-User-Device
    sort_order = {
        'AWS': 1,
        'Azure': 2,
        'GCP': 3,
        'Oracle': 4,
        'Alibaba': 5,
        'Others-IMDS': 6,
        'No-IMDS': 7,
        'On-Premise': 8,
        'End-User-Device': 9
    }
    providers.sort(key=lambda x: sort_order.get(x['cloud_provider'], 999))

    total_avg = sum(p['avg_28day'] for p in providers)

    return jsonify({
        'providers': providers,
        'total_avg_28day': total_avg,
        'date_range': {
            'start': date_range_row['start_date'],
            'end': date_range_row['end_date'],
            'total_hours': date_range_row['total_hours'],
            'total_days': round(date_range_row['total_hours'] / 24, 1)
        }
    })


if __name__ == '__main__':
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}")
        print("Run billing collector first to create database.")
        sys.exit(1)

    # Security: Only enable debug mode via environment variable
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))

    if debug_mode:
        print("⚠️  WARNING: Running in DEBUG mode (for development only)")

    print("Starting Falcon Sensor Billing Dashboard...")
    print(f"Database: {DB_PATH}")
    print(f"Access dashboard at: http://localhost:{port}")
    print()

    # Security: Bind to localhost only for local use
    app.run(debug=debug_mode, host='127.0.0.1', port=port)
