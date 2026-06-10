# Web Dashboard & CSV Export

## Quick Start

### Start the Dashboard

```bash
cd /Users/ykwan/Documents/code/knowledgebase/projects/falcon-sensor-billing-tool
python3 web_dashboard.py
```

The dashboard will be available at: **http://localhost:5000**

### Features

#### **NEW: Licensing Compliance Calculator** 🆕
- Calculate Reserved Hourly Average Sensor License compliance
- Calculate Reserved Sensor License (per clock-hour) compliance
- Track on-demand sensor license consumption
- Visual compliance status with color-coded indicators
- Hourly compliance chart showing usage vs reserved limits
- See [LICENSING_COMPLIANCE.md](LICENSING_COMPLIANCE.md) for detailed guide

#### Web Dashboard
- **Real-time Statistics**: Total sensors, hours collected, 28-day average, unique tags
- **Interactive Charts**:
  - Hourly sensor count trend (line chart)
  - Daily average comparison (bar chart with min/max/avg)
- **Tag Breakdown Table**: Shows billing allocation by sensor tags
- **Recent Sensors Table**: Lists most recently active sensors with details
- **Time Range Selector**: View data for last 1, 3, 7, 14, or 28 days

#### CSV Export Options

**4 Export Types Available:**

1. **Hourly Export** - Raw hourly sensor counts
   - Columns: Timestamp, CID, Sensor Count, Collection Method
   - One row per hour collected

2. **Daily Export** - Daily aggregated statistics
   - Columns: Date, Average Count, Max Count, Min Count, Hours Collected
   - One row per day

3. **Tags Export** - Billing breakdown by tag
   - Columns: Tag, Average Count, Total Hours, Hours Active
   - Perfect for sub-CID cost allocation

4. **Sensors Export** - Detailed sensor information
   - Columns: Sensor ID, Hostname, Platform, OS Version, Tags, Last Seen, Hours Active
   - Full audit trail of all sensors

### API Endpoints

All endpoints return JSON:

- `GET /api/stats` - Overall statistics
- `GET /api/hourly_trend?days=7` - Hourly sensor counts
- `GET /api/daily_averages?days=28` - Daily averages with min/max
- `GET /api/tag_breakdown?days=28&limit=20` - Top tags by sensor count
- `GET /api/recent_sensors?limit=50` - Recently active sensors
- `GET /api/export/csv?type=hourly&days=7` - CSV export (types: hourly, daily, tags, sensors)

### Example API Usage

```bash
# Get overall stats
curl http://localhost:5000/api/stats | python3 -m json.tool

# Export last 7 days to CSV
curl "http://localhost:5000/api/export/csv?type=daily&days=7" -o billing_export.csv

# Get tag breakdown for cost allocation
curl "http://localhost:5000/api/tag_breakdown?days=28" | python3 -m json.tool

# Export full sensor details
curl "http://localhost:5000/api/export/csv?type=sensors&days=28" -o sensor_details.csv
```

### Integration Examples

#### Export to Google Sheets
```bash
# Export daily billing
curl "http://localhost:5000/api/export/csv?type=daily&days=28" -o /tmp/billing.csv
# Upload to Google Sheets (requires gsheet CLI or manual upload)
```

#### Automated Reporting
```bash
# Add to cron for daily exports
0 1 * * * cd /path/to/project && curl "http://localhost:5000/api/export/csv?type=daily&days=28" -o "/reports/billing_$(date +\%Y\%m\%d).csv"
```

#### Custom Queries
```bash
# Get JSON data for custom processing
curl "http://localhost:5000/api/daily_averages?days=90" | jq '.[] | select(.avg > 250)'
```

## Technical Details

### Dependencies
- **Flask 3.0+** - Web framework
- **Chart.js 4.4** - Frontend charting (loaded from CDN)
- **SQLite3** - Database (Python built-in)

### Port Configuration
Default port: 5000

To change port, edit `web_dashboard.py:363`:
```python
app.run(debug=True, host='0.0.0.0', port=8080)  # Change to desired port
```

### Security Notes
- Dashboard binds to `0.0.0.0` (all interfaces) - accessible from network
- No authentication by default
- For production use, add authentication or bind to `127.0.0.1` only
- Consider using reverse proxy (nginx) with HTTPS for external access

### Troubleshooting

**Port already in use:**
```bash
# Find process using port 5000
lsof -ti:5000
# Kill it
kill $(lsof -ti:5000)
```

**Module not found:**
```bash
pip3 install --break-system-packages flask requests
```

**Database not found:**
```bash
# Run collector first to create database
python3 billing_collector.py --collect-hourly
```

## Dashboard Screenshots

The dashboard provides:
- 📊 Statistics cards showing key metrics
- 📈 Interactive line chart for hourly trends
- 📊 Bar chart for daily comparisons
- 🏷️ Tag breakdown table for cost allocation
- 🖥️ Recent sensors list with platform details
- 📤 One-click CSV export buttons

## CSV Export Examples

### Daily Billing Export
```csv
Date,Average Count,Max Count,Min Count,Hours Collected
2026-04-07,244.0,244,244,1
2026-04-08,237.38,251,233,24
2026-04-09,241.79,246,239,24
```

### Tag Breakdown Export
```csv
Tag,Average Count,Total Hours,Hours Active
Linux86,18.45,3119,169
SVCSDEPLOY-TEST,21.12,3569,169
production,45.23,7644,169
```

### Sensor Details Export
```csv
Sensor ID,Hostname,Platform,OS Version,Tags,Last Seen,Hours Active
abc123...,host01,Linux,Ubuntu 22.04,production,2026-04-14 15:00:00,169
def456...,host02,Windows,Server 2022,test,2026-04-14 14:00:00,156
```
