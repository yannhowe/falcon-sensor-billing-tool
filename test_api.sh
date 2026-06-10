#!/bin/bash
python3 web_dashboard.py > /tmp/dashboard.log 2>&1 &
PID=$!
sleep 3
curl -s "http://localhost:5000/api/product_breakdown?days=28"
kill $PID
