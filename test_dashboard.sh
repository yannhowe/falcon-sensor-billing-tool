#!/bin/bash
python3 web_dashboard.py > /tmp/dashboard_test.log 2>&1 &
PID=$!
sleep 3

echo "Testing dashboard APIs..."
echo ""

echo "1. Product breakdown:"
curl -s "http://localhost:5000/api/product_breakdown?days=28" | python3 -m json.tool | head -30

echo ""
echo "2. Stats:"
curl -s "http://localhost:5000/api/stats" | python3 -m json.tool | head -20

kill $PID 2>/dev/null
echo ""
echo "✓ Dashboard test complete"
echo "Visit http://localhost:5000 to see the updated UI"
