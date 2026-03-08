#!/usr/bin/env bash
# Compare ZAP authenticated vs unauthenticated scan URL discovery
set -e
cd "$(dirname "$0")/../.."
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

echo "=== ZAP Scan Comparison ==="
echo ""
echo "Unauthenticated scan (baseline):"
echo "  Report: labs/lab5/zap/report-noauth.html"
if [ -f labs/lab5/zap/zap-report-noauth.json ]; then
  noauth_sites=$(jq -r '.site[] | .@host' labs/lab5/zap/zap-report-noauth.json 2>/dev/null | sort -u | wc -l)
  noauth_alerts=$(jq '[.site[].alerts[]] | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
  echo "  Sites: $noauth_sites"
  echo "  Total alerts: $noauth_alerts"
fi
echo ""
echo "Authenticated scan:"
if [ -f labs/lab5/zap/report-auth.html ]; then
  echo "  Report: labs/lab5/zap/report-auth.html (exists)"
  auth_alerts=$(grep -c 'class="risk-' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
  echo "  Risk alerts in report: ~$auth_alerts"
else
  echo "  Report: labs/lab5/zap/report-auth.html (not yet generated)"
  echo "  Run: docker run --rm --network host -v \$(pwd)/labs/lab5:/zap/wrk:Z zaproxy/zap-stable zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml"
fi
echo ""
echo "Expected: Authenticated scan discovers 5-10x more URLs (admin, basket, orders, etc.)"
