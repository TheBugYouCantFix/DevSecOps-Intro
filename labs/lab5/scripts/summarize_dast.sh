#!/usr/bin/env bash
# Summarize DAST tool results
set -e
cd "$(dirname "$0")/../.."
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

echo "=== DAST Tool Summary ==="
echo ""
echo "ZAP (baseline):"
[ -f labs/lab5/zap/report-noauth.html ] && echo "  report-noauth.html: $(wc -l < labs/lab5/zap/report-noauth.html) lines" || echo "  Not found"
[ -f labs/lab5/zap/report-auth.html ] && echo "  report-auth.html: $(wc -l < labs/lab5/zap/report-auth.html) lines" || echo "  report-auth.html: Not found"
echo ""
echo "Nuclei:"
[ -f labs/lab5/nuclei/nuclei-results.json ] && echo "  nuclei-results.json: $(wc -l < labs/lab5/nuclei/nuclei-results.json) findings" || echo "  Not found"
echo ""
echo "Nikto:"
[ -f labs/lab5/nikto/nikto-results.txt ] && echo "  nikto-results.txt: $(wc -l < labs/lab5/nikto/nikto-results.txt) lines" || echo "  Not found"
echo ""
echo "SQLmap:"
sqlmap_csv=$(find labs/lab5/sqlmap -name "*.csv" 2>/dev/null | head -1)
[ -n "$sqlmap_csv" ] && echo "  SQL injection findings: $(tail -n +2 "$sqlmap_csv" 2>/dev/null | grep -v '^$' | wc -l)" || echo "  No results"
