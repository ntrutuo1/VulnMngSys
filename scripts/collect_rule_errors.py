"""Collect non-Collected rule evaluations and save to reports/scan_errors.json
Run from project root (where `vulnmngsys_app.services.scanflow` is importable).
"""
import json
from pathlib import Path
import sys

# Ensure project root (one level up from scripts/) is on sys.path so
# `vulnmngsys_app.services.scanflow` can be imported when running this script directly.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulnmngsys_app.services.scanflow.json_rule_engine import _compare_rule, _load_snapshots

OUT = Path('reports')
OUT.mkdir(exist_ok=True)
OUT_FILE = OUT / 'scan_errors.json'

try:
    snap = _load_snapshots()
except Exception:
    snap = None
results = []

for path in sorted(Path('rules').glob('*.json')):
    try:
        payload = json.loads(path.read_text(encoding='utf-8-sig'))
    except Exception as e:
        results.append({
            'file': str(path),
            'error': f'json-load-error: {e}'
        })
        continue

    if isinstance(payload, list):
        for rule in payload:
            try:
                res = _compare_rule(rule, snap or _load_snapshots())
                if getattr(res, 'status', None) != 'Collected':
                    results.append({
                        'file': str(path),
                        'id': rule.get('id'),
                        'title': rule.get('title'),
                        'status': getattr(res, 'status', None),
                        'verdict': getattr(res, 'verdict', None),
                        'actual': getattr(res, 'actual', None),
                        'source': getattr(res, 'source', None),
                    })
            except Exception as e:
                results.append({
                    'file': str(path),
                    'id': rule.get('id'),
                    'title': rule.get('title'),
                    'status': 'CollectorError',
                    'error': str(e),
                })

# Save results
OUT_FILE.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Wrote {len(results)} entries to {OUT_FILE}')
