"""Render saved measurement evidence into a self-contained printable report."""
import html
import json
from pathlib import Path
import sqlite3
import xml.etree.ElementTree as ET

base = Path(__file__).parent
out = base/'results'
data = json.loads((out/'experiments.json').read_text())
dbs = list((base/'work').glob('*/lab.db'))
db = max(dbs, key=lambda p:p.stat().st_mtime)
with sqlite3.connect(db) as c:
    counts = dict(c.execute('select verdict,count(*) from alerts group by verdict'))
data['postShutdownAlertCounts'] = counts
(out/'experiments.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
tr = ''.join(f"<tr><td>{html.escape(s['scenario'])}</td><td>{s['passed']}/{s['trials']}</td><td>{s['medianMs']:.2f}</td><td>{s['p95Ms']:.2f}</td></tr>" if s['medianMs'] is not None else f"<tr><td>{s['scenario']}</td><td>{s['passed']}/{s['trials']}</td><td>—</td><td>—</td></tr>" for s in data['summary'])
testrows = ''
failures=[]
for suite in ['backend','network']:
    root=ET.parse(out/f'{suite}-tests-final.xml')
    s=next(root.iter('testsuite')).attrib
    passed=int(s['tests'])-int(s['failures'])-int(s['errors'])-int(s['skipped'])
    testrows+=f"<tr><td>{suite}</td><td>{passed}</td><td>{s['failures']}</td><td>{s['skipped']}</td><td>{s['time']} s</td></tr>"
    failures += [t.attrib['name'] for t in root.iter('testcase') if t.find('failure') is not None]
bars=''
for i,s in enumerate(data['summary'][:4]+[data['summary'][6]]):
    y=40+i*45
    bars+=f'<text x="10" y="{y+16}">{s["scenario"].replace("renamed-copy-to-synthetic-usb","Copy alert (synthetic USB)")}</text><rect x="255" y="{y}" width="{s["medianMs"]*.6}" height="25" fill="#247bba"/><text x="{265+s["medianMs"]*.6}" y="{y+17}">{s["medianMs"]:.1f} ms</text>'
report=f'''<!doctype html><html lang="en"><meta charset="utf-8"><title>ExfilTrace laboratory evaluation</title>
<style>body{{font:16px/1.5 system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#182536}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{padding:9px;border:1px solid #cbd5df;text-align:left}}th{{background:#edf3f8}}h1,h2{{color:#164d76}}code{{overflow-wrap:anywhere}}svg{{width:100%;max-width:850px}}@media print{{body{{margin:0}}}}</style>
<h1>ExfilTrace: measured laboratory results</h1><p>Completed: {data['completedAt']}. Environment: {data['platform']}; Python {data['python'].split()[0]}.</p>
<p><strong>Scope:</strong> real Windows filesystem monitoring and SQLite persistence; synthetic USB device/mount and synthetic network flow inputs. No physical USB latency, live network detection, physical BadUSB verdict, dashboard latency or recovery success rate was measured.</p>
<h2>Repeated experiments</h2><p>80/80 filesystem operations recorded; 20/20 renamed 64 KiB copies verified on a simulated USB mount. Five fixed network scenarios repeated 20 times each matched their expected alert behavior (60 alert-positive and 40 alert-negative trials). This is scenario conformance, not an estimate of real-world attack accuracy.</p>
<svg viewBox="0 0 850 290" role="img" aria-label="Median observation delays"><text x="10" y="20" font-weight="bold">Median backend observation delay</text>{bars}</svg>
<table><tr><th>Scenario</th><th>Passed / trials</th><th>Median ms</th><th>95th percentile ms</th></tr>{tr}</table>
<h2>Methodology and interpretation</h2><p>{data['methodology']}</p>
<p>Latency uses a monotonic clock from immediately before the operation until a matching database record is observed; includes operation duration and query overhead. Timeout: 8 seconds. P95 uses nearest rank. File modifications waited 1.6 seconds after creation to respect the default 1.5-second deduplication window. These results do not assess rapid successive writes or sustained load. Copy trials used different known 65,536-byte contents and renamed destination files. The 0.5-second default stability check contributes to copy-alert delay.</p>
<p>USB insertion/removal trials force a synthetic inventory poll and exclude the default 3-second polling delay and Windows hardware enumeration. Network trials reset a 20-sample baseline (200,000–240,000 bytes) each time and use a documentation IP without transmitting traffic: 250,000-byte known destination; 10,000,000-byte known destination; 1,500,000-byte new destination; 1,000-byte external port 4444; and 1,000-byte new destination on port 443. Network timings are function execution time only.</p>
<p>Negative file controls used 20 unmatched files on the simulated USB. Immediate checks used 0.3-second observation windows; after service shutdown and worker draining, the database contained exactly {counts.get('VERIFIED_TRANSFER',0)} verified-transfer alerts, all accounted for by the 20 positive copies. It also contained {counts.get('SUSPICIOUS',0)} SUSPICIOUS alert from heuristic activity. Therefore report zero extra <em>verified-transfer</em> alerts for these controls, not zero alerts overall or a general zero false-positive rate.</p>
<h2>Existing automated regression suites</h2><table><tr><th>Suite</th><th>Passed</th><th>Failed</th><th>Skipped</th><th>Suite duration</th></tr>{testrows}</table>
<p>Total: 189 passed, 3 failed, 2 skipped across 194 collected tests. Passing regression assertions are not attack-detection accuracy. Existing tests include transfer-count boundaries, exactly 5,000,000 versus 5,000,001 bytes, aggregate bytes, renamed matching, USB fingerprint/simulation isolation and mocked network capture.</p>
<p>Failures: {', '.join(failures)}. Inspection shows POSIX path string expectations in mocked lookup tests encountering Windows Path normalization. These are unresolved portability/test failures, not proof that actual installed TShark capture fails. Both skipped tests require Sleuth Kit for real FAT32 tool integration. Recovery success is unavailable.</p>
<p>Initial attempts failed because the default pytest temporary directory was inaccessible; a subsequent custom-basetemp attempt lacked its parent directory. Final suite XML files use a writable workspace basetemp and contain no setup errors. Initial attempts are excluded from the totals above.</p>
<h2>Exploratory process CPU measurements</h2><table><tr><th>Phase</th><th>Duration seconds</th><th>CPU percent of one core</th></tr>'''+''.join(f"<tr><td>{r['phase']}</td><td>{r['durationSeconds']:.2f}</td><td>{r['processCpuPercentOneCore']:.2f}</td></tr>" for r in data['resources'])+'''</table>
<p>CPU measures process CPU time divided by elapsed time, including the benchmark driver and database polling. Idle samples last only five seconds; displayed zero is below timer resolution over that interval, not zero resource consumption. File-action phase includes intentional waits. These are exploratory harness measurements, not production service overhead. Memory was not measured.</p>
<h2>Report-ready results paragraph</h2><blockquote>In a controlled Windows laboratory evaluation, ExfilTrace recorded all 80 tested filesystem operations and generated verified-transfer alerts for all 20 renamed file copies to a simulated USB mount. Median observable backend delays ranged from 27.37 to 35.61 ms for file events, while median copy-alert delay was 687.05 ms (95th percentile: 714.48 ms). Five synthetic network scenarios matched expected rule behavior across 100 repetitions. Regression testing yielded 189 passes, three unresolved Windows path-lookup test failures and two recovery-tool-dependent skips. Results validate the tested software scenarios; physical USB behavior, live network detection and recovery effectiveness require additional validation.</blockquote>
<h2>Reproduction and evidence</h2><p>From the repository root, use backend/.venv/Scripts/python.exe to run backend/evaluation/run_experiments.py. Run each pytest suite separately with -p no:cacheprovider, a new --basetemp beneath backend/evaluation/work (create the parent first), and --junitxml beneath backend/evaluation/results. Then run backend/evaluation/build_report.py. Preserve previous results before rerunning.</p><p>Raw observations: experiments.json. Regression evidence: backend-tests-final.xml and network-tests-final.xml. No application source was modified.</p></html>'''
(out/'report.html').write_text(report,encoding='utf-8')
print(out/'report.html')
