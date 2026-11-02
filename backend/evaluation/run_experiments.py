"""Repeatable lab evaluation. Real filesystem; synthetic USB and network inputs."""
import collections
import ctypes
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'backend'), str(ROOT)]
from app.config import Config
from app.service import MonitoringService
from app.usb.base import UsbBackend, normalize_device
from backend.network.detector import Flow, IntervalStats, OutboundBaseline, FirstSeenTracker, detect_interval

OUT = Path(__file__).parent / 'results'
WORK = Path(__file__).parent / 'work' / str(uuid.uuid4())
WORK.mkdir(parents=True)
OUT.mkdir(exist_ok=True)
rows = []

def utc():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

class FakeUsb(UsbBackend):
    name = 'evaluation-synthetic'
    devices = []
    def snapshot(self):
        return [normalize_device(d) for d in self.devices]

def trial(name, action, predicate, timeout=8):
    stamp, start = utc(), time.perf_counter()
    action()
    result = predicate()
    while not result and time.perf_counter() - start < timeout:
        time.sleep(.01)
        result = predicate()
    rows.append(dict(scenario=name, actionAt=stamp, observedAt=utc(), passed=bool(result),
                     latencyMs=round((time.perf_counter()-start)*1000, 3) if result else None))

docs, usb = WORK/'docs', WORK/'synthetic-usb'
docs.mkdir(); usb.mkdir()
for i in range(20):
    (docs/f'source{i}.bin').write_bytes(bytes([i+1])*65536)
cfg = Config({'monitored_directories':[str(docs)], 'database_path':str(WORK/'lab.db')})
fake = FakeUsb()
svc = MonitoringService(cfg, usb_backend=fake)

def events(kind, path):
    return any(e['event_type']==kind and e['path']==str(path) for e in svc.db.query_file_events(limit=10000)[0])

def verified():
    return svc.db.query_alerts(verdict='VERIFIED_TRANSFER', limit=10000)[0]

resources = []
def phase(name, action):
    start, cpu = time.perf_counter(), time.process_time()
    action()
    duration = time.perf_counter()-start
    resources.append(dict(phase=name, durationSeconds=duration,
                          processCpuPercentOneCore=100*(time.process_time()-cpu)/duration))

phase('service-stopped-idle', lambda: time.sleep(5))
svc.start()
try:
    phase('monitoring-idle-synthetic-usb-backend', lambda: time.sleep(5))
    def file_actions():
        for i in range(20):
            p = docs/f'event{i}.txt'
            trial('file-create', lambda:p.write_text('original'), lambda:events('CREATED',p))
            # Respect default create/modify suppression; not included in latency.
            time.sleep(1.6)
            trial('file-modify', lambda:p.write_text('changed'), lambda:events('MODIFIED',p))
            q = docs/f'renamed{i}.txt'
            trial('file-rename', lambda:p.rename(q), lambda:events('RENAMED',p))
            trial('file-delete', q.unlink, lambda:events('DELETED',q))
    phase('80-filesystem-actions-including-dedupe-waits', file_actions)
    for i in range(20):
        fake.devices = [dict(device_id=f'EVAL{i}',name='Synthetic USB', mounts=[str(usb)])]
        trial('synthetic-usb-insert-forced-poll', svc.usb.poll_once,
              lambda:any(e['device_id']==f'EVAL{i}' and e['event_type']=='INSERTED' for e in svc.db.query_usb_events(limit=1000)[0]))
        fake.devices = []
        trial('synthetic-usb-remove-forced-poll', svc.usb.poll_once,
              lambda:any(e['device_id']==f'EVAL{i}' and e['event_type']=='REMOVED' for e in svc.db.query_usb_events(limit=1000)[0]))
    fake.devices = [dict(device_id='COPY',name='Synthetic USB',mounts=[str(usb)])]
    svc.usb.poll_once()
    def copies():
        for i in range(20):
            before = len(verified())
            trial('renamed-copy-to-synthetic-usb',
                  lambda:shutil.copyfile(docs/f'source{i}.bin',usb/f'copy{i}.bin'),
                  lambda:len(verified())>before)
    phase('20-renamed-64KiB-copies', copies)
    # Negative controls concern VERIFIED_TRANSFER, not all heuristic alerts.
    for i in range(20):
        before = len(verified())
        (usb/f'unrelated{i}.txt').write_text(f'unmatched-content-{i}')
        time.sleep(.3)
        rows.append(dict(scenario='unmatched-file-no-verified-transfer', actionAt=utc(),
                         passed=len(verified())==before, latencyMs=None))
finally:
    svc.stop()

# Independent synthetic scenarios: reset baseline and destination history each trial.
cases = [('normal-known-https',250000,443,True,False),
         ('large-known-upload',10000000,443,True,True),
         ('new-destination-upload',1500000,443,False,True),
         ('external-watchlist-port',1000,4444,False,True),
         ('small-new-https',1000,443,False,False)]
for name, size, port, known, expected in cases:
    for i in range(20):
        baseline, tracker = OutboundBaseline(), FirstSeenTracker()
        for j in range(20): baseline.add(200000+(j%5)*10000)
        if known: tracker.add('203.0.113.58')
        flow = Flow(src_ip='192.168.1.57',dst_ip='203.0.113.58',dst_port=port,protocol='TCP',bytes_out=size)
        start = time.perf_counter()
        alerts = detect_interval(IntervalStats(timestamp=utc(),bytes_out=size),[flow],baseline,tracker)
        rows.append(dict(scenario='network-synthetic-'+name,passed=bool(alerts)==expected,
                         expectedAlert=expected, observedAlert=bool(alerts),
                         latencyMs=(time.perf_counter()-start)*1000))

summary = []
for name in dict.fromkeys(r['scenario'] for r in rows):
    group = [r for r in rows if r['scenario']==name]
    times = sorted(r['latencyMs'] for r in group if r['latencyMs'] is not None)
    summary.append(dict(scenario=name,trials=len(group),passed=sum(r['passed'] for r in group),
                        medianMs=statistics.median(times) if times else None,
                        p95Ms=times[math.ceil(.95*len(times))-1] if times else None))
result = dict(completedAt=utc(),python=sys.version,platform=platform.platform(),
              methodology='Default service configuration, real watchdog and SQLite, asynchronous detection, 10ms observation polling. USB is a temporary folder and synthetic backend, forced polls exclude physical enumeration/poll interval. Network inputs synthetic; timings exclude capture. CPU includes experiment driver. No UI latency measured.',
              summary=summary,resources=resources,trials=rows)
(OUT/'experiments.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(dict(summary=summary,resources=resources),indent=2))
