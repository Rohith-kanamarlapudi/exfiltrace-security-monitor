from pathlib import Path
import json
import xml.etree.ElementTree as ET
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

base=Path(__file__).parent
out=base/'results'
data=json.loads((out/'experiments.json').read_text())
doc=Document()
sec=doc.sections[0]
sec.top_margin=Inches(.65); sec.bottom_margin=Inches(.65)
sec.left_margin=Inches(.8); sec.right_margin=Inches(.8)
styles=doc.styles
styles['Normal'].font.name='Aptos'; styles['Normal'].font.size=Pt(10)
for nm in ['Title','Heading 1','Heading 2']:
    styles[nm].font.name='Aptos Display'
styles['Heading 1'].font.color.rgb=RGBColor(22,77,118)
styles['Heading 2'].font.color.rgb=RGBColor(39,104,165)

p=doc.add_paragraph(style='Title'); p.alignment=WD_ALIGN_PARAGRAPH.CENTER
p.add_run('ExfilTrace Laboratory Evaluation Results')
p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER
p.add_run('Measured monitoring behavior, response delays and regression tests').italic=True
doc.add_heading('Executive summary',1)
doc.add_paragraph('In a controlled Windows 11 evaluation, ExfilTrace recorded all 80 tested filesystem operations and generated verified-transfer alerts for all 20 renamed file copies to a simulated USB mount. Median backend observation delay was 27.37–35.61 ms for file events and 687.05 ms for copy alerts (P95: 714.48 ms). Five synthetic network scenarios matched expected rule behavior across 100 repetitions. Automated regression testing produced 189 passes, 3 failures and 2 skips.')
doc.add_paragraph('The figures below summarize the recorded trials. Synthetic USB and network results demonstrate behavior for the tested scenarios; they do not establish physical-device or real-world attack-detection accuracy.')
doc.add_heading('Results at a glance',1)
t=doc.add_table(rows=1, cols=3); t.style='Light Shading Accent 1'
for c,v in zip(t.rows[0].cells,['Measure','Result','Scope']): c.text=v
for row in [('Filesystem events','80/80 recorded','20 each: create, modify, rename, delete'),('Renamed USB copies','20/20 alerts','64 KiB each; simulated USB mount'),('Network scenarios','100/100 expected','5 synthetic cases × 20 trials'),('Regression tests','189 pass, 3 fail, 2 skip','194 collected tests')]:
    cells=t.add_row().cells
    for c,v in zip(cells,row): c.text=v

plots=[
('Detection delay distributions','01_delay_distribution.png','File create, modify, rename and delete events appeared in the backend within roughly 27–36 ms at the median. Copy alerts took longer, with a median near 687 ms. Boxes show the interquartile range; dots show individual trials. The panels use separate vertical scales.'),
('Median and P95 delay','02_median_p95.png','The copy-alert P95 was 714 ms, while file-event P95 values ranged from 45–55 ms. The extra copy delay includes file stability checking and content hashing.'),
('Automated regression outcomes','03_regression_outcomes.png','189 of 194 tests passed. Three mocked Windows TShark path-lookup tests failed; two recovery integration tests were skipped because Sleuth Kit was unavailable. Regression checks measure tested software behavior, not threat-detection accuracy.'),
('Synthetic network scenario matrix','04_network_matrix.png','The detector matched expectations for all 100 predefined synthetic checks: 60 expected alerts appeared, and 40 expected-silence trials remained unflagged. No live traffic or independent attack dataset was used.'),
('Copy-alert delay across trials','05_copy_trials.png','All 20 renamed 64 KiB copies triggered alerts. Delays were mostly around 660–715 ms, with one trial near 846 ms. This measures alert timing to a simulated mount, not physical USB throughput.')]
for i,(title,image,conclusion) in enumerate(plots):
    doc.add_heading(f'Figure {i+1}. {title}',1)
    img=out/'plots'/image
    doc.add_picture(str(img),width=Inches(6.45))
    doc.paragraphs[-1].alignment=WD_ALIGN_PARAGRAPH.CENTER
    p=doc.add_paragraph(); r=p.add_run('Conclusion. '); r.bold=True; p.add_run(conclusion)

doc.add_heading('Methods and limitations',1)
doc.add_paragraph('Each filesystem action and copy was repeated 20 times. Latency was measured with a monotonic clock from immediately before the action until its matching database record appeared. Measurements include operation duration and database polling/query overhead. Copy trials used different known 65,536-byte files with renamed destinations and include the configured 0.5-second file-stability check.')
doc.add_paragraph('USB insertion and removal used a synthetic backend and forced inventory polls, excluding physical Windows device enumeration and the normal polling interval. Network tests reset a synthetic baseline for each repetition. The five cases were normal known HTTPS (no alert), large known-destination upload (alert), new-destination upload (alert), external watchlist port 4444 (alert), and small new HTTPS (no alert). Network timing measures detector function execution only.')
doc.add_paragraph('Negative controls used 20 unmatched files on the simulated USB mount. After the service worker drained, the database contained exactly 20 verified-transfer alerts from the positive copy trials. One separate SUSPICIOUS heuristic alert occurred; therefore these trials support zero extra verified-transfer alerts for these specific controls, not a general zero false-positive rate.')
doc.add_paragraph('The regression failures concern mocked Windows path-lookup expectations; they do not establish whether live TShark capture works on Windows. The skipped recovery tests require Sleuth Kit. Physical USB behavior, live network detection accuracy, dashboard display latency, memory use, and real FAT32 recovery success remain unmeasured.')
doc.add_heading('Report-ready conclusion',1)
doc.add_paragraph('In a controlled Windows laboratory evaluation, ExfilTrace recorded all 80 tested filesystem operations and generated verified-transfer alerts for all 20 renamed file copies to a simulated USB mount. Median backend observation delays ranged from 27.37 to 35.61 ms for file events, while the median copy-alert delay was 687.05 ms (P95: 714.48 ms). Five synthetic network scenarios matched expected rule behavior across 100 repetitions. Regression testing yielded 189 passes, three mocked Windows path-lookup failures and two recovery-tool-dependent skips. Physical USB behavior, live network detection and recovery effectiveness require additional validation.')
doc.core_properties.title='ExfilTrace Laboratory Evaluation Results'
doc.core_properties.subject='Measured results, figures, methodology and limitations'
path=out/'ExfilTrace-evaluation-results.docx'
doc.save(path)
print(path)
