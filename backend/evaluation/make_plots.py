"""Make publication-ready figures from saved evidence, without rerunning trials."""
from pathlib import Path
import os
import sys
import json
import statistics
import xml.etree.ElementTree as ET
import zipfile

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE/'work'/'plot-libs'))
os.environ['MPLCONFIGDIR'] = str(BASE/'work'/'mpl-config')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = BASE/'results'/'plots'
OUT.mkdir(exist_ok=True)
data = json.loads((BASE/'results'/'experiments.json').read_text())
plt.rcParams.update({'font.size':11,'axes.spines.top':False,'axes.spines.right':False,
                     'savefig.dpi':240,'font.family':'DejaVu Sans'})
blue,teal,red,amber = '#2768A5','#168575','#C24A46','#DDA535'
def save(fig,name):
    for ext in ['png','svg','pdf']:
        fig.savefig(OUT/f'{name}.{ext}',bbox_inches='tight',facecolor='white')
    plt.close(fig)

names=['file-create','file-modify','file-rename','file-delete','renamed-copy-to-synthetic-usb']
values=[[r['latencyMs'] for r in data['trials'] if r['scenario']==n] for n in names]
fig,axes=plt.subplots(1,2,figsize=(12,5),gridspec_kw={'width_ratios':[3,1]},layout='constrained')
for ax,vs,labels in [(axes[0],values[:4],['Create','Modify','Rename','Delete']),
                     (axes[1],values[4:],['Copy alert\n(synthetic USB)'])]:
    ax.boxplot(vs,tick_labels=labels,patch_artist=True,showfliers=False,
               boxprops={'facecolor':'#DCEAF5'},medianprops={'color':blue,'linewidth':2})
    for i,v in enumerate(vs):
        ax.scatter(np.full(len(v),i+1)+np.linspace(-.09,.09,len(v)),v,s=18,color=teal,alpha=.7,zorder=3)
    ax.set_ylabel('Observable backend delay (ms)')
    ax.grid(axis='y',alpha=.2)
    ax.set_ylim(bottom=0)
axes[0].set_title('Real filesystem operations')
axes[1].set_title('Real copy; simulated USB mount')
fig.suptitle('1. Distribution of backend observation delays',fontsize=16,fontweight='bold')
fig.supxlabel('20 trials per operation | boxes: Q1–Q3; line: median; whiskers: 1.5×IQR; dots: all trials\nSeparate vertical scales; delay includes operation time and database observation overhead.',fontsize=10)
save(fig,'01_delay_distribution')

fig,ax=plt.subplots(figsize=(11,5.5),layout='constrained')
med=[statistics.median(v) for v in values]
p95=[sorted(v)[18] for v in values]
x=np.arange(5)
b1=ax.bar(x-.19,med,.38,label='Median',color=blue)
b2=ax.bar(x+.19,p95,.38,label='P95 (nearest rank)',color=teal)
ax.bar_label(b1,fmt='%.1f',padding=3,fontsize=10)
ax.bar_label(b2,fmt='%.1f',padding=3,fontsize=10)
ax.set_xticks(x,['Create','Modify','Rename','Delete','Copy alert\n(synthetic USB)'])
ax.set_ylabel('Observable backend delay (ms)'); ax.set_ylim(0,max(p95)*1.2)
ax.set_title('2. Typical and slower backend response times',fontsize=16,fontweight='bold',pad=18)
ax.legend(loc='upper left'); ax.grid(axis='y',alpha=.2); ax.set_axisbelow(True)
fig.supxlabel('20 trials per operation | Copy-alert timing includes the default 0.5-second file-stability check.\nThese are backend measurements, not dashboard refresh or physical USB response times.',fontsize=10)
save(fig,'02_median_p95')

groups={}
for suite in ['backend','network']:
    for t in ET.parse(BASE/'results'/f'{suite}-tests-final.xml').iter('testcase'):
        key=t.attrib['classname'].split('.')[-1]
        label=('Network: ' if suite=='network' else 'Backend: ')+key.removeprefix('test_').replace('_',' ')
        state=1 if t.find('failure') is not None or t.find('error') is not None else 2 if t.find('skipped') is not None else 0
        groups.setdefault(label,[0,0,0])[state]+=1
fig,ax=plt.subplots(figsize=(12,8),layout='constrained')
a=np.array(list(groups.values())); left=np.zeros(len(a)); y=np.arange(len(a))
for k,(label,color) in enumerate([('Passed',teal),('Failed',red),('Skipped',amber)]):
    bars=ax.barh(y,a[:,k],left=left,label=label,color=color)
    for bar,count in zip(bars,a[:,k]):
        if count: ax.text(bar.get_x()+bar.get_width()/2,bar.get_y()+bar.get_height()/2,str(count),ha='center',va='center',color='white' if k<2 else '#202020',fontweight='bold')
    left+=a[:,k]
ax.set_yticks(y,list(groups));ax.invert_yaxis();ax.set_xlabel('Number of automated test cases')
ax.set_title('3. Automated regression test outcomes\n189 passed · 3 failed · 2 skipped',fontsize=16,fontweight='bold',pad=18)
ax.legend(loc='lower right');ax.set_xlim(0,35);ax.grid(axis='x',alpha=.15);ax.set_axisbelow(True)
fig.supxlabel('194 collected tests | Failures: mocked Windows path lookup | Skips: Sleuth Kit recovery integration\nRegression pass counts measure tested software behavior, not attack-detection accuracy.',fontsize=10)
save(fig,'03_regression_outcomes')

network=[r for r in data['trials'] if r['scenario'].startswith('network-synthetic-')]
matrix=np.zeros((2,2),dtype=int)
for r in network: matrix[0 if r['expectedAlert'] else 1,0 if r['observedAlert'] else 1]+=1
assert matrix.tolist()==[[60,0],[0,40]]
fig,ax=plt.subplots(figsize=(8,6),layout='constrained')
ax.imshow(matrix,cmap='Blues',vmin=0,vmax=60)
labels=[['Expected alert\nproduced','Expected alert\nmissing'],['Unexpected\nalert','Expected silence\nobserved']]
for i in range(2):
    for j in range(2):
        ax.text(j,i,f'{matrix[i,j]}\n{labels[i][j]}',ha='center',va='center',color='white' if matrix[i,j]>=40 else '#18364B',fontsize=12,fontweight='bold')
ax.set_xticks([0,1],['Alert produced','No alert produced']);ax.set_yticks([0,1],['Alert expected','No alert expected'])
ax.set_xlabel('Observed detector output'); ax.set_ylabel('Scenario expectation')
ax.set_title('4. Synthetic network scenario confusion matrix',fontsize=15,fontweight='bold',pad=20)
fig.supxlabel('5 fixed scenarios × 20 repetitions = 100 checks\nExpected-rule behavior only; no captured traffic or independent attack dataset.',fontsize=10)
save(fig,'04_network_matrix')

fig,ax=plt.subplots(figsize=(11,5),layout='constrained')
ax.plot(range(1,21),values[4],marker='o',color=blue,label='Observed copy-alert delay')
ax.axhline(med[4],color=teal,ls='--',label=f'Median: {med[4]:.2f} ms')
ax.set_xticks(range(1,21));ax.set_ylim(bottom=0);ax.set_ylabel('Observable backend delay (ms)');ax.set_xlabel('Sequential trial number')
ax.set_title('5. Copy-alert delay across 20 renamed-file transfers',fontsize=16,fontweight='bold',pad=18)
ax.legend(loc='lower right');ax.grid(alpha=.2)
fig.supxlabel('Each file: 65,536 bytes (64 KiB) | Real file copies to a temporary folder representing USB storage\nSequential operations; this does not measure physical USB throughput or concurrent-load scalability.',fontsize=10)
save(fig,'05_copy_trials')

with zipfile.ZipFile(OUT/'ExfilTrace-plots.zip','w',zipfile.ZIP_DEFLATED) as z:
    for p in OUT.iterdir():
        if p.suffix in ['.png','.svg','.pdf']: z.write(p,p.name)
    z.write(BASE/'results'/'experiments.json','experiments.json')
    z.write(Path(__file__),'make_plots.py')
print(json.dumps({'plots':str(OUT),'fileLatencyStats':[{'scenario':n,'min':min(v),'max':max(v),'median':statistics.median(v),'p95':sorted(v)[18]} for n,v in zip(names,values)]},indent=2))
