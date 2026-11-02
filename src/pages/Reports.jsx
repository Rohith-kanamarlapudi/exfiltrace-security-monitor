import { useState } from 'react'
import { Download, Eye, EyeOff, FileText } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import RiskBadge from '../components/RiskBadge'
import IncidentTimeline from '../components/IncidentTimeline'
import LoadingState from '../components/LoadingState'
import LiveState from '../components/LiveState'
import { useApi } from '../hooks'
import { exportReport, getReports } from '../services/api'
import { formatDate } from '../utils/format'

function Section({ label, children }) {
  return <div><h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">{label}</h4>
    <p className="text-sm leading-relaxed text-ink-dim">{children}</p></div>
}

function ReportCard({ report, expanded, onToggle, onExport }) {
  return <Panel bodyClassName="p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-3"><span className="font-mono text-sm font-semibold text-accent">{report.id}</span><RiskBadge level={report.severity} /></div>
        <h3 className="mt-2 text-base font-medium text-ink">{report.incidentType}</h3>
        <p className="mt-1 font-mono text-xs text-ink-faint">{formatDate(report.date)} · {report.status} · {report.incidentId}</p>
      </div>
      <div className="flex gap-2">
        <button type="button" onClick={onToggle} aria-expanded={expanded} className="flex items-center gap-1.5 rounded-sm border border-accent bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold tracking-wide text-accent hover:bg-accent/20">
          {expanded ? <EyeOff size={13} /> : <Eye size={13} />}{expanded ? 'HIDE REPORT' : 'VIEW REPORT'}
        </button>
        <button type="button" onClick={() => onExport(report)} className="flex items-center gap-1.5 rounded-sm border border-line-strong px-3 py-1.5 font-mono text-xs font-semibold tracking-wide text-ink-dim hover:border-ink-faint hover:text-ink">
          <Download size={13} /> EXPORT XML
        </button>
      </div>
    </div>
    <p className="mt-3 text-sm leading-relaxed text-ink-dim">{report.summary}</p>
    {expanded && <div className="mt-4 grid grid-cols-1 gap-6 border-t border-line pt-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
      <div className="space-y-4">
        <Section label="USB Activity">{report.usbActivity}</Section>
        <Section label="File Activity">{report.fileActivity}</Section>
        <Section label="Network Activity">{report.networkActivity}</Section>
        <Section label="Evidence Counts">{report.fileCount} file events · {report.sensitiveFileCount} sensitive · {report.networkEventCount} network events</Section>
      </div>
      <div><h4 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Session Timeline</h4><IncidentTimeline steps={report.timeline} compact /></div>
    </div>}
  </Panel>
}

export default function Reports() {
  const resource = useApi(getReports)
  const [expandedId, setExpandedId] = useState(null)
  const reports = resource.data?.items ?? []
  if (resource.loading) return <LoadingState label="Loading reports..." />

  const handleExport = async (report) => {
    try {
      const blob = await exportReport(report.id)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${report.id}.xml`
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) { window.alert(`Could not export report: ${error.message}`) }
  }

  return <>
    <PageHeader title="Security Report" subtitle="Latest USB mass storage device with correlated file and network activity">
      <span className="flex items-center gap-2 font-mono text-xs text-ink-dim"><FileText size={14} />{reports.length ? '1 USB mass storage' : 'No USB mass storage'}</span>
    </PageHeader>
    <LiveState resource={resource} label="reports" />
    {!resource.error && reports.length === 0 && <Panel><p className="p-4 text-sm text-ink-dim">No mounted USB mass storage device has been recorded yet. The report appears when one is detected.</p></Panel>}
    <div className="space-y-4">{reports.map((report) => <ReportCard key={report.id} report={report} expanded={expandedId === report.id}
      onToggle={() => setExpandedId(expandedId === report.id ? null : report.id)} onExport={handleExport} />)}</div>
  </>
}
