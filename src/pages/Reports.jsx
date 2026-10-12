import { useState } from 'react'
import { Download, Eye, EyeOff, FileText, Info, X } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import PreviewNotice from '../components/PreviewNotice'
import Panel from '../components/Panel'
import RiskBadge from '../components/RiskBadge'
import IncidentTimeline from '../components/IncidentTimeline'
import LoadingState from '../components/LoadingState'
import { useApi } from '../hooks'
import { getReports } from '../services/api'
import { formatDate } from '../utils/format'

function Section({ label, children }) {
  return (
    <div>
      <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">{label}</h4>
      <p className="text-sm leading-relaxed text-ink-dim">{children}</p>
    </div>
  )
}

function ReportCard({ report, expanded, onToggle, onExport }) {
  return (
    <Panel bodyClassName="p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-sm font-semibold text-accent">{report.id}</span>
            <RiskBadge level={report.severity} />
          </div>
          <h3 className="mt-2 text-base font-medium text-ink">{report.incidentType}</h3>
          <p className="mt-1 font-mono text-xs text-ink-faint">
            {formatDate(report.date)} · Incident {report.incidentId}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={expanded}
            className="flex items-center gap-1.5 rounded-sm border border-accent bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold tracking-wide text-accent hover:bg-accent/20"
          >
            {expanded ? <EyeOff size={13} /> : <Eye size={13} />}
            {expanded ? 'HIDE REPORT' : 'VIEW REPORT'}
          </button>
          <button
            type="button"
            onClick={() => onExport(report)}
            className="flex items-center gap-1.5 rounded-sm border border-line-strong px-3 py-1.5 font-mono text-xs font-semibold tracking-wide text-ink-dim hover:border-ink-faint hover:text-ink"
          >
            <Download size={13} />
            EXPORT REPORT
          </button>
        </div>
      </div>

      <p className="mt-3 text-sm leading-relaxed text-ink-dim">{report.summary}</p>

      {expanded && (
        <div className="mt-4 grid grid-cols-1 gap-6 border-t border-line pt-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
          <div className="space-y-4">
            <Section label="USB Activity">{report.usbActivity}</Section>
            <Section label="File Activity">{report.fileActivity}</Section>
            <Section label="Network Activity">{report.networkActivity}</Section>
          </div>
          <div>
            <h4 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Incident Timeline</h4>
            <IncidentTimeline steps={report.timeline} compact />
          </div>
        </div>
      )}
    </Panel>
  )
}

export default function Reports() {
  const { data: reports, loading } = useApi(getReports, 0)
  const [expandedId, setExpandedId] = useState(null)
  const [notice, setNotice] = useState(null)

  if (loading) return <LoadingState label="Loading reports..." />

  // Placeholder until the backend can generate PDF/CSV exports.
  const handleExport = (report) =>
    setNotice(`Export for ${report.id} is not available yet. It will be enabled once the report API is connected.`)

  return (
    <>
      <PreviewNotice />
      <PageHeader title="Security Reports — sample preview" subtitle="Live report generation is unavailable">
        <span className="flex items-center gap-2 font-mono text-xs text-ink-dim">
          <FileText size={14} />
          {reports.length} reports
        </span>
      </PageHeader>

      {notice && (
        <div role="status" className="mb-4 flex items-start gap-3 rounded-sm border border-accent/30 bg-accent/10 px-4 py-3">
          <Info size={16} className="mt-0.5 shrink-0 text-accent" />
          <p className="flex-1 text-sm text-ink">{notice}</p>
          <button type="button" onClick={() => setNotice(null)} className="text-ink-dim hover:text-ink" aria-label="Dismiss">
            <X size={16} />
          </button>
        </div>
      )}

      <div className="space-y-4">
        {reports.map((report) => (
          <ReportCard
            key={report.id}
            report={report}
            expanded={expandedId === report.id}
            onToggle={() => setExpandedId(expandedId === report.id ? null : report.id)}
            onExport={handleExport}
          />
        ))}
      </div>
    </>
  )
}
