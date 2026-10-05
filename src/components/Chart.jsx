import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

// Brand colours (mirrors the Tailwind theme tokens in index.css)
const COLORS = { outbound: '#3b82f6', inbound: '#667080', suspicious: '#ef4444' }

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-sm border border-line-strong bg-panel-2 px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-mono text-ink-dim">{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey} className="flex items-center justify-between gap-4 font-mono" style={{ color: p.color }}>
          <span className="capitalize">{p.dataKey}</span>
          <span>{p.value} MB</span>
        </p>
      ))}
    </div>
  )
}

// Network traffic over time. `data` = [{ time, outbound, inbound, suspicious }] in MB.
export default function Chart({ data, height = 280 }) {
  return (
    <div style={{ width: '100%', height }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
          <CartesianGrid stroke="#232830" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="time" stroke="#667080" tick={{ fontSize: 11, fontFamily: 'ui-monospace, monospace' }} tickLine={false} />
          <YAxis stroke="#667080" tick={{ fontSize: 11, fontFamily: 'ui-monospace, monospace' }} tickLine={false} axisLine={false} unit=" MB" />
          <Tooltip content={<ChartTooltip />} />
          <Legend wrapperStyle={{ fontSize: 12, color: '#9aa3b0' }} iconType="plainline" />
          <Area isAnimationActive={false} type="monotone" dataKey="inbound" stroke={COLORS.inbound} fill={COLORS.inbound} fillOpacity={0.12} strokeWidth={1.5} />
          <Area isAnimationActive={false} type="monotone" dataKey="outbound" stroke={COLORS.outbound} fill={COLORS.outbound} fillOpacity={0.18} strokeWidth={2} />
          <Area isAnimationActive={false} type="monotone" dataKey="suspicious" stroke={COLORS.suspicious} fill={COLORS.suspicious} fillOpacity={0.3} strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
