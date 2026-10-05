const pad = (n) => String(n).padStart(2, '0')

// "2026-10-05T14:06:41" -> "14:06:41"
export function formatTime(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

// "2026-10-05T14:06:41" -> "05 Oct 14:06:41"
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
export function formatDateTime(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${pad(d.getDate())} ${MONTHS[d.getMonth()]} ${formatTime(iso)}`
}

export function formatDate(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${pad(d.getDate())} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`
}

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return '-'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

export const formatNumber = (n) => n.toLocaleString('en-US')
