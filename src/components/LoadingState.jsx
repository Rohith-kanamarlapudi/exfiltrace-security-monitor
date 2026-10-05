import { Loader2 } from 'lucide-react'

export default function LoadingState({ label = 'Loading data...' }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-ink-dim" role="status">
      <Loader2 size={16} className="animate-spin" />
      {label}
    </div>
  )
}
