// Generic table. Scrolls horizontally inside its card on small screens.
//
// columns: [{ key, header, render?(row), className? }]
// rowClassName: optional (row) => string, used to highlight risky rows.
export default function DataTable({
  columns,
  rows,
  onRowClick,
  selectedId,
  rowClassName,
  emptyText = 'No records found.',
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-max text-left text-sm">
        <thead>
          <tr className="border-b border-line bg-panel-2">
            {columns.map((col) => (
              <th
                key={col.key}
                className="whitespace-nowrap px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-ink-faint"
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-sm text-ink-faint">
                {emptyText}
              </td>
            </tr>
          )}
          {rows.map((row) => {
            const selected = selectedId !== undefined && selectedId === row.id
            const clickable = Boolean(onRowClick)
            return (
              <tr
                key={row.id}
                onClick={clickable ? () => onRowClick(row) : undefined}
                onKeyDown={
                  clickable
                    ? (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          onRowClick(row)
                        }
                      }
                    : undefined
                }
                tabIndex={clickable ? 0 : undefined}
                className={`border-b border-line/60 last:border-b-0 ${
                  clickable ? 'cursor-pointer hover:bg-panel-2 focus:bg-panel-2 focus:outline-none' : ''
                } ${selected ? 'bg-accent/10' : ''} ${rowClassName ? rowClassName(row) : ''}`}
              >
                {columns.map((col) => (
                  <td key={col.key} className={`whitespace-nowrap px-3 py-2.5 ${col.className ?? 'text-ink'}`}>
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
