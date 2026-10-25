import { Table, type TableProps, type TableScrollContainerProps } from '@mantine/core'
import { useLayoutEffect, useRef } from 'react'

/**
 * Copies each column heading onto its body cells as `data-label`, so the phone layout (`.porch-list` in global.css)
 * can show "Heading: value" once the header row is hidden. Headings that are only visually hidden (an actions column)
 * give an empty label. Cells spanning several columns are left unlabelled.
 */
function labelCells(table: HTMLTableElement) {
  const heads = [...table.querySelectorAll(':scope > thead > tr:first-child > th')].flatMap((th) => {
    const text = th.querySelector('.visually-hidden, .mantine-VisuallyHidden-root') ? '' : th.textContent.trim()
    return Array<string>((th as HTMLTableCellElement).colSpan || 1).fill(text)
  })
  for (const row of table.querySelectorAll(':scope > tbody > tr')) {
    let col = 0
    for (const cell of row.children) {
      const span = (cell as HTMLTableCellElement).colSpan || 1
      const label = span === 1 ? (heads[col] ?? '') : ''
      if (cell.getAttribute('data-label') !== label) cell.setAttribute('data-label', label)
      col += span
    }
  }
}

/**
 * A list of records: a scrolling table from tablet width up, one card per row on phones. `minWidth` is the table's
 * width before it scrolls sideways (tablets and narrow desktop windows); `scroll` passes props to that container.
 */
export function ListTable({
  minWidth,
  scroll,
  className,
  children,
  ...props
}: TableProps & { minWidth?: number; scroll?: Omit<TableScrollContainerProps, 'minWidth' | 'children'> }) {
  const ref = useRef<HTMLTableElement>(null)
  useLayoutEffect(() => {
    const table = ref.current
    if (!table) return
    labelCells(table)
    // Rows come and go (pagination, expanding a row); attribute changes are not observed, so labelling never loops.
    const observer = new MutationObserver(() => {
      labelCells(table)
    })
    observer.observe(table, { childList: true, subtree: true, characterData: true })
    return () => {
      observer.disconnect()
    }
  }, [])
  const table = (
    <Table ref={ref} className={className ? `porch-list ${className}` : 'porch-list'} {...props}>
      {children}
    </Table>
  )
  return minWidth ? (
    <Table.ScrollContainer minWidth={minWidth} {...scroll} className="porch-list-scroll">
      {table}
    </Table.ScrollContainer>
  ) : (
    table
  )
}
