import { Badge, Tooltip } from '@mantine/core'

/**
 * Who manages a resource. Same information as the kit's Provenance badge, but on the neutral "default" variant: the kit's
 * tinted (light) badge colours fail WCAG AA text contrast in the light theme.
 */
export function ManagedBy({ managedBy, lastChangedBy }: { managedBy?: string; lastChangedBy?: string }) {
  if (!managedBy) return null
  const badge = (
    <Badge variant="default" size="sm" tt="none">
      {managedBy}
    </Badge>
  )
  if (managedBy !== 'terraform' && !lastChangedBy) return badge
  return (
    <Tooltip
      label={[
        managedBy === 'terraform' ? 'Managed by Terraform: manual changes are overwritten on the next apply.' : null,
        lastChangedBy ? `Last changed by ${lastChangedBy}` : null,
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {badge}
    </Tooltip>
  )
}
