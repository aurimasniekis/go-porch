/**
 * Pure helpers for the authorization admin pages. Validation mirrors the server (internal/authz/permissions.go,
 * internal/domain/domain.go) so forms can reject bad input before a round trip; the server stays authoritative.
 */

/** `<resource_type>:<action>`, either side may be `*` (authz.permRE). */
export const PERMISSION_RE = /^(\*|[a-z][a-z0-9_]{0,31}):(\*|[a-z][a-z0-9_]{0,31})$/

/** DNS-label-like slug (domain.slugRE). */
export const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

export function validPermission(p: string): boolean {
  return PERMISSION_RE.test(p)
}

export function validSlug(s: string): boolean {
  return SLUG_RE.test(s)
}

/** A resource type: a lowercase identifier without wildcards (authz.regexpType). */
export function validResourceType(t: string): boolean {
  return t !== '' && !t.includes('*') && validPermission(`${t}:x`)
}

/** Attribute keys are slugs or identifiers (authz.validateAttrs). */
export function validAttributeKey(k: string): boolean {
  return validSlug(k) || validResourceType(k)
}

/** A concrete action for a check (no wildcards). */
export function validAction(a: string): boolean {
  return validPermission(a) && !a.includes('*')
}

/** Splits entered permissions into valid and invalid ones (deduplicated, trimmed). */
export function partitionPermissions(values: string[], allowStar = false): { valid: string[]; invalid: string[] } {
  const valid: string[] = []
  const invalid: string[] = []
  for (const raw of values) {
    const v = raw.trim()
    if (!v) continue
    const ok = validPermission(v) || (allowStar && v === '*')
    const bucket = ok ? valid : invalid
    if (!bucket.includes(v)) bucket.push(v)
  }
  return { valid, invalid }
}

/** Suggests a slug from a display name. */
export function slugify(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/g, '')
}

export interface TreeItem {
  id: string
  parent_id?: string
}

export interface FlatNode<T> {
  item: T
  depth: number
  /** Number of descendants (children, grandchildren, …). */
  descendants: number
}

/**
 * Orders items depth-first by their parent links. Items whose parent is missing become roots; cycles (which the
 * server prevents) are cut so every item appears exactly once.
 */
export function flattenTree<T extends TreeItem>(items: T[], compare: (a: T, b: T) => number = () => 0): FlatNode<T>[] {
  const ids = new Set(items.map((i) => i.id))
  const kids = new Map<string, T[]>()
  const roots: T[] = []
  for (const i of items) {
    if (i.parent_id && i.parent_id !== i.id && ids.has(i.parent_id)) {
      const list = kids.get(i.parent_id) ?? []
      list.push(i)
      kids.set(i.parent_id, list)
    } else {
      roots.push(i)
    }
  }
  const out: FlatNode<T>[] = []
  const seen = new Set<string>()
  const walk = (i: T, depth: number): number => {
    if (seen.has(i.id)) return 0
    seen.add(i.id)
    const node: FlatNode<T> = { item: i, depth, descendants: 0 }
    out.push(node)
    for (const k of [...(kids.get(i.id) ?? [])].sort(compare)) node.descendants += 1 + walk(k, depth + 1)
    return node.descendants
  }
  for (const r of [...roots].sort(compare)) walk(r, 0)
  // Anything left is part of a parent cycle: show it at the top level rather than hiding it.
  for (const i of items) if (!seen.has(i.id)) walk(i, 0)
  return out
}

/** IDs of every item below id. */
export function descendantIds(items: TreeItem[], id: string): Set<string> {
  const out = new Set<string>()
  let frontier = [id]
  while (frontier.length > 0) {
    const next: string[] = []
    for (const i of items) {
      if (i.parent_id && frontier.includes(i.parent_id) && !out.has(i.id) && i.id !== id) {
        out.add(i.id)
        next.push(i.id)
      }
    }
    frontier = next
  }
  return out
}

/** Groups below g through nesting (children of children…), from parent links. Cycles are cut. */
export function groupDescendants(groups: { id: string; parents: string[] }[], id: string): Set<string> {
  const out = new Set<string>()
  let frontier = [id]
  while (frontier.length > 0) {
    const next: string[] = []
    for (const g of groups) {
      if (g.id !== id && !out.has(g.id) && g.parents.some((p) => frontier.includes(p))) {
        out.add(g.id)
        next.push(g.id)
      }
    }
    frontier = next
  }
  return out
}

/** Converts a datetime-local value (browser local time) to RFC 3339; undefined when empty or invalid. */
export function localInputToISO(value: string): string | undefined {
  if (!value) return undefined
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

/** Formats a date as a datetime-local value in the browser's time zone. */
export function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export interface AttributeRow {
  key: string
  value: string
}

/** Converts editor rows to an attribute map, reporting the first problem (empty rows are ignored). */
export function rowsToAttributes(rows: AttributeRow[]): { attributes: Record<string, string>; error?: string } {
  const attributes: Record<string, string> = {}
  for (const r of rows) {
    const key = r.key.trim()
    if (!key && !r.value) continue
    if (!validAttributeKey(key))
      return { attributes, error: `"${key}" is not a valid attribute key (lowercase, digits, - or _)` }
    if (key in attributes) return { attributes, error: `Attribute "${key}" appears twice` }
    if (r.value.length > 512) return { attributes, error: `Attribute "${key}" is longer than 512 characters` }
    attributes[key] = r.value
  }
  if (Object.keys(attributes).length > 50) return { attributes, error: 'At most 50 attributes' }
  return { attributes }
}

export function attributesToRows(attrs: Record<string, string> | undefined): AttributeRow[] {
  return Object.entries(attrs ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({ key, value }))
}

const reasons: Record<string, string> = {
  granted: 'A grant applies and no deny policy matched.',
  default_deny: 'No grant applies (default deny).',
  denied_by_policy: 'A deny policy matched (or failed to evaluate).',
  tenant_gate: 'The subject is not an active member of this tenant (tenant gate).',
  invalid_request: 'The request is invalid (unknown subject or malformed action).',
}

/** A sentence explaining a decision reason. */
export function describeReason(reason: string): string {
  return reasons[reason] ?? reason
}

/** Human label for an assignment scope. */
export function scopeText(
  scopeType: string,
  resourceType: string | undefined,
  resourceName: string | undefined,
): string {
  switch (scopeType) {
    case 'tenant':
      return 'Whole tenant'
    case 'resource_type':
      return `All ${resourceType ?? '?'} resources`
    default:
      return `${resourceType === 'app' ? 'Application' : (resourceType ?? '?')}: ${resourceName ?? '?'}`
  }
}
