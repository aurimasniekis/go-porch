import { Alert, Badge, Group, Stack, Text, TextInput, Title } from '@mantine/core'
import { IconSearch } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { useMemo, useState } from 'react'
import type { Schemas } from '@/api/client'
import { myAppsQuery } from '@/api/queries'
import { UserShell } from '@/components/UserShell'

type LauncherApp = Schemas['LauncherApp']

export const Route = createFileRoute('/_app/')({
  component: function Home() {
    const { me } = Route.useRouteContext()
    const apps = useQuery(myAppsQuery)
    const [q, setQ] = useState('')
    const temporary = me.session.method === 'setup' || me.session.method === 'recovery_link'
    const sections = useMemo(() => groupApps(filterApps(apps.data ?? [], q)), [apps.data, q])
    const tenants = me.memberships.filter((m) => m.status === 'active').map((m) => m.tenant_name)
    return (
      <UserShell
        me={me}
        title={`Hello, ${me.display_name}`}
        subtitle={tenants.length > 0 ? `Member of ${tenants.join(', ')}` : 'You are not a member of any tenant yet.'}
        hero={
          <TextInput
            mt="lg"
            maw={460}
            size="md"
            radius="md"
            aria-label="Search applications"
            placeholder="Search applications"
            leftSection={<IconSearch size={18} aria-hidden />}
            value={q}
            onChange={(e) => {
              setQ(e.currentTarget.value)
            }}
          />
        }
      >
        <Stack gap="xl">
          {temporary ? (
            <Alert color="yellow" title="Finish securing your account">
              This is a temporary {me.session.method === 'setup' ? 'setup' : 'recovery'} session. Link Google or enroll
              a backup login on the <Link to="/account">account page</Link>.
            </Alert>
          ) : null}
          <Title order={2} size="h3">
            My applications
          </Title>
          {apps.data?.length === 0 ? <Text c="dimmed">No applications are available to you yet.</Text> : null}
          {apps.data && apps.data.length > 0 && sections.length === 0 ? (
            <Text c="dimmed">No application matches “{q}”.</Text>
          ) : null}
          <div className="porch-sections">
            {sections.map(([group, list]) => (
              <section
                key={group || '_'}
                aria-label={group || 'Applications'}
                className={list.length > 2 ? 'porch-section-wide' : undefined}
              >
                {group || sections.length > 1 ? (
                  <Title order={3} size="h5" mb="sm" c="dimmed" tt="uppercase" lts={0.5}>
                    {group || 'Other'}
                  </Title>
                ) : null}
                <div className="porch-tiles">
                  {list.map((a) => (
                    <Tile key={a.id} app={a} />
                  ))}
                </div>
              </section>
            ))}
          </div>
        </Stack>
      </UserShell>
    )
  },
})

function filterApps(apps: LauncherApp[], q: string): LauncherApp[] {
  const s = q.trim().toLowerCase()
  if (!s) return apps
  return apps.filter((a) => [a.name, a.description, a.group, a.tenant_name].some((v) => v.toLowerCase().includes(s)))
}

/** Sections in name order, ungrouped applications last. */
function groupApps(apps: LauncherApp[]): [string, LauncherApp[]][] {
  const m = new Map<string, LauncherApp[]>()
  for (const a of apps) m.set(a.group, [...(m.get(a.group) ?? []), a])
  return [...m.entries()].sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)))
}

// Letter tiles: dark enough for white text (large text, ≥ 3:1 and mostly ≥ 4.5:1).
const letterColors = [
  '#1b4fbf',
  '#0b7285',
  '#2b8a3e',
  '#862e9c',
  '#c92a2a',
  '#a61e4d',
  '#5f3dc4',
  '#d9480f',
  '#364fc7',
  '#087f5b',
]

function letterColor(name: string): string {
  let h = 0
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return letterColors[h % letterColors.length]
}

function Tile({ app }: { app: LauncherApp }) {
  const body = (
    <>
      {app.icon_url ? (
        <span className="porch-tile-plate">
          <img className="porch-tile-icon" src={app.icon_url} alt="" loading="lazy" />
        </span>
      ) : (
        <span className="porch-tile-letter" style={{ background: letterColor(app.name) }} aria-hidden>
          {app.name.trim().charAt(0).toUpperCase()}
        </span>
      )}
      <span className="porch-tile-name">{app.name}</span>
      <span className="porch-tile-tenant">{app.tenant_name}</span>
    </>
  )
  return (
    <article className="porch-tile" aria-label={app.name} title={app.description || undefined}>
      {app.launch_url ? (
        <a className="porch-tile-link" href={app.launch_url}>
          {/* The accessible name keeps the visible text (WCAG 2.5.3): "Open <name> <tenant>". */}
          <span className="visually-hidden">Open </span>
          {body}
        </a>
      ) : (
        <div className="porch-tile-link">
          {body}
          <Text size="xs" c="dimmed">
            No launch address
          </Text>
        </div>
      )}
      {app.shared ? (
        <Group className="porch-tile-badge" gap={0}>
          <Badge size="xs" variant="light">
            shared
          </Badge>
        </Group>
      ) : null}
    </article>
  )
}
