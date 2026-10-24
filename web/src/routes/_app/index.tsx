import { Alert, Anchor, Badge, Card, Group, SimpleGrid, Stack, Text, Title } from '@mantine/core'
import { IconExternalLink } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { myAppsQuery } from '@/api/queries'

export const Route = createFileRoute('/_app/')({
  component: function Home() {
    const { me } = Route.useRouteContext()
    const apps = useQuery(myAppsQuery)
    const temporary = me.session.method === 'setup' || me.session.method === 'recovery_link'
    return (
      <Stack maw={960} mx="auto">
        <Title order={1} size="h2">
          Hello, {me.display_name}
        </Title>
        {temporary ? (
          <Alert color="yellow" title="Finish securing your account">
            This is a temporary {me.session.method === 'setup' ? 'setup' : 'recovery'} session. Link Google or enroll a
            backup login on the <Link to="/account">account page</Link>.
          </Alert>
        ) : null}
        <section aria-labelledby="apps-heading">
          <Title order={2} size="h4" id="apps-heading" mb="sm">
            Your applications
          </Title>
          {apps.data?.length === 0 ? <Text c="dimmed">No applications are available to you yet.</Text> : null}
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }}>
            {apps.data?.map((a) => (
              <Card key={a.id} component="article" aria-label={a.name}>
                <Group justify="space-between" mb={4}>
                  <Text fw={600}>{a.name}</Text>
                  {a.shared ? <Badge variant="default">shared</Badge> : null}
                </Group>
                {a.description ? (
                  <Text size="sm" c="dimmed" mb="xs">
                    {a.description}
                  </Text>
                ) : null}
                <Text size="xs" c="dimmed" mb="sm">
                  {a.tenant_name}
                </Text>
                {a.launch_url ? (
                  <Anchor href={a.launch_url} size="sm">
                    <Group gap={4}>
                      Open {a.name} <IconExternalLink size={14} aria-hidden />
                    </Group>
                  </Anchor>
                ) : (
                  <Text size="sm" c="dimmed">
                    No launch address configured
                  </Text>
                )}
              </Card>
            ))}
          </SimpleGrid>
        </section>
        <Card>
          <Title order={2} size="h4" mb="sm">
            Your memberships
          </Title>
          {me.memberships.length === 0 ? (
            <Text c="dimmed">You are not a member of any tenant yet.</Text>
          ) : (
            <Stack gap="xs">
              {me.memberships.map((m) => (
                <Group key={m.tenant_id} justify="space-between">
                  <Text>{m.tenant_name}</Text>
                  <Badge variant="default">{m.status}</Badge>
                </Group>
              ))}
            </Stack>
          )}
        </Card>
      </Stack>
    )
  },
})
