import { Alert, Badge, Card, Group, Stack, Text, Title } from '@mantine/core'
import { createFileRoute, Link } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/')({
  component: function Home() {
    const { me } = Route.useRouteContext()
    return (
      <Stack maw={880} mx="auto">
        <Title order={1} size="h2">
          Hello, {me.display_name}
        </Title>
        {me.session.method === 'setup' || me.session.method === 'recovery_link' ? (
          <Alert color="yellow" title="Finish securing your account">
            This is a temporary {me.session.method === 'setup' ? 'setup' : 'recovery'} session. Link Google or enroll a
            backup login on the <Link to="/account">account page</Link>.
          </Alert>
        ) : null}
        <Card>
          <Title order={2} size="h4" mb="sm">
            Your groups
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
        {me.operator_roles.length > 0 ? (
          <Text size="sm" c="dimmed">
            Installation roles: {me.operator_roles.join(', ')}
          </Text>
        ) : null}
      </Stack>
    )
  },
})
