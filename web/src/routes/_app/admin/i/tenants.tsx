import { Anchor, Button, Code, Group, Modal, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus } from '@tabler/icons-react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, ifMatch, useAdminMutation } from '@/api/admin'
import { installKeys, tenantPagesQuery, type Tenant } from '@/api/admin/install'
import { api, ApiError, unwrap } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { useVersionedMutation } from '@/components/admin/install/hooks'
import { ManagedBy } from '@/components/admin/install/ManagedBy'
import { StatusBadge, toneOf } from '@/components/admin/install/StatusBadge'
import { ConfirmAction } from '@/components/admin/install/ConfirmAction'
import { DateTime, Loading } from '@/components/admin/install/ui'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/i/tenants')({
  component: Tenants,
})

const slugRE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Derives a tenant slug from a display name ("Smith family" → "smith-family"). */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/g, '')
}

function Tenants() {
  const q = useInfiniteQuery(tenantPagesQuery)
  const [opened, { open, close }] = useDisclosure(false)
  const tenants = q.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <Stack>
      <PageHeader
        title="Tenants"
        description="Families, teams or organisations on this installation. Each tenant has its own members, applications and access rules."
        actions={
          <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={open}>
            New tenant
          </Button>
        }
      />
      <ErrorAlert error={q.error} title="Could not load tenants" />
      {q.isPending ? <Loading label="Loading tenants…" /> : null}
      {q.isSuccess && tenants.length === 0 ? <EmptyState>No tenants yet. Create the first one.</EmptyState> : null}
      {tenants.length > 0 ? (
        <ListTable minWidth={760} striped highlightOnHover aria-label="Tenants" verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Slug</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Managed by</Table.Th>
              <Table.Th>Created</Table.Th>
              <Table.Th>
                <span className="visually-hidden">Actions</span>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tenants.map((t) => (
              <TenantRow key={t.id} t={t} />
            ))}
          </Table.Tbody>
        </ListTable>
      ) : null}
      {q.hasNextPage ? (
        <Group justify="center">
          <Button variant="default" loading={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
            Load more
          </Button>
        </Group>
      ) : null}
      <CreateTenant opened={opened} onClose={close} />
    </Stack>
  )
}

function TenantRow({ t }: { t: Tenant }) {
  const disable = t.status === 'active'
  const toggle = useVersionedMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH('/tenants/{tenant}', {
          params: { path: { tenant: t.id }, header: ifMatch(t.version) },
          body: { status: disable ? 'disabled' : 'active' },
        }),
      ),
    success: disable ? `${t.name} disabled` : `${t.name} enabled`,
    invalidate: [installKeys.tenants, adminQuery.queryKey],
  })
  return (
    <Table.Tr>
      <Table.Td>
        <Anchor renderRoot={(props) => <Link {...props} to="/admin/t/$tenant/members" params={{ tenant: t.slug }} />}>
          {t.name}
        </Anchor>
      </Table.Td>
      <Table.Td>
        <Code>{t.slug}</Code>
      </Table.Td>
      <Table.Td>
        <StatusBadge tone={toneOf(t.status)}>{t.status}</StatusBadge>
      </Table.Td>
      <Table.Td>
        <ManagedBy managedBy={t.managed_by} lastChangedBy={t.last_changed_by} />
      </Table.Td>
      <Table.Td>
        <DateTime value={t.created_at} />
      </Table.Td>
      <Table.Td>
        <ConfirmAction
          label={
            <>
              {disable ? 'Disable' : 'Enable'}
              <VisuallyHidden> {t.name}</VisuallyHidden>
            </>
          }
          confirmLabel={disable ? 'Disable tenant' : 'Enable tenant'}
          title={disable ? `Disable ${t.name}?` : `Enable ${t.name}?`}
          color={disable ? 'red' : 'blue'}
          loading={toggle.isPending}
          onConfirm={() => toggle.mutateAsync(undefined).catch(() => undefined)}
        >
          <Text size="sm">
            {disable
              ? 'Members of a disabled tenant can no longer sign in to its applications. Nothing is deleted; you can enable it again later.'
              : 'Members will be able to use the tenant and its applications again.'}
          </Text>
        </ConfirmAction>
      </Table.Td>
    </Table.Tr>
  )
}

function CreateTenant({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const [slugTouched, setSlugTouched] = useState(false)
  const form = useForm({
    initialValues: { name: '', slug: '' },
    validate: {
      name: (v) => (v.trim() ? null : 'Enter a name'),
      slug: (v) => (slugRE.test(v) && v.length >= 2 ? null : 'Use 2–63 lowercase letters, digits or hyphens'),
    },
  })
  const close = () => {
    form.reset()
    setSlugTouched(false)
    onClose()
  }
  const create = useAdminMutation({
    mutationFn: async (v: { name: string; slug: string }) =>
      unwrap(await api.POST('/tenants', { body: { name: v.name.trim(), slug: v.slug } })),
    success: (t) => `Tenant ${t.name} created`,
    invalidate: [installKeys.tenants, adminQuery.queryKey, installKeys.health],
    onSuccess: close,
  })
  return (
    <Modal
      closeButtonProps={{ 'aria-label': 'Close' }}
      lockScroll={false}
      opened={opened}
      onClose={close}
      title="New tenant"
      centered
    >
      <form
        onSubmit={form.onSubmit((v) => {
          create.mutate(v, {
            onError: (e) => {
              if (e instanceof ApiError)
                for (const f of e.fields) form.setFieldError(f.field.replace(/^body\./, ''), f.message)
            },
          })
        })}
      >
        <Stack>
          <TextInput
            label="Name"
            required
            data-autofocus
            {...form.getInputProps('name')}
            onChange={(e) => {
              const name = e.currentTarget.value
              form.setFieldValue('name', name)
              if (!slugTouched) form.setFieldValue('slug', slugify(name))
            }}
          />
          <TextInput
            label="Slug"
            description="Used in URLs; cannot be changed later"
            required
            {...form.getInputProps('slug')}
            onChange={(e) => {
              setSlugTouched(true)
              form.setFieldValue('slug', e.currentTarget.value)
            }}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Create tenant
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
