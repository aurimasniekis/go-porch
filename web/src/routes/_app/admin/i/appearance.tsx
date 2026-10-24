import {
  ActionIcon,
  Alert,
  Anchor,
  Button,
  Card,
  Group,
  NumberInput,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  TagsInput,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core'
import { useForm, type UseFormReturnType } from '@mantine/form'
import { IconArrowDown, IconArrowUp, IconPlus, IconTrash } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useEffect } from 'react'
import { adminQuery, useAdminMutation } from '@/api/admin'
import { api, unwrap, type Schemas } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'

export const Route = createFileRoute('/_app/admin/i/appearance')({
  component: AppearancePage,
})

type Settings = Schemas['AppearanceSettings']
type Background = Schemas['BackgroundSettings']
type Provider = Schemas['BackgroundProvider']
type Source = Provider['source']
type Image = Schemas['Image']

const appearanceKey = ['install', 'appearance']
const maxProviders = 8

/** Commons categories checked to exist (featured or quality-reviewed photos, mostly landscape orientation). */
const categories = [
  'Featured pictures of landscapes',
  'Featured pictures of mountains',
  'Featured pictures of forests',
  'Featured pictures of lakes',
  'Featured pictures of coasts',
  'Featured pictures of waterfalls',
  'Featured pictures of sunsets',
  'Quality images of landscapes',
]

const sourceInfo: Record<Source, { label: string; add: string; description: string }> = {
  wikimedia: {
    label: 'Wikimedia Commons',
    add: 'Add Wikimedia Commons',
    description:
      'Openly licensed photos, chosen from a category or by file name. The author and license are credited on the page.',
  },
  picsum: {
    label: 'Lorem Picsum',
    add: 'Add Lorem Picsum',
    description: 'Photos from Unsplash (Unsplash License): a random selection, or the photo IDs you list.',
  },
  url: {
    label: 'Your own images',
    add: 'Add image URLs',
    description: 'https image URLs you choose (JPEG, PNG or WebP, landscape). No credit is shown.',
  },
}

interface ProviderForm {
  source: Source
  category: string
  files: string[]
}

interface FormValues {
  title: string
  providers: ProviderForm[]
  rotation: Background['rotation']
  count: number
  refresh: Background['refresh']
}

function newProvider(source: Source): ProviderForm {
  return { source, category: source === 'wikimedia' ? categories[0] : '', files: [] }
}

function toForm(s?: Settings): FormValues {
  const b = s?.background
  return {
    title: s?.title ?? 'Porch',
    providers: (b?.providers ?? []).map((p) => ({ source: p.source, category: p.category ?? '', files: p.files })),
    rotation: b?.rotation ?? 'visit',
    count: b?.count ?? 6,
    refresh: b?.refresh ?? 'weekly',
  }
}

function toProvider(p: ProviderForm): Provider {
  return { source: p.source, ...(p.source === 'wikimedia' ? { category: p.category.trim() } : {}), files: p.files }
}

function providerErrors(p: ProviderForm): string | null {
  if (p.source === 'wikimedia' && p.files.length === 0 && !p.category.trim()) return 'Pick a category or list files'
  if (p.source === 'picsum' && p.files.some((id) => !/^\d+$/.test(id))) return 'Picsum photo IDs are numbers'
  if (p.source === 'url' && p.files.length === 0) return 'Add at least one image URL'
  if (p.source === 'url' && p.files.some((u) => !/^https:\/\/\S+$/.test(u)))
    return 'Image URLs must start with https://'
  return null
}

function AppearancePage() {
  const caps = useQuery(adminQuery)
  const canEdit = caps.data?.installation ?? false
  const q = useQuery({
    queryKey: appearanceKey,
    queryFn: async () => unwrap(await api.GET('/installation/appearance')),
  })
  const form = useForm<FormValues>({
    initialValues: toForm(),
    validate: {
      title: (v) => (v.trim().length > 80 ? 'At most 80 characters' : null),
      providers: {
        files: (_v, all, path) => {
          const i = Number(path.split('.')[1])
          return providerErrors(all.providers[i])
        },
      },
    },
  })
  useEffect(() => {
    if (q.data) {
      form.setInitialValues(toForm(q.data))
      form.setValues(toForm(q.data))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset the form only when new data arrives
  }, [q.data])
  const save = useAdminMutation({
    mutationFn: async (v: FormValues) =>
      unwrap(
        await api.PUT('/installation/appearance', {
          body: {
            title: v.title.trim(),
            background: {
              providers: v.providers.map(toProvider),
              rotation: v.rotation,
              count: v.count,
              refresh: v.refresh,
            },
          },
        }),
      ),
    success: 'Appearance saved',
    invalidate: [appearanceKey, ['appearance']],
  })
  const refresh = useAdminMutation({
    mutationFn: async () => unwrap(await api.POST('/installation/appearance/refresh')),
    success: (s) => `Fetched ${String(s.images?.length ?? 0)} background images`,
    invalidate: [appearanceKey, ['appearance']],
  })
  const v = form.values
  const images = q.data?.images ?? []
  const savedProviders = q.data?.background.providers.length ?? 0
  return (
    <Stack>
      <PageHeader
        title="Appearance"
        description="How the sign-in page and the launcher look. Background images are downloaded by Porch from the image providers below and served from Porch itself, so visitors' browsers never contact a third party."
        actions={
          canEdit && savedProviders > 0 ? (
            <Button
              variant="default"
              loading={refresh.isPending}
              onClick={() => {
                refresh.mutate()
              }}
            >
              Fetch new images now
            </Button>
          ) : null
        }
      />
      <ErrorAlert error={q.error} title="Could not load the appearance settings" />
      <form
        onSubmit={form.onSubmit((vals) => {
          save.mutate(vals)
        })}
      >
        <fieldset disabled={!canEdit} style={{ border: 0, padding: 0, margin: 0 }}>
          <Stack>
            {!canEdit ? (
              <Alert color="blue">Only installation owners and administrators can change the appearance.</Alert>
            ) : null}
            <Card>
              <Title order={2} size="h4" mb="sm">
                Sign-in page
              </Title>
              <TextInput
                label="Title"
                description="Shown as “Welcome to …” on the sign-in page and in the launcher header"
                maw={420}
                {...form.getInputProps('title')}
              />
            </Card>
            <Card>
              <Title order={2} size="h4" mb={4}>
                Image providers
              </Title>
              <Text size="sm" c="dimmed" mb="md">
                Porch fills one pool of background images from these providers in turn; if one is unreachable, the
                others fill its share. With no providers, backgrounds are off: the pages show a plain gradient and Porch
                makes no outbound image requests.
              </Text>
              <Stack>
                {v.providers.length === 0 ? <EmptyState>No image providers: backgrounds are off.</EmptyState> : null}
                {v.providers.map((p, i) => (
                  <ProviderEditor key={i} form={form} index={i} provider={p} count={v.providers.length} />
                ))}
                {canEdit && v.providers.length < maxProviders ? (
                  <Group gap="xs">
                    {(Object.keys(sourceInfo) as Source[]).map((s) => (
                      <Button
                        key={s}
                        variant="light"
                        size="xs"
                        leftSection={<IconPlus size={14} aria-hidden />}
                        onClick={() => {
                          form.insertListItem('providers', newProvider(s))
                        }}
                      >
                        {sourceInfo[s].add}
                      </Button>
                    ))}
                  </Group>
                ) : null}
                {v.providers.length > 0 ? (
                  <Group grow align="flex-start" maw={720}>
                    <Select
                      label="Show"
                      allowDeselect={false}
                      data={[
                        { value: 'visit', label: 'A random image on every visit' },
                        { value: 'daily', label: 'The same image all day' },
                      ]}
                      {...form.getInputProps('rotation')}
                    />
                    <NumberInput
                      label="Images to keep"
                      description="Shared across providers"
                      min={1}
                      max={24}
                      {...form.getInputProps('count')}
                    />
                    <Select
                      label="New selection"
                      allowDeselect={false}
                      data={[
                        { value: 'weekly', label: 'Every week' },
                        { value: 'daily', label: 'Every day' },
                        { value: 'never', label: 'Never (keep these)' },
                      ]}
                      {...form.getInputProps('refresh')}
                    />
                  </Group>
                ) : null}
                {canEdit ? (
                  <Group justify="space-between">
                    <Text size="sm" c="dimmed">
                      {save.isPending && v.providers.length > 0
                        ? 'Saving and downloading images; this can take up to a minute…'
                        : 'Changing the providers or the number of images downloads new images.'}
                    </Text>
                    <Button type="submit" loading={save.isPending} disabled={!form.isDirty()}>
                      Save appearance
                    </Button>
                  </Group>
                ) : null}
              </Stack>
            </Card>
          </Stack>
        </fieldset>
      </form>
      <Card>
        <Title order={2} size="h4" mb="sm">
          Current images
        </Title>
        {images.length === 0 ? (
          <EmptyState>
            {savedProviders === 0
              ? 'Backgrounds are off: add an image provider.'
              : 'No images yet. Save the settings or fetch new images.'}
          </EmptyState>
        ) : (
          <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
            {images.map((img) => (
              <ImageCard key={img.id} img={img} />
            ))}
          </SimpleGrid>
        )}
      </Card>
    </Stack>
  )
}

function ProviderEditor({
  form,
  index,
  provider,
  count,
}: {
  form: UseFormReturnType<FormValues>
  index: number
  provider: ProviderForm
  count: number
}) {
  const p = provider
  const name = `Provider ${String(index + 1)}`
  const path = `providers.${String(index)}`
  return (
    <Paper withBorder p="md" radius="md" component="section" aria-label={`${name}: ${sourceInfo[p.source].label}`}>
      <Stack gap="sm">
        <Group justify="space-between" wrap="nowrap" align="flex-start">
          <Select
            label={`${name} source`}
            description={sourceInfo[p.source].description}
            data={(Object.keys(sourceInfo) as Source[]).map((s) => ({ value: s, label: sourceInfo[s].label }))}
            allowDeselect={false}
            value={p.source}
            maw={520}
            style={{ flex: 1 }}
            onChange={(s) => {
              if (s) form.replaceListItem('providers', index, newProvider(s as Source))
            }}
          />
          <Group gap={4} wrap="nowrap" mt={4}>
            <Tooltip label="Move up">
              <ActionIcon
                variant="subtle"
                color="gray"
                aria-label={`Move ${name} up`}
                disabled={index === 0}
                onClick={() => {
                  form.reorderListItem('providers', { from: index, to: index - 1 })
                }}
              >
                <IconArrowUp size={16} />
              </ActionIcon>
            </Tooltip>
            <Tooltip label="Move down">
              <ActionIcon
                variant="subtle"
                color="gray"
                aria-label={`Move ${name} down`}
                disabled={index === count - 1}
                onClick={() => {
                  form.reorderListItem('providers', { from: index, to: index + 1 })
                }}
              >
                <IconArrowDown size={16} />
              </ActionIcon>
            </Tooltip>
            <Tooltip label="Remove">
              <ActionIcon
                variant="subtle"
                color="red"
                aria-label={`Remove ${name}`}
                onClick={() => {
                  form.removeListItem('providers', index)
                }}
              >
                <IconTrash size={16} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>
        {p.source === 'wikimedia' ? (
          <>
            <Select
              label="Category"
              description="A Commons category of photos; ignored when file names are listed"
              data={categories.includes(p.category) || !p.category ? categories : [p.category, ...categories]}
              searchable
              allowDeselect={false}
              maw={520}
              placeholder={p.files.length ? 'Not used: specific files are listed' : 'Pick a category'}
              {...form.getInputProps(`${path}.category`)}
            />
            <TagsInput
              label="Specific files (optional)"
              description="Commons file names, e.g. Lake Bled from the Mountain.jpg. Press Enter after each."
              placeholder={p.files.length ? undefined : 'File name'}
              maxTags={24}
              {...form.getInputProps(`${path}.files`)}
            />
          </>
        ) : null}
        {p.source === 'picsum' ? (
          <TagsInput
            label="Photo IDs (optional)"
            description={
              <>
                Leave empty for a random selection, or list IDs from{' '}
                <Anchor href="https://picsum.photos/images" target="_blank" rel="noreferrer noopener" size="xs">
                  picsum.photos/images
                </Anchor>
                .
              </>
            }
            placeholder={p.files.length ? undefined : '1015'}
            maxTags={24}
            {...form.getInputProps(`${path}.files`)}
          />
        ) : null}
        {p.source === 'url' ? (
          <TagsInput
            label="Image URLs"
            description="https:// addresses of landscape photos. Press Enter after each."
            placeholder={p.files.length ? undefined : 'https://example.com/photo.jpg'}
            maxTags={24}
            {...form.getInputProps(`${path}.files`)}
          />
        ) : null}
      </Stack>
    </Paper>
  )
}

function ImageCard({ img }: { img: Image }) {
  return (
    <Card padding="xs" component="figure" m={0}>
      <Card.Section>
        <img
          src={img.url}
          alt={img.title || 'Background image'}
          loading="lazy"
          style={{ display: 'block', width: '100%', aspectRatio: '16 / 10', objectFit: 'cover' }}
        />
      </Card.Section>
      <Text component="figcaption" size="xs" mt="xs">
        {img.source_url ? (
          <Anchor href={img.source_url} target="_blank" rel="noreferrer noopener" size="xs">
            {img.title || 'Image'}
          </Anchor>
        ) : (
          img.title || 'Image'
        )}
        {img.author ? ` by ${img.author}` : ''}
        {img.license ? (
          <>
            {', '}
            {img.license_url ? (
              <Anchor href={img.license_url} target="_blank" rel="noreferrer noopener" size="xs">
                {img.license}
              </Anchor>
            ) : (
              img.license
            )}
          </>
        ) : null}
      </Text>
    </Card>
  )
}
