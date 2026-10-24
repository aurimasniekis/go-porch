import { Anchor, FileInput, Group, Image, Select, Stack, Text, TextInput } from '@mantine/core'
import type { UseFormReturnType } from '@mantine/form'
import { IconPhoto } from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import type { Application, UpdateApplicationRequest } from '@/api/admin/tenant'

export type IconSource = '' | 'thesvg' | 'dashboard_icons' | 'url' | 'upload'

/** How an application looks in the launcher: its section and icon (ADR-0045). */
export interface LauncherForm {
  group: string
  icon_source: IconSource
  icon_ref: string
  file: File | null
}

export function toLauncherForm(a?: Application): LauncherForm {
  return {
    group: a?.group ?? '',
    icon_source: a?.icon_source ?? '',
    icon_ref: a?.icon_ref ?? '',
    file: null,
  }
}

const sources = [
  { value: '', label: 'No icon (letter tile)' },
  { value: 'thesvg', label: 'Brand logo from theSVG' },
  { value: 'dashboard_icons', label: 'From dashboard-icons' },
  { value: 'url', label: 'From an image URL' },
  { value: 'upload', label: 'Upload an image' },
]

const maxUpload = 512 * 1024

export function launcherValidate(v: LauncherForm, hasUploaded: boolean): Partial<Record<keyof LauncherForm, string>> {
  const e: Partial<Record<keyof LauncherForm, string>> = {}
  if (v.group.length > 64) e.group = 'At most 64 characters'
  if (v.icon_source === 'thesvg' && !/^[a-z0-9][a-z0-9-]{0,99}(\/[a-z0-9][a-z0-9-]{0,49})?$/.test(v.icon_ref.trim()))
    e.icon_ref = 'A theSVG slug, optionally with a variant (e.g. github or github/mono)'
  if (v.icon_source === 'dashboard_icons' && !/^[a-z0-9][a-z0-9-]{0,99}$/.test(v.icon_ref.trim()))
    e.icon_ref = 'An icon name: lowercase letters, digits and dashes (e.g. grafana)'
  if (v.icon_source === 'url' && !/^https:\/\/\S+$/.test(v.icon_ref.trim())) e.icon_ref = 'An https:// image URL'
  if (v.icon_source === 'upload' && !v.file && !hasUploaded) e.file = 'Choose an image'
  if (v.file && v.file.size > maxUpload) e.file = 'At most 512 KiB'
  return e
}

/**
 * The group and icon part of an application update. Upload is sent separately (PUT …/icon); keeping the uploaded icon
 * sends nothing.
 */
export function launcherUpdate(v: LauncherForm, a?: Application): Pick<UpdateApplicationRequest, 'group' | 'icon'> {
  const out: Pick<UpdateApplicationRequest, 'group' | 'icon'> = { group: v.group.trim() }
  const ref = v.icon_ref.trim()
  if (v.icon_source === '' && (a?.icon_source ?? '') !== '') out.icon = { source: '' }
  if (
    (v.icon_source === 'thesvg' || v.icon_source === 'dashboard_icons' || v.icon_source === 'url') &&
    (v.icon_source !== a?.icon_source || ref !== a.icon_ref)
  )
    out.icon = { source: v.icon_source, ref }
  return out
}

/** Reads a file as base64 (without the data: prefix). */
export async function fileBase64(f: File): Promise<string> {
  const buf = new Uint8Array(await f.arrayBuffer())
  let bin = ''
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000))
  return btoa(bin)
}

function useDataURL(f: File | null): string {
  const [url, setUrl] = useState('')
  useEffect(() => {
    if (!f) return
    // A data: URL, not blob:, because the Content-Security-Policy allows img-src 'self' data: only.
    let live = true
    const r = new FileReader()
    r.onload = () => {
      if (live && typeof r.result === 'string') setUrl(r.result)
    }
    r.readAsDataURL(f)
    return () => {
      live = false
    }
  }, [f])
  return f ? url : ''
}

export function LauncherFields({ form, current }: { form: UseFormReturnType<LauncherForm>; current?: Application }) {
  const preview = useDataURL(form.values.file)
  const shown = preview || (form.values.icon_source === current?.icon_source ? current.icon_url : '')
  const src = form.values.icon_source
  return (
    <Stack>
      <TextInput
        label="Launcher group"
        description="Applications with the same group appear together in the launcher (e.g. Media, Documents)"
        placeholder="No group"
        {...form.getInputProps('group')}
      />
      <Group align="flex-start" wrap="nowrap" gap="lg">
        <Stack gap={4} align="center" w={88}>
          {shown ? (
            <Image src={shown} alt="Icon preview" w={64} h={64} fit="contain" />
          ) : (
            <IconPhoto size={64} stroke={1} aria-hidden color="var(--mantine-color-dimmed)" />
          )}
          <Text size="xs" c="dimmed">
            {shown ? 'Current' : 'No icon'}
          </Text>
        </Stack>
        <Stack style={{ flex: 1 }}>
          <Select
            label="Icon"
            data={sources}
            allowDeselect={false}
            value={src}
            onChange={(v) => {
              form.setFieldValue('icon_source', (v ?? '') as IconSource)
              form.setFieldValue('icon_ref', v === current?.icon_source ? current.icon_ref : '')
              form.setFieldValue('file', null)
            }}
          />
          {src === 'thesvg' ? (
            <TextInput
              label="Logo"
              placeholder="grafana"
              description={
                <>
                  A slug from the{' '}
                  <Anchor href="https://thesvg.org" target="_blank" rel="noreferrer noopener" size="xs">
                    theSVG
                  </Anchor>{' '}
                  brand library, optionally with a variant (github/mono). Porch downloads it once and serves it itself.
                </>
              }
              {...form.getInputProps('icon_ref')}
            />
          ) : null}
          {src === 'dashboard_icons' ? (
            <TextInput
              label="Icon name"
              placeholder="grafana"
              description={
                <>
                  A name from the open{' '}
                  <Anchor href="https://dashboardicons.com" target="_blank" rel="noreferrer noopener" size="xs">
                    dashboard-icons
                  </Anchor>{' '}
                  set. Porch downloads it once and serves it itself.
                </>
              }
              {...form.getInputProps('icon_ref')}
            />
          ) : null}
          {src === 'url' ? (
            <TextInput
              label="Image URL"
              placeholder="https://example.com/logo.png"
              description="SVG, PNG, JPEG, GIF or WebP. Porch downloads it once and serves it itself."
              {...form.getInputProps('icon_ref')}
            />
          ) : null}
          {src === 'upload' ? (
            <FileInput
              label="Image file"
              placeholder={current?.icon_source === 'upload' ? 'Keep the uploaded icon' : 'Choose a file'}
              description="SVG, PNG, JPEG, GIF or WebP, at most 512 KiB. Pictures are scaled to 256×256; SVGs are cleaned of scripts."
              accept=".svg,.png,.jpg,.jpeg,.gif,.webp,image/svg+xml,image/png,image/jpeg,image/gif,image/webp"
              clearable
              clearButtonProps={{ 'aria-label': 'Clear file' }}
              {...form.getInputProps('file')}
            />
          ) : null}
        </Stack>
      </Group>
    </Stack>
  )
}
