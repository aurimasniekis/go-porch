import { ActionIcon, Button, Group, Input, Stack, TagsInput, Text, TextInput } from '@mantine/core'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { useId, useState } from 'react'
import { partitionPermissions, type AttributeRow } from './logic'

/**
 * Picks permissions from the catalogue or accepts free-form `<type>:<action>` entries (validated like the server;
 * invalid entries are rejected with a message).
 */
export function PermissionPicker({
  label,
  description,
  value,
  onChange,
  system = [],
  custom = [],
  disabled,
  allowStar,
  placeholder = 'Pick or type, e.g. doc:read',
}: {
  label: string
  description?: string
  value: string[]
  onChange: (v: string[]) => void
  system?: string[]
  custom?: string[]
  disabled?: boolean
  allowStar?: boolean
  placeholder?: string
}) {
  const [error, setError] = useState<string | null>(null)
  const data = [
    ...(allowStar ? [{ group: 'Everything', items: ['*'] }] : []),
    { group: 'System permissions', items: system },
    ...(custom.length > 0 ? [{ group: 'Custom permissions in use', items: custom }] : []),
  ].filter((g) => g.items.length > 0)
  return (
    <TagsInput
      label={label}
      description={
        description ?? 'Format <resource_type>:<action>; either side may be * (for example doc:* or *:read).'
      }
      placeholder={value.length === 0 ? placeholder : undefined}
      value={value}
      data={data}
      disabled={disabled}
      error={error}
      splitChars={[',', ' ']}
      acceptValueOnBlur
      clearable={!disabled}
      clearButtonProps={{ 'aria-label': `Clear ${label.toLowerCase()}` }}
      maxDropdownHeight={240}
      onChange={(vals) => {
        const { valid, invalid } = partitionPermissions(vals, allowStar)
        setError(
          invalid.length > 0
            ? `${invalid.map((i) => `"${i}"`).join(', ')} ${invalid.length > 1 ? 'are' : 'is'} not <resource_type>:<action> (lowercase letters, digits, _; either side may be *)`
            : null,
        )
        onChange(valid)
      }}
    />
  )
}

/** Edits string attributes as key/value rows. */
export function AttributesEditor({
  rows,
  onChange,
  error,
}: {
  rows: AttributeRow[]
  onChange: (rows: AttributeRow[]) => void
  error?: string | null
}) {
  const id = useId()
  const set = (i: number, patch: Partial<AttributeRow>) => {
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  }
  return (
    <Input.Wrapper
      label="Attributes"
      labelElement="div"
      id={id}
      description="Visible to policies as resource.attributes (keys: lowercase letters, digits, - or _)."
      error={error}
    >
      <Stack gap="xs" mt={4}>
        {rows.length === 0 ? (
          <Text size="sm" c="dimmed">
            No attributes.
          </Text>
        ) : null}
        {rows.map((r, i) => (
          <Group key={i} gap="xs" wrap="nowrap" align="flex-start">
            <TextInput
              aria-label={`Attribute ${i + 1} key`}
              placeholder="key"
              value={r.key}
              onChange={(e) => {
                set(i, { key: e.currentTarget.value })
              }}
              style={{ flex: 1 }}
            />
            <TextInput
              aria-label={`Attribute ${i + 1} value`}
              placeholder="value"
              value={r.value}
              onChange={(e) => {
                set(i, { value: e.currentTarget.value })
              }}
              style={{ flex: 2 }}
            />
            <ActionIcon
              variant="subtle"
              color="red"
              size="lg"
              aria-label={`Remove attribute ${r.key || i + 1}`}
              onClick={() => {
                onChange(rows.filter((_, j) => j !== i))
              }}
            >
              <IconTrash size={16} aria-hidden />
            </ActionIcon>
          </Group>
        ))}
        <Group>
          <Button
            variant="default"
            size="xs"
            leftSection={<IconPlus size={14} aria-hidden />}
            onClick={() => {
              onChange([...rows, { key: '', value: '' }])
            }}
          >
            Add attribute
          </Button>
        </Group>
      </Stack>
    </Input.Wrapper>
  )
}
