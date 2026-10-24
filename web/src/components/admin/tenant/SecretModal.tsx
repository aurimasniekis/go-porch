import { Button, Group, Modal, Stack } from '@mantine/core'
import { IconAlertTriangle } from '@tabler/icons-react'
import type { ReactNode } from 'react'
import { CopyField, Notice } from './common'

export interface OneTimeSecret {
  title: string
  clientId: string
  secret: string
}

/**
 * Shows a client secret exactly once. The secret is kept only in component state and dropped when the dialog closes.
 */
export function SecretModal({
  value,
  onClose,
  children,
}: {
  value: OneTimeSecret | null
  onClose: () => void
  children?: ReactNode
}) {
  return (
    <Modal
      opened={value !== null}
      onClose={onClose}
      title={value?.title ?? 'Client secret'}
      size="lg"
      centered
      closeOnClickOutside={false}
    >
      {value ? (
        <Stack>
          <Notice color="yellow" icon={<IconAlertTriangle size={18} />} title="Shown only once">
            Copy the client secret now and store it in a secret manager. Porch keeps only a hash: it cannot show this
            secret again. If it is lost, rotate the secret.
          </Notice>
          <CopyField label="Client ID" value={value.clientId} />
          <CopyField label="Client secret" value={value.secret} secret />
          {children}
          <Group justify="flex-end">
            <Button onClick={onClose}>I have stored the secret</Button>
          </Group>
        </Stack>
      ) : null}
    </Modal>
  )
}
