import { Button, Group, Modal, Stack, type ButtonProps } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import type { ReactNode } from 'react'

/**
 * Asks for confirmation before running a destructive action. Same contract as the kit's ConfirmButton, with two
 * accessibility fixes: the trigger uses the neutral "default" variant (Mantine's tinted red fails WCAG AA contrast) and
 * the dialog's close button has an accessible name. Scroll locking is off: react-remove-scroll injects a <style> element
 * without the CSP nonce.
 */
export function ConfirmAction({
  label,
  title,
  children,
  onConfirm,
  loading,
  color = 'red',
  confirmLabel,
  size = 'xs',
  disabled,
}: {
  label: ReactNode
  title: string
  children: ReactNode
  onConfirm: () => unknown
  loading?: boolean
  color?: string
  confirmLabel?: string
  size?: ButtonProps['size']
  disabled?: boolean
}) {
  const [opened, { open, close }] = useDisclosure(false)
  return (
    <>
      <Button variant="default" size={size} onClick={open} disabled={disabled}>
        {label}
      </Button>
      <Modal
        opened={opened}
        onClose={close}
        title={title}
        centered
        closeButtonProps={{ 'aria-label': 'Close' }}
        lockScroll={false}
      >
        <Stack>
          <div>{children}</div>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button
              color={color}
              loading={loading}
              onClick={() => {
                void (async () => {
                  try {
                    await onConfirm()
                  } finally {
                    close()
                  }
                })()
              }}
            >
              {confirmLabel ?? (typeof label === 'string' ? label : 'Confirm')}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}
