import { Anchor } from '@mantine/core'
import type { Appearance } from '@/api/queries'

type Background = NonNullable<Appearance['background']>

/** Inline style for an element showing the appearance background (a gradient when there is none). */
export function backgroundStyle(bg: Background | null | undefined): React.CSSProperties | undefined {
  return bg ? { backgroundImage: `url("${bg.url}")` } : undefined
}

/** Full-screen background behind the sign-in pages. */
export function Backdrop({ background }: { background: Background | null | undefined }) {
  return <div className="porch-backdrop" style={backgroundStyle(background)} aria-hidden />
}

/** Credit line required by the image's license (Wikimedia Commons, Unsplash via Picsum). */
export function Credit({ background, className }: { background: Background | null | undefined; className?: string }) {
  if (!background) return null
  const by = background.author ? ` by ${background.author}` : ''
  return (
    <p className={className ?? 'porch-credit'}>
      Background:{' '}
      <Anchor href={background.source_url} c="inherit" inherit target="_blank" rel="noreferrer noopener">
        {background.title || 'photo'}
      </Anchor>
      {by}
      {background.license ? (
        <>
          ,{' '}
          {background.license_url ? (
            <Anchor href={background.license_url} c="inherit" inherit target="_blank" rel="noreferrer noopener">
              {background.license}
            </Anchor>
          ) : (
            background.license
          )}
        </>
      ) : null}
    </p>
  )
}
