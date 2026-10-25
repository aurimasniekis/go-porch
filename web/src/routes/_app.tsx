import { createFileRoute, Outlet, redirect } from '@tanstack/react-router'
import { meQuery } from '@/api/queries'

// Pages that need a session. Without one the browser goes to /login and comes back afterwards. Each section draws its
// own layout: administration uses AppLayout, the launcher and account pages UserShell.
export const Route = createFileRoute('/_app')({
  beforeLoad: async ({ context, location }) => {
    const me = await context.queryClient.query(meQuery)
    if (!me) throw redirect({ to: '/login', search: { return_to: location.href, error: '', stepup: '' } })
    return { me }
  },
  component: Outlet,
})
