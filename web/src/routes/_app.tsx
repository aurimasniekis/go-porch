import { createFileRoute, Outlet, redirect, useRouterState } from '@tanstack/react-router'
import { meQuery } from '@/api/queries'
import { AppLayout } from '@/components/AppLayout'

// Pages that need a session. Without one the browser goes to /login and comes back afterwards. Administration keeps
// its own layout; the launcher and account pages draw their own (UserShell).
export const Route = createFileRoute('/_app')({
  beforeLoad: async ({ context, location }) => {
    const me = await context.queryClient.query(meQuery)
    if (!me) throw redirect({ to: '/login', search: { return_to: location.href, error: '', stepup: '' } })
    return { me }
  },
  component: function AppRoot() {
    const { me } = Route.useRouteContext()
    const admin = useRouterState({ select: (s) => s.location.pathname.startsWith('/admin') })
    return admin ? (
      <AppLayout me={me}>
        <Outlet />
      </AppLayout>
    ) : (
      <Outlet />
    )
  },
})
