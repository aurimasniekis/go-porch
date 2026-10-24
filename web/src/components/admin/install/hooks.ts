import { useQueryClient, type QueryKey } from '@tanstack/react-query'
import { useAdminMutation } from '@/api/admin'
import { explainConflict, isConflict } from '@/api/admin/install'

/**
 * useAdminMutation for versioned resources: a 412 (If-Match failed) reloads `invalidate` and reports
 * "changed by someone else" instead of the raw precondition error.
 */
export function useVersionedMutation<TVars, TData>(opts: {
  mutationFn: (vars: TVars) => Promise<TData>
  success?: string | ((data: TData) => string)
  invalidate?: QueryKey[]
  onSuccess?: (data: TData) => void
}) {
  const qc = useQueryClient()
  return useAdminMutation<TVars, TData>({
    ...opts,
    mutationFn: async (vars) => {
      try {
        return await opts.mutationFn(vars)
      } catch (e) {
        if (isConflict(e)) for (const key of opts.invalidate ?? []) await qc.invalidateQueries({ queryKey: key })
        return explainConflict(e)
      }
    },
  })
}
