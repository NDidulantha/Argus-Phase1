import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '../context/AuthContext'
import { ApiError } from '../lib/api'

// useQuery with the JWT injected; an expired token logs the session out.
export function useAuthedQuery<T>(
  key: readonly unknown[],
  fn: (token: string) => Promise<T>,
  options?: { refetchInterval?: number },
) {
  const { token, logout } = useAuth()
  const query = useQuery({
    queryKey: [...key, token],
    queryFn: () => fn(token!),
    enabled: token !== null,
    retry: 1,
    refetchInterval: options?.refetchInterval,
  })

  const { error } = query
  useEffect(() => {
    if (error instanceof ApiError && error.status === 401) logout()
  }, [error, logout])

  return query
}
