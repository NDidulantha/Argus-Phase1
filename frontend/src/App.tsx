import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { Alerts } from './routes/Alerts'
import { CaseDetail } from './routes/CaseDetail'
import { Cases } from './routes/Cases'
import { Dashboard } from './routes/Dashboard'
import { Entities } from './routes/Entities'
import { EvidenceGraph } from './routes/EvidenceGraph'
import { Integrations } from './routes/Integrations'
import { Login } from './routes/Login'
import { Mitre } from './routes/Mitre'
import { Reports } from './routes/Reports'
import { Settings } from './routes/Settings'
import { Tenants } from './routes/Tenants'
import { ThreatIntel } from './routes/ThreatIntel'
import { Timeline } from './routes/Timeline'
import { PlaceholderScreen } from './routes/PlaceholderScreen'
import { RequireAuth } from './routes/RequireAuth'
import { Workspace } from './routes/Workspace'
import { navGroups } from './lib/navigation'

// Screens built so far; everything else stays a placeholder (Phase-1 §7).
const builtScreens: Record<string, () => React.JSX.Element> = {
  '/dashboard': Dashboard,
  '/alerts': Alerts,
  '/workspace': Workspace,
  '/cases': Cases,
  '/graph': EvidenceGraph,
  '/timeline': Timeline,
  '/integrations': Integrations,
  '/mitre': Mitre,
  '/entities': Entities,
  '/intel': ThreatIntel,
  '/reports': Reports,
  '/tenants': Tenants,
  '/settings': Settings,
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        {navGroups.flatMap((group) =>
          group.items.map((item) => {
            const Screen = builtScreens[item.path]
            return (
              <Route
                key={item.path}
                path={item.path}
                element={Screen ? <Screen /> : <PlaceholderScreen title={item.label} />}
              />
            )
          }),
        )}
        <Route path="/cases/:caseId" element={<CaseDetail />} />
        <Route path="*" element={<PlaceholderScreen title="Page not found" />} />
      </Route>
    </Routes>
  )
}
