import {
  LayoutDashboard,
  Bell,
  Sparkles,
  FolderSearch,
  Network,
  ChartNoAxesGantt,
  Grid3x3,
  ScanSearch,
  Globe,
  FileText,
  Plug,
  Building2,
  Settings,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  label: string
  path: string
  icon: LucideIcon
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

// Information architecture per argus/ui-design.md §3 —
// grouped by analyst workflow, not by feature.
export const navGroups: NavGroup[] = [
  {
    label: 'Monitor',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
      { label: 'Alerts', path: '/alerts', icon: Bell },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { label: 'AI workspace', path: '/workspace', icon: Sparkles },
      { label: 'Cases', path: '/cases', icon: FolderSearch },
      { label: 'Evidence graph', path: '/graph', icon: Network },
      { label: 'Timeline', path: '/timeline', icon: ChartNoAxesGantt },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { label: 'MITRE ATT&CK', path: '/mitre', icon: Grid3x3 },
      { label: 'Entity explorer', path: '/entities', icon: ScanSearch },
      { label: 'Threat intel', path: '/intel', icon: Globe },
    ],
  },
  {
    label: 'Manage',
    items: [
      { label: 'Reports', path: '/reports', icon: FileText },
      { label: 'Integrations', path: '/integrations', icon: Plug },
      { label: 'Tenants', path: '/tenants', icon: Building2 },
      { label: 'Settings', path: '/settings', icon: Settings },
    ],
  },
]
