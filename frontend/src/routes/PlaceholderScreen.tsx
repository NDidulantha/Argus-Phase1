import { ArgusMark } from '../components/ArgusMark'

interface PlaceholderScreenProps {
  title: string
}

// Empty-state placeholder (ui-design.md §5): faint scan-ring watermark,
// one line, never a dead end. Replaced screen by screen through Phase 1.
export function PlaceholderScreen({ title }: PlaceholderScreenProps) {
  return (
    <div className="flex h-full flex-col p-6">
      <h1 className="text-page-title">{title}</h1>
      <div className="flex flex-1 flex-col items-center justify-center gap-4">
        <ArgusMark size={72} className="opacity-20" />
        <p className="text-label text-tertiary">This screen hasn't been built yet.</p>
      </div>
    </div>
  )
}
