const numberFormat = new Intl.NumberFormat('en-US')

export function formatCount(n: number): string {
  return numberFormat.format(n)
}

// All analyst-facing timestamps render in UTC with an explicit label —
// never the browser's local zone. The backend stores and reasons in UTC;
// the UI showing local time next to a UTC narrative reads as two clocks.
function pad(n: number): string {
  return String(n).padStart(2, '0')
}

function utcDate(d: Date): string {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`
}

function utcClock(d: Date, seconds = true): string {
  const hm = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  return seconds ? `${hm}:${pad(d.getUTCSeconds())}` : hm
}

export function formatUtcDateTime(input: string | number): string {
  const d = new Date(input)
  return `${utcDate(d)} ${utcClock(d)} UTC`
}

export function formatUtcTime(input: string | number): string {
  return `${utcClock(new Date(input))} UTC`
}

// "2026-07-13 15:15 → 15:32 UTC" (dates collapse when the window is same-day)
export function formatUtcWindow(startIso: string, endIso: string): string {
  const start = new Date(startIso)
  const end = new Date(endIso)
  const startDay = utcDate(start)
  const endDay = utcDate(end)
  if (startDay === endDay) {
    return `${startDay} ${utcClock(start, false)} → ${utcClock(end, false)} UTC`
  }
  return `${startDay} ${utcClock(start, false)} → ${endDay} ${utcClock(end, false)} UTC`
}

export function relativeAge(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'now'
  const minutes = seconds / 60
  if (minutes < 60) return `${Math.floor(minutes)}m`
  const hours = minutes / 60
  if (hours < 24) return `${Math.floor(hours)}h`
  return `${Math.floor(hours / 24)}d`
}

export function isoHoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3_600_000).toISOString()
}
