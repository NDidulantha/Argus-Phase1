// MITRE kill-chain tactic order — shared by the attack chain, the matrix,
// and anything else that lays tactics out left to right. Vocabulary comes
// from the loaded catalog (it changes across ATT&CK releases); this list
// only provides ordering for the slugs it knows, with a stable fallback.
export const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'stealth',
  'defense-impairment',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]

export function tacticRank(tactic: string): number {
  const i = TACTIC_ORDER.indexOf(tactic)
  return i === -1 ? TACTIC_ORDER.length : i
}

export function tacticLabel(slug: string): string {
  return slug
    .split('-')
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(' ')
}
