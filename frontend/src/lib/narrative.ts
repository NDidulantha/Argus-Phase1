// Parse the investigation narrative into its prompted sections
// (see backend _INSTRUCTIONS: SUMMARY / ATT&CK ASSESSMENT / CONFIDENCE /
// ALTERNATIVE EXPLANATIONS / RECOMMENDED NEXT STEPS). Models decorate the
// headings differently (### 1. SUMMARY, **SUMMARY**, …), so match loosely
// and fall back to one untitled section rather than dropping content.

const SECTION_TITLES = [
  'SUMMARY',
  'ATT&CK ASSESSMENT',
  'CONFIDENCE',
  'ALTERNATIVE EXPLANATIONS',
  'RECOMMENDED NEXT STEPS',
] as const

export interface NarrativeSection {
  title: string
  body: string
}

export interface ParsedNarrative {
  sections: NarrativeSection[]
  confidence: 'High' | 'Medium' | 'Low' | null
}

const headingPattern = new RegExp(
  `^\\s*#{0,6}\\s*\\**\\s*(?:\\d+\\s*[.)]\\s*)?(${SECTION_TITLES.map((t) =>
    t.replace('&', '&'),
  ).join('|')})\\s*\\**:?\\s*$`,
  'gim',
)

export function parseNarrative(text: string): ParsedNarrative {
  const matches = [...text.matchAll(headingPattern)]
  let sections: NarrativeSection[]

  if (matches.length >= 2) {
    sections = matches.map((m, i) => {
      const start = m.index! + m[0].length
      const end = i + 1 < matches.length ? matches[i + 1].index! : text.length
      return {
        title: m[1].toUpperCase(),
        body: text.slice(start, end).trim(),
      }
    })
  } else {
    sections = [{ title: 'ASSESSMENT', body: text.trim() }]
  }

  const confidenceBody = sections.find((s) => s.title === 'CONFIDENCE')?.body ?? ''
  const level = confidenceBody.match(/\b(High|Medium|Low)\b/i)?.[1]
  const confidence = level
    ? ((level[0].toUpperCase() + level.slice(1).toLowerCase()) as 'High' | 'Medium' | 'Low')
    : null

  return { sections, confidence }
}
