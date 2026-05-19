export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  title: string
  details: string
  recommendation: string
  evidence: string
}

export interface CoverageItem {
  name: string
  status: 'covered' | 'partial' | 'not_covered'
  notes: string
}

export interface WebCheckResult {
  checkedAt: string
  target: string
  finalUrl: string
  statusCode: number
  usesHttps: boolean
  tlsVersion: string
  httpRedirectsToHttps: boolean
  supportedMethods: string[]
  checkedModules: string[]
  dvwaCoverage: CoverageItem[]
  findings: Finding[]
}

export interface OpenPortItem {
  port: number
  durationMs: number
  service: string
}

export interface PortScanProgress {
  checkedPort: number
  checkedCount: number
  total: number
  openPort: number
}

export interface PortScanResult {
  openPorts: OpenPortItem[]
  total: number
  scanned: number
  host: string
}
