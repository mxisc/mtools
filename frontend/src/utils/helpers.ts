export function getSeverityLabel(severity: string): string {
  return severity
}

export function getSeverityClass(severity: string): string {
  const map: Record<string, string> = {
    高: 'high',
    中: 'medium',
    低: 'low',
    信息: 'info',
  }
  return `severity-${map[severity] || 'info'}`
}

export function getCoverageLabel(status: string): string {
  const map: Record<string, string> = {
    covered: '已覆盖',
    partial: '部分覆盖',
    not_covered: '未覆盖',
  }
  return map[status] || status
}

export function getCoverageClass(status: string): string {
  return `coverage-${status}`
}

export function guessService(port: number): string {
  const wellKnown: Record<number, string> = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    161: 'SNMP',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    514: 'Syslog',
    587: 'SMTP-TLS',
    631: 'IPP',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1434: 'MSSQL-Browser',
    1521: 'Oracle',
    2049: 'NFS',
    2082: 'cPanel',
    2083: 'cPanel-SSL',
    2086: 'WHM',
    2087: 'WHM-SSL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5901: 'VNC-1',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt',
    9090: 'HTTP-Admin',
    11211: 'Memcached',
    27017: 'MongoDB',
  }
  return wellKnown[port] || 'Unknown'
}

export function formatDuration(ms: number): string {
  if (ms < 1) return `${Math.round(ms * 1000)}μs`
  if (ms < 1000) return `${ms.toFixed(0)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}
