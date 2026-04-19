export const moduleCatalog = [
  { id: 'linux-ubuntu22-ssh', osFamily: 'linux', osVersion: 'ubuntu-22.04', service: 'ssh', name: 'Ubuntu 22.04 - SSH Server' },
  { id: 'linux-ubuntu24-ssh', osFamily: 'linux', osVersion: 'ubuntu-24.04', service: 'ssh', name: 'Ubuntu 24.04 - SSH Server' },
  { id: 'linux-generic-apache-http', osFamily: 'linux', osVersion: 'generic', service: 'apache-http', name: 'Linux - Apache HTTP Server 2.4' },
  { id: 'linux-generic-tomcat', osFamily: 'linux', osVersion: 'generic', service: 'apache-tomcat', name: 'Linux - Apache Tomcat 7/8/9/10/10.1' },
  { id: 'windows-11-ssh', osFamily: 'windows', osVersion: 'windows-11', service: 'ssh', name: 'Windows 11 - OpenSSH Server' },
  { id: 'windows-generic-apache-http', osFamily: 'windows', osVersion: 'generic', service: 'apache-http', name: 'Windows - Apache HTTP Server 2.4' },
  { id: 'windows-generic-tomcat', osFamily: 'windows', osVersion: 'generic', service: 'apache-tomcat', name: 'Windows - Apache Tomcat 10.1' },
  { id: 'macos-14-ssh', osFamily: 'macos', osVersion: 'macos-14', service: 'ssh', name: 'macOS 14 - OpenSSH' },
  { id: 'macos-generic-apache-http', osFamily: 'macos', osVersion: 'generic', service: 'apache-http', name: 'macOS - Apache HTTP Server' },
  { id: 'macos-generic-tomcat', osFamily: 'macos', osVersion: 'generic', service: 'apache-tomcat', name: 'macOS - Apache Tomcat' },
];

const ruleTemplates = {
  ssh: [
    ['Disable direct root login', 'Critical'],
    ['Disallow empty passwords', 'Critical'],
    ['Limit auth retries', 'High'],
    ['Disable forwarding', 'High'],
    ['Set legal banner', 'Low'],
  ],
  'apache-http': [
    ['Hide version details', 'High'],
    ['Disable server signature', 'Medium'],
    ['Disable TRACE', 'High'],
    ['Set keepalive timeout', 'Medium'],
    ['Limit request body', 'High'],
  ],
  'apache-tomcat': [
    ['Disable shutdown port', 'Critical'],
    ['Harden connector headers', 'High'],
    ['Mask server header', 'Medium'],
    ['Safe global error page', 'High'],
    ['Disable cross-context', 'Medium'],
  ],
};

const severityWeight = {
  Low: 1,
  Medium: 4,
  High: 7,
  Critical: 10,
};

export function simulateScan(moduleDef) {
  const rows = (ruleTemplates[moduleDef.service] || []).map(([name, severity], index) => {
    const passed = Math.random() > (severity === 'Critical' ? 0.45 : 0.3);
    return {
      code: `${moduleDef.id.toUpperCase().slice(0, 5)}-${String(index + 1).padStart(3, '0')}`,
      title: name,
      severity,
      weight: severityWeight[severity],
      passed,
      reason: passed ? 'Compliant with expected value' : 'Missing or mismatched directive',
    };
  });

  const totalWeight = rows.reduce((sum, item) => sum + item.weight, 0);
  const passedWeight = rows.filter((item) => item.passed).reduce((sum, item) => sum + item.weight, 0);
  const index = totalWeight === 0 ? 0 : Math.round((passedWeight / totalWeight) * 100);

  let grade = 'D';
  if (index >= 90) grade = 'A';
  else if (index >= 75) grade = 'B';
  else if (index >= 60) grade = 'C';

  return {
    hardeningIndex: index,
    grade,
    passedChecks: rows.filter((item) => item.passed).length,
    totalChecks: rows.length,
    rows,
  };
}
