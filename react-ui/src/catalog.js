export const moduleCatalog = [
  { id: 'linux-ubuntu22-ssh', osFamily: 'linux', osVersion: 'ubuntu-22.04', service: 'ssh', name: 'Ubuntu 22.04 - SSH Server' },
  { id: 'linux-ubuntu24-ssh', osFamily: 'linux', osVersion: 'ubuntu-24.04', service: 'ssh', name: 'Ubuntu 24.04 - SSH Server' },
  { id: 'linux-ubuntu22-apache-http-config', osFamily: 'linux', osVersion: 'ubuntu-22.04', service: 'apache-http', name: 'HTTP-APACHE-config-scanner (Ubuntu 22.04)' },
  { id: 'linux-generic-tomcat', osFamily: 'linux', osVersion: 'generic', service: 'apache-tomcat', name: 'Linux - Apache Tomcat 7/8/9/10/10.1' },
  { id: 'windows-11-ssh', osFamily: 'windows', osVersion: 'windows-11', service: 'ssh', name: 'Windows 11 - OpenSSH Server' },
  { id: 'windows-11-apache-http-config', osFamily: 'windows', osVersion: 'windows-11', service: 'apache-http', name: 'HTTP-APACHE-config-scanner (Windows 11)' },
  { id: 'windows-generic-tomcat', osFamily: 'windows', osVersion: 'generic', service: 'apache-tomcat', name: 'Windows - Apache Tomcat 10.1' },
  { id: 'macos-14-ssh', osFamily: 'macos', osVersion: 'macos-14', service: 'ssh', name: 'macOS 14 - OpenSSH' },
  { id: 'macos-generic-apache-http', osFamily: 'macos', osVersion: 'generic', service: 'apache-http', name: 'macOS - Apache HTTP Server' },
  { id: 'macos-generic-tomcat', osFamily: 'macos', osVersion: 'generic', service: 'apache-tomcat', name: 'macOS - Apache Tomcat' },
];

export const ruleTemplates = {
  ssh: [
    {
      title: 'Disable direct root login',
      severity: 'Critical',
      where: '/etc/ssh/sshd_config -> PermitRootLogin',
      expected: 'PermitRootLogin no',
      passObserved: ['PermitRootLogin no'],
      failObserved: ['PermitRootLogin yes', 'PermitRootLogin prohibit-password'],
      shortReason: 'Root can still authenticate directly over SSH.',
      whyFail: 'Direct root login significantly raises blast radius if credentials are leaked.',
      fixCommands: ['sudo sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config', 'sudo systemctl reload sshd'],
      cisRef: 'CIS SSH 5.2.8',
    },
    {
      title: 'Disallow empty passwords',
      severity: 'Critical',
      where: '/etc/ssh/sshd_config -> PermitEmptyPasswords',
      expected: 'PermitEmptyPasswords no',
      passObserved: ['PermitEmptyPasswords no'],
      failObserved: ['PermitEmptyPasswords yes', 'PermitEmptyPasswords not set'],
      shortReason: 'Empty password authentication is possible.',
      whyFail: 'Attackers can brute-force accounts that accidentally have blank passwords.',
      fixCommands: ['sudo sed -i "s/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config', 'sudo systemctl reload sshd'],
      cisRef: 'CIS SSH 5.2.9',
    },
    {
      title: 'Limit auth retries',
      severity: 'High',
      where: '/etc/ssh/sshd_config -> MaxAuthTries',
      expected: 'MaxAuthTries 4 or less',
      passObserved: ['MaxAuthTries 4', 'MaxAuthTries 3'],
      failObserved: ['MaxAuthTries 6', 'MaxAuthTries 10'],
      shortReason: 'Too many attempts allowed per connection.',
      whyFail: 'Higher retry count increases online brute-force success probability.',
      fixCommands: ['sudo sed -i "s/^#*MaxAuthTries.*/MaxAuthTries 4/" /etc/ssh/sshd_config', 'sudo systemctl reload sshd'],
      cisRef: 'CIS SSH 5.2.15',
    },
    {
      title: 'Disable forwarding',
      severity: 'High',
      where: '/etc/ssh/sshd_config -> AllowTcpForwarding',
      expected: 'AllowTcpForwarding no (unless explicitly required)',
      passObserved: ['AllowTcpForwarding no'],
      failObserved: ['AllowTcpForwarding yes', 'AllowTcpForwarding not set'],
      shortReason: 'SSH tunnel forwarding still enabled.',
      whyFail: 'Forwarding can be abused to bypass network segmentation controls.',
      fixCommands: ['sudo sed -i "s/^#*AllowTcpForwarding.*/AllowTcpForwarding no/" /etc/ssh/sshd_config', 'sudo systemctl reload sshd'],
      cisRef: 'CIS SSH 5.2.17',
    },
    {
      title: 'Set legal banner',
      severity: 'Low',
      where: '/etc/ssh/sshd_config -> Banner',
      expected: 'Banner /etc/issue.net',
      passObserved: ['Banner /etc/issue.net'],
      failObserved: ['Banner none', 'Banner not set'],
      shortReason: 'No pre-login legal warning banner configured.',
      whyFail: 'Legal banner supports policy enforcement and prosecution posture.',
      fixCommands: ['echo "Authorized access only" | sudo tee /etc/issue.net', 'sudo sed -i "s|^#*Banner.*|Banner /etc/issue.net|" /etc/ssh/sshd_config', 'sudo systemctl reload sshd'],
      cisRef: 'CIS SSH 5.2.20',
    },
  ],
  'apache-http': [
    {
      title: 'Hide version details',
      severity: 'High',
      where: 'httpd.conf -> ServerTokens',
      expected: 'ServerTokens Prod',
      passObserved: ['ServerTokens Prod'],
      failObserved: ['ServerTokens Full', 'ServerTokens OS'],
      shortReason: 'Server version detail still exposed in responses.',
      whyFail: 'Detailed version leaks improve exploit targeting precision.',
      fixCommands: ['echo "ServerTokens Prod" | sudo tee -a /etc/apache2/conf-enabled/security.conf', 'sudo systemctl reload apache2'],
      cisRef: 'CIS Apache 2.4 2.4.1',
    },
    {
      title: 'Disable server signature',
      severity: 'Medium',
      where: 'httpd.conf -> ServerSignature',
      expected: 'ServerSignature Off',
      passObserved: ['ServerSignature Off'],
      failObserved: ['ServerSignature On', 'ServerSignature not set'],
      shortReason: 'Error pages disclose server signature.',
      whyFail: 'Signature disclosure reveals stack metadata during errors.',
      fixCommands: ['echo "ServerSignature Off" | sudo tee -a /etc/apache2/conf-enabled/security.conf', 'sudo systemctl reload apache2'],
      cisRef: 'CIS Apache 2.4 2.4.2',
    },
    {
      title: 'Disable TRACE',
      severity: 'High',
      where: 'httpd.conf -> TraceEnable',
      expected: 'TraceEnable Off',
      passObserved: ['TraceEnable Off'],
      failObserved: ['TraceEnable On', 'TraceEnable not set'],
      shortReason: 'HTTP TRACE method is not disabled.',
      whyFail: 'TRACE can assist cross-site tracing and credential reflection attacks.',
      fixCommands: ['echo "TraceEnable Off" | sudo tee -a /etc/apache2/conf-enabled/security.conf', 'sudo systemctl reload apache2'],
      cisRef: 'CIS Apache 2.4 3.5',
    },
    {
      title: 'Set keepalive timeout',
      severity: 'Medium',
      where: 'httpd.conf -> KeepAliveTimeout',
      expected: 'KeepAliveTimeout <= 5',
      passObserved: ['KeepAliveTimeout 5', 'KeepAliveTimeout 3'],
      failObserved: ['KeepAliveTimeout 15', 'KeepAliveTimeout 30'],
      shortReason: 'Keep-alive timeout too high.',
      whyFail: 'Long keep-alive ties up workers and increases DoS susceptibility.',
      fixCommands: ['sudo sed -i "s/^KeepAliveTimeout.*/KeepAliveTimeout 5/" /etc/apache2/apache2.conf', 'sudo systemctl reload apache2'],
      cisRef: 'CIS Apache 2.4 2.4.6',
    },
    {
      title: 'Limit request body',
      severity: 'High',
      where: 'httpd.conf -> LimitRequestBody',
      expected: 'LimitRequestBody set to safe boundary (example 10485760)',
      passObserved: ['LimitRequestBody 10485760'],
      failObserved: ['LimitRequestBody 0', 'LimitRequestBody not set'],
      shortReason: 'Request body size is effectively unlimited.',
      whyFail: 'Unlimited payload size can drive memory pressure and app-layer DoS.',
      fixCommands: ['echo "LimitRequestBody 10485760" | sudo tee -a /etc/apache2/apache2.conf', 'sudo systemctl reload apache2'],
      cisRef: 'CIS Apache 2.4 2.4.8',
    },
  ],
  'apache-tomcat': [
    {
      title: 'Disable shutdown port',
      severity: 'Critical',
      where: 'server.xml -> Server@port',
      expected: 'Server port="-1"',
      passObserved: ['Server port="-1"'],
      failObserved: ['Server port="8005"'],
      shortReason: 'Shutdown port still reachable.',
      whyFail: 'Open shutdown port can allow remote service interruption.',
      fixCommands: ['sudo sed -i "s/<Server port=\"8005\"/<Server port=\"-1\"/" /opt/tomcat/conf/server.xml', 'sudo systemctl restart tomcat'],
      cisRef: 'CIS Tomcat 5.1',
    },
    {
      title: 'Harden connector headers',
      severity: 'High',
      where: 'server.xml -> Connector@xpoweredBy',
      expected: 'xpoweredBy="false"',
      passObserved: ['xpoweredBy="false"'],
      failObserved: ['xpoweredBy="true"', 'xpoweredBy not set'],
      shortReason: 'Technology header exposure is still enabled.',
      whyFail: 'Header leakage helps attacker fingerprint vulnerable stacks.',
      fixCommands: ['Set xpoweredBy="false" on all HTTP connectors in server.xml', 'sudo systemctl restart tomcat'],
      cisRef: 'CIS Tomcat 3.2',
    },
    {
      title: 'Mask server header',
      severity: 'Medium',
      where: 'server.xml -> Connector@server',
      expected: 'server="" or generic value',
      passObserved: ['server=""'],
      failObserved: ['server="Apache-Coyote/1.1"', 'server not set'],
      shortReason: 'Server header still reveals Tomcat flavor.',
      whyFail: 'Server banner leakage lowers attacker reconnaissance effort.',
      fixCommands: ['Set server="" in Connector block', 'sudo systemctl restart tomcat'],
      cisRef: 'CIS Tomcat 3.1',
    },
    {
      title: 'Safe global error page',
      severity: 'High',
      where: 'web.xml -> error-page',
      expected: 'Custom sanitized error pages configured',
      passObserved: ['error-page entries defined for 4xx/5xx'],
      failObserved: ['Default Tomcat error page in use'],
      shortReason: 'Default verbose error page still active.',
      whyFail: 'Verbose errors leak internals useful for exploit chaining.',
      fixCommands: ['Define custom error-page blocks in conf/web.xml', 'sudo systemctl restart tomcat'],
      cisRef: 'CIS Tomcat 4.6',
    },
    {
      title: 'Disable cross-context',
      severity: 'Medium',
      where: 'context.xml -> crossContext',
      expected: 'crossContext="false"',
      passObserved: ['crossContext="false"'],
      failObserved: ['crossContext="true"', 'crossContext not set'],
      shortReason: 'Cross-context access is enabled.',
      whyFail: 'Cross-context access can allow privilege crossing between apps.',
      fixCommands: ['Set crossContext="false" in all Context definitions', 'sudo systemctl restart tomcat'],
      cisRef: 'CIS Tomcat 4.1',
    },
  ],
};

const severityWeight = {
  Low: 1,
  Medium: 4,
  High: 7,
  Critical: 10,
};

const passThresholdBySeverity = {
  Low: 0.2,
  Medium: 0.38,
  High: 0.55,
  Critical: 0.7,
};

const modeThresholdShift = {
  strict: 0.08,
  balanced: 0,
  quick: -0.08,
};

function hashText(text) {
  let hash = 0;
  for (let i = 0; i < text.length; i += 1) {
    hash = (hash * 31 + text.charCodeAt(i)) >>> 0;
  }
  return hash;
}

function pickValue(values, seed) {
  if (!values || values.length === 0) return 'N/A';
  return values[seed % values.length];
}

export function simulateScan(moduleDef, context = {}) {
  const scanMode = context.scanMode || 'balanced';
  const fingerprint = `${moduleDef.id}|${context.osVersion || ''}|${context.serviceVersion || ''}|${scanMode}`;

  const rows = (ruleTemplates[moduleDef.service] || []).map((rule, index) => {
    const seed = hashText(`${fingerprint}|${rule.title}|${index}`);
    const score = (seed % 1000) / 1000;
    const threshold = (passThresholdBySeverity[rule.severity] || 0.5) + (modeThresholdShift[scanMode] || 0);
    const passed = score >= threshold;

    return {
      code: `${moduleDef.id.toUpperCase().slice(0, 5)}-${String(index + 1).padStart(3, '0')}`,
      title: rule.title,
      severity: rule.severity,
      weight: severityWeight[rule.severity],
      passed,
      where: rule.where,
      expected: rule.expected,
      observed: passed ? pickValue(rule.passObserved, seed) : pickValue(rule.failObserved, seed),
      shortReason: passed ? 'Configuration matches expected hardening baseline.' : rule.shortReason,
      whyFail: passed ? 'No mismatch detected in this check.' : rule.whyFail,
      fixCommands: passed ? [] : rule.fixCommands,
      cisRef: rule.cisRef,
    };
  });

  const totalWeight = rows.reduce((sum, item) => sum + item.weight, 0);
  const passedWeight = rows.filter((item) => item.passed).reduce((sum, item) => sum + item.weight, 0);
  const index = totalWeight === 0 ? 0 : Math.round((passedWeight / totalWeight) * 100);

  const failedRows = rows.filter((item) => !item.passed);
  const failedCritical = failedRows.filter((item) => item.severity === 'Critical').length;
  const failedHigh = failedRows.filter((item) => item.severity === 'High').length;

  let grade = 'D';
  if (index >= 90) grade = 'A';
  else if (index >= 75) grade = 'B';
  else if (index >= 60) grade = 'C';

  return {
    hardeningIndex: index,
    grade,
    passedChecks: rows.filter((item) => item.passed).length,
    totalChecks: rows.length,
    failedChecks: failedRows.length,
    failedCritical,
    failedHigh,
    topPriority: failedRows
      .slice()
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3)
      .map((row) => `${row.code}: ${row.title}`),
    rows,
  };
}
