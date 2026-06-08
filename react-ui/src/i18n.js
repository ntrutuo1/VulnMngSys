import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

const LANGUAGE_STORAGE_KEY = 'vulnmngsys-ui-language'

const resources = {
  en: {
    translation: {
      app: {
        title: 'VulnMngSys',
        subtitle: 'Windows Server configuration vulnerability scanner',
        statusReady: 'API ready',
        statusNotReady: 'API unavailable',
      },
      banner: {
        readyTitle: 'Scan flow is ready',
        readyDescription:
          'The app auto-selects the closest Windows Server rule profile, runs the JSON rule engine, and displays PASS/FAIL results.',
      },
      alerts: {
        nonServerTitle: 'This machine is not Windows Server',
        nonServerDescription: 'The tool is designed for Windows Server. Scan output may be incomplete.',
      },
      cards: {
        osTitle: 'Operating system',
        unknown: 'Unknown',
        notServer: 'Non-server host',
      },
      scan: {
        controlsTitle: 'Scan controls',
        quick: 'Quick',
        full: 'Full',
        start: 'Start scan',
        reconfig: 'Reconfig',
        resultsTitle: 'Scan results',
        profileMode: 'Profile: {{profile}} | Mode: {{mode}}',
        noResult: 'No scan result yet. Click Start scan to run the selected rule profile.',
      },
      messages: {
        inventoryLoadFailed: 'Failed to load machine inventory: {{error}}',
        scanDone: 'Scan completed: {{passed}}/{{total}} PASS rules',
        scanFailed: 'Scan failed',
        scanFailedWithError: 'Scan failed: {{error}}',
        reconfigDone: 'Reconfig completed: {{applied}} rule(s), {{skipped}} skipped. Run the scan again to verify.',
        reconfigFailed: 'Reconfig failed',
        reconfigFailedWithError: 'Reconfig failed: {{error}}',
      },
      report: {
        summary: '{{status}} | {{passed}}/{{total}} PASS',
        fileLabel: 'JSON file: {{path}}',
        modeQuick: 'Quick',
        modeFull: 'Full',
        na: 'N/A',
      },
      table: {
        rule: 'Rule',
        result: 'Result',
        expected: 'Expected',
        actual: 'Actual',
        status: 'Status',
        service: 'Service',
        checkType: 'Check type',
        source: 'Source',
        cisReference: 'CIS reference',
        registryPath: 'Registry path',
        powershellCheck: 'PowerShell check',
        remediation: 'Remediation',
        reason: 'Reason',
        guidance: 'Guidance',
        details: 'Details',
        totalRules: '{{from}}-{{to}} / {{total}} rules',
      },
      language: {
        label: 'Language',
        en: 'EN',
      },
      view: {
        desktop: 'Desktop',
        mobile: 'Mobile',
      },
      stage: {
        strategy: 'Strategy',
        configure: 'Configure',
        results: 'Results',
        strategyTitle: 'Choose scan strategy',
        continue: 'Continue',
        back: 'Back',
      },
      scanType: {
        title: 'Scan Type',
        config: 'Configuration Scan (PowerShell)',
        iisMsf: 'IIS Service Scan (Metasploit)',
        configDesc: 'Checks Windows security configuration rules via PowerShell, registry, secedit, and auditpol.',
        iisMsfDesc: 'Runs Metasploit auxiliary scanners against IIS / HTTP.sys through a backend-managed local msfrpcd service.',
      },
      iisAudit: {
        connectionTitle: 'Metasploit RPC Connection',
        controlsTitle: 'IIS MSF Audit Controls',
        resultsTitle: 'Audit Results',
        notConnected: 'Not Connected',
        notConnectedDesc: 'Test a successful msfRPC connection above to enable the IIS audit scan.',
        connected: 'Connected',
        disconnected: 'Disconnected',
        testConnection: 'Test Connection',
        runAudit: 'Run IIS MSF Audit',
        activeTest: 'Active Test (PUT write)',
        activeTestHint: 'Enable http_put_write_test â€” writes a benign test file. Only use in your own lab.',
        target: 'Target',
        safeMode: 'Safe mode: excludes DoS and memory-dump modules',
        moduleInfo: 'IIS / HTTP.sys service scanners for Windows Server 2022+',
        noResult: 'Connect to msfRPC and click "Run IIS MSF Audit" to start the scan.',
        running: 'Running IIS Metasploit auditâ€¦ this may take a few minutes.',
        done: 'IIS Audit complete â€” Score: {{score}}/100 ({{label}})',
        failed: 'IIS Audit failed',
      },
    },
  },
}

const initialLanguage = localStorage.getItem(LANGUAGE_STORAGE_KEY)
const fallbackLanguage = initialLanguage === 'en' ? initialLanguage : 'en'

i18n.use(initReactI18next).init({
  resources,
  lng: fallbackLanguage,
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false,
  },
})

i18n.on('languageChanged', (language) => {
  localStorage.setItem(LANGUAGE_STORAGE_KEY, language === 'en' ? 'en' : 'en')
})

export default i18n

