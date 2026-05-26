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
          'The app calls scripts/scan_executor.ps1 directly, receives PASS/FAIL JSON from scan_rules_*.ps1, and displays results on the UI.',
      },
      alerts: {
        nonServerTitle: 'This machine is not Windows Server',
        nonServerDescription: 'The tool is designed for Windows Server. Scan output may be incomplete.',
      },
      cards: {
        osTitle: 'Operating system',
        serviceTitle: 'Detected services',
        unknown: 'Unknown',
        notServer: 'Non-server host',
      },
      scan: {
        controlsTitle: 'Scan controls',
        servicesTitle: 'Detected services to scan',
        servicesDescription:
          'Choose the services you want to include in the scan. The engine will prune service-owned rules that are not selected.',
        quick: 'Quick',
        full: 'Full',
        start: 'Start scan',
        selectAll: 'Select all',
        clearSelection: 'Clear',
        serviceCount: '{{selected}} / {{total}} selected',
        noServicesDetected: 'No services detected on this machine.',
        selectedServicesSummary: '{{count}} selected services were included in the scan',
        resultsTitle: 'Scan results',
        profileMode: 'Profile: {{profile}} | Mode: {{mode}}',
        noResult: 'No scan result yet. Click Start scan to run scan_executor.ps1.',
      },
      messages: {
        inventoryLoadFailed: 'Failed to load machine inventory: {{error}}',
        selectServicesFirst: 'Select at least one detected service before starting the scan.',
        scanDone: 'Scan completed: {{passed}}/{{total}} PASS rules',
        scanFailed: 'Scan failed',
        scanFailedWithError: 'Scan failed: {{error}}',
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
