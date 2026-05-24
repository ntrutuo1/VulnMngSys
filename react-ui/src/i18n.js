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
        quick: 'Quick',
        full: 'Full',
        start: 'Start scan',
        resultsTitle: 'Scan results',
        profileMode: 'Profile: {{profile}} | Mode: {{mode}}',
        noResult: 'No scan result yet. Click Start scan to run scan_executor.ps1.',
      },
      messages: {
        inventoryLoadFailed: 'Failed to load machine inventory: {{error}}',
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
        result: 'Result',
        totalRules: '{{from}}-{{to}} / {{total}} rules',
      },
      language: {
        label: 'Language',
        vi: 'VI',
        en: 'EN',
      },
    },
  },
  vi: {
    translation: {
      app: {
        title: 'VulnMngSys',
        subtitle: 'Cong cu phat hien lo hong cau hinh Windows Server',
        statusReady: 'API san sang',
        statusNotReady: 'API khong kha dung',
      },
      banner: {
        readyTitle: 'Luong scan da san sang',
        readyDescription:
          'Ung dung goi truc tiep scripts/scan_executor.ps1, nhan JSON PASS/FAIL tu scan_rules_*.ps1 va hien thi ket qua tren UI.',
      },
      alerts: {
        nonServerTitle: 'May hien tai khong phai Windows Server',
        nonServerDescription: 'Cong cu duoc thiet ke cho Windows Server. Ket qua scan co the khong day du.',
      },
      cards: {
        osTitle: 'He dieu hanh',
        serviceTitle: 'Dich vu phat hien',
        unknown: 'Khong xac dinh',
        notServer: 'Khong phai Server',
      },
      scan: {
        controlsTitle: 'Dieu khien scan',
        quick: 'Nhanh',
        full: 'Day du',
        start: 'Bat dau scan',
        resultsTitle: 'Ket qua scan',
        profileMode: 'Profile: {{profile}} | Mode: {{mode}}',
        noResult: 'Chua co ket qua scan. Bam Bat dau scan de chay scan_executor.ps1.',
      },
      messages: {
        inventoryLoadFailed: 'Khong tai duoc thong tin may: {{error}}',
        scanDone: 'Da scan xong: {{passed}}/{{total}} rule PASS',
        scanFailed: 'Scan that bai',
        scanFailedWithError: 'Scan that bai: {{error}}',
      },
      report: {
        summary: '{{status}} | {{passed}}/{{total}} PASS',
        fileLabel: 'File JSON: {{path}}',
        modeQuick: 'Nhanh',
        modeFull: 'Day du',
        na: 'N/A',
      },
      table: {
        result: 'Ket qua',
        totalRules: '{{from}}-{{to}} / {{total}} rules',
      },
      language: {
        label: 'Ngon ngu',
        vi: 'VI',
        en: 'EN',
      },
    },
  },
}

const initialLanguage = localStorage.getItem(LANGUAGE_STORAGE_KEY)
const fallbackLanguage = initialLanguage === 'vi' || initialLanguage === 'en' ? initialLanguage : 'vi'

i18n.use(initReactI18next).init({
  resources,
  lng: fallbackLanguage,
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false,
  },
})

i18n.on('languageChanged', (language) => {
  localStorage.setItem(LANGUAGE_STORAGE_KEY, language)
})

export default i18n
