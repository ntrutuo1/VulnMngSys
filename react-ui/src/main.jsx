import React from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider } from 'antd'
import App from './App'
import './i18n'
import './styles.css'
import 'antd/dist/reset.css'

const theme = {
  token: {
    colorPrimary: '#0f766e',
    colorSuccess: '#16a34a',
    colorWarning: '#d97706',
    colorError: '#dc2626',
    borderRadius: 8,
    borderRadiusLG: 8,
    borderRadiusSM: 6,
    fontSize: 14,
    fontSizeLG: 15,
    fontSizeSM: 13,
    fontFamily: '"Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif',
    lineHeight: 1.6,
    controlHeight: 36,
    controlHeightLG: 42,
    controlHeightSM: 28,
    paddingContentHorizontal: 16,
    paddingContentVertical: 10,
  },
  components: {
    Table: {
      fontSize: 13,
      cellPaddingBlock: 10,
      cellPaddingInline: 12,
      headerBg: '#f8fafc',
      rowHoverBg: '#f8fafc',
    },
    Card: {
      paddingLG: 20,
      headerFontSize: 15,
      headerFontSizeSM: 13,
      boxShadow: 'none',
    },
    Button: {
      fontWeight: 500,
    },
    Tag: {
      fontSize: 12,
    },
    Badge: {
      fontSize: 12,
    },
  },
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ConfigProvider theme={theme}>
      <App />
    </ConfigProvider>
  </React.StrictMode>
)
