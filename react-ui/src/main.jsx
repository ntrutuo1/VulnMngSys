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
    borderRadius: 12,
    fontFamily: 'Segoe UI, -apple-system, BlinkMacSystemFont, sans-serif',
  },
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ConfigProvider theme={theme}>
      <App />
    </ConfigProvider>
  </React.StrictMode>
)
