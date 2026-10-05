import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './layout/Layout'
import Dashboard from './pages/Dashboard'
import USBForensics from './pages/USBForensics'
import FileMonitoring from './pages/FileMonitoring'
import NetworkAnalysis from './pages/NetworkAnalysis'
import Incidents from './pages/Incidents'
import Reports from './pages/Reports'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="usb" element={<USBForensics />} />
        <Route path="files" element={<FileMonitoring />} />
        <Route path="network" element={<NetworkAnalysis />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="reports" element={<Reports />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
