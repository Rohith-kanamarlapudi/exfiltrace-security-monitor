import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Navbar from './Navbar'

export default function Layout() {
  const [navOpen, setNavOpen] = useState(false)

  return (
    <div className="min-h-full bg-bg">
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="lg:pl-60">
        <Navbar onMenuClick={() => setNavOpen(true)} />
        <main className="mx-auto max-w-[1500px] p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
