import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: '⚠️ VULNERABLE APP - DO NOT DEPLOY',
  description: 'This application intentionally uses vulnerable packages for security testing',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
