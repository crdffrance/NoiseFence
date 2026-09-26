import type { Metadata } from 'next';
import './globals.css';
import './console.css';
import './workspace.css';
import './diagnostics.css';
import './interface.css';
import './workspace-refinement.css';
import './message-search.css';
import './filter-workspace.css';
import './message-analysis.css';

export const metadata: Metadata = {
  title: "NoiseFence — Mail security",
  description:
    "NoiseFence mail security: messages, filtering policies and delivery diagnostics.",
  robots: { index: false, follow: false },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
