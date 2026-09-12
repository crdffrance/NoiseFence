import type { Metadata } from 'next';
import './globals.css';
import './console.css';
import './workspace.css';
import './diagnostics.css';
import './interface.css';
import './workspace-refinement.css';

export const metadata: Metadata = {
  title: 'NoiseFence — Console de messagerie',
  description:
    'Console privée NoiseFence : décisions du filtre et corrections.',
  robots: { index: false, follow: false },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
