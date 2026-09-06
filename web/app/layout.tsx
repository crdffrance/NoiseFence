import type { Metadata } from 'next';
import './globals.css';
import './console.css';

export const metadata: Metadata = {
  title: 'NoiseFence — Historique et décisions',
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
