import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";

// Font configuration
const sfProDisplay = localFont({
  src: [
    {
      path: "./fonts/GeistVF.woff",
      weight: "100 900",
      style: "normal",
    }
  ],
  variable: "--font-sf-pro-display",
  display: "swap",
  fallback: ["-apple-system", "BlinkMacSystemFont", "system-ui", "sans-serif"],
});

const sfProText = localFont({
  src: [
    {
      path: "./fonts/GeistMonoVF.woff", 
      weight: "100 900",
      style: "normal",
    }
  ],
  variable: "--font-sf-pro-text",
  display: "swap",
  fallback: ["-apple-system", "BlinkMacSystemFont", "system-ui", "sans-serif"],
});

// Apple-Style Metadata
export const metadata: Metadata = {
  title: {
    default: "DataVault Enterprise | Quantum-Safe Data Platform",
    template: "%s | DataVault Enterprise"
  },
  description: "Enterprise-grade distributed file system with Byzantine Fault Tolerance, quantum-resistant encryption, and 11-layer security architecture.",
  keywords: [
    "enterprise security",
    "quantum encryption", 
    "byzantine fault tolerance",
    "zero trust architecture",
    "distributed file system"
  ],
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#007AFF" },
    { media: "(prefers-color-scheme: dark)", color: "#0056B3" },
  ],
};

// Clean Server Component Layout
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html 
      lang="en" 
      className={`${sfProDisplay.variable} ${sfProText.variable}`}
      suppressHydrationWarning
    >
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="default" />
        <meta name="format-detection" content="telephone=no" />
      </head>
      
      <body className="apple-body antialiased">
        <main className="relative min-h-screen">
          {children}
        </main>
      </body>
    </html>
  );
}
