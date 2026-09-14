import type { Metadata } from "next";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  weight: ["400", "500", "700"],
});

export const metadata: Metadata = {
  title: "Sentinela",
  description: "Plataforma interna de pentest e bug bounty",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="pt-BR"
      className={`${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-[var(--color-bg)] text-[var(--color-fg)]">
        <div className="crt-vignette" aria-hidden="true" />
        <div className="crt-overlay" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}
