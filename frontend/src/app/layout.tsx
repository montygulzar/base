import "../styles/globals.css";
import type { Metadata } from "next";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import Dramatist from "@/components/Dramatist";

export const metadata: Metadata = { title: "base — osint platform", description: "modular osint investigation platform" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-bg text-ink">
        <div className="flex min-h-screen">
          <Sidebar />
          <div className="flex-1 flex flex-col">
            <TopBar />
            <main className="flex-1 p-6 overflow-auto scroll-thin">{children}</main>
          </div>
          <Dramatist />
        </div>
      </body>
    </html>
  );
}
