"use client";
import { useEffect, useState } from "react";
import { api, getToken, setToken } from "@/lib/api";
import { useRouter } from "next/navigation";

export default function TopBar() {
  const [email, setEmail] = useState<string | null>(null);
  const router = useRouter();
  useEffect(() => {
    if (!getToken()) { router.push("/login"); return; }
    api<{ email: string }>("/api/auth/me").then(u => setEmail(u.email)).catch(() => router.push("/login"));
  }, [router]);
  return (
    <header className="h-12 border-b border-line bg-panel px-6 flex items-center justify-between">
      <div className="text-sm font-mono text-mute">intelligence platform</div>
      <div className="flex items-center gap-4">
        <span className="text-sm font-mono text-ink">{email}</span>
        <button onClick={() => { setToken(null); router.push("/login"); }} className="btn">logout</button>
      </div>
    </header>
  );
}
