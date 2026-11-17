"use client";
import { useState } from "react";
import { login } from "@/lib/api";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [email, setEmail] = useState("admin@base.local");
  const [password, setPassword] = useState("admin");
  const [err, setErr] = useState("");
  const r = useRouter();
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try { await login(email, password); r.push("/"); }
    catch (ex: any) { setErr(ex.message); }
  }
  return (
    <div className="min-h-screen flex items-center justify-center bg-bg">
      <form onSubmit={submit} className="card w-96 p-6 space-y-4">
        <div className="text-acc font-mono text-xl tracking-widest">BASE</div>
        <div className="text-mute font-mono text-sm">sign in</div>
        <input className="input w-full" value={email} onChange={e => setEmail(e.target.value)} placeholder="email" />
        <input className="input w-full" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="password" />
        {err && <div className="text-err text-sm font-mono">{err}</div>}
        <button className="btn-primary w-full" type="submit">sign in</button>
      </form>
    </div>
  );
}
