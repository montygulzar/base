"use client";
import { useState } from "react";
import { login } from "@/lib/api";
import { useRouter } from "next/navigation";

const tagline = [
  "the receipts machine",
  "a very polite search engine",
  "osint, for your very normal reasons",
  "paste something you probably shouldn't have",
  "ok but why are you logged in at 3am",
][Math.floor(Math.random() * 5)];

export default function LoginPage() {
  const [email, setEmail] = useState("admin@base.app");
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
      <form onSubmit={submit} className="card w-[420px] p-7 space-y-4">
        <div>
          <div className="flex items-baseline gap-2">
            <h1 className="text-2xl font-semibold tracking-tight text-ink">base</h1>
            <span className="text-xs text-mute font-mono">v0.1</span>
          </div>
          <div className="text-sm text-mute mt-1">{tagline}</div>
        </div>
        <div className="space-y-2">
          <label className="block">
            <div className="text-xs text-mute mb-1">Email</div>
            <input className="input w-full" value={email} onChange={e => setEmail(e.target.value)} />
          </label>
          <label className="block">
            <div className="text-xs text-mute mb-1">Password</div>
            <input className="input w-full" type="password" value={password} onChange={e => setPassword(e.target.value)} />
          </label>
        </div>
        {err && <div className="text-err text-xs">{err}</div>}
        <button className="btn-primary w-full" type="submit">Sign in</button>
        <div className="text-[10px] text-dim text-center">
          every query is audited. consider that before typing your ex's name.
        </div>
      </form>
    </div>
  );
}
