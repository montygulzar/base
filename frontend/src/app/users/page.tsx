"use client";
import useSWR from "swr";
import { useState } from "react";
import { api, fetcher } from "@/lib/api";

type U = { id: string; email: string; role: string; created_at: string };

export default function Users() {
  const { data, error, mutate } = useSWR<U[]>("/api/users", fetcher);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  async function create() {
    await api("/api/auth/users", { method: "POST",
      body: JSON.stringify({ email, password, role }) });
    setEmail(""); setPassword(""); mutate();
  }
  async function patch(id: string, p: any) { await api(`/api/users/${id}`, { method: "PATCH", body: JSON.stringify(p) }); mutate(); }
  async function del(id: string) { if (confirm("delete user?")) { await api(`/api/users/${id}`, { method: "DELETE" }); mutate(); } }
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">users</h1>
      {error && <div className="text-err text-sm font-mono">admin only — {error.message}</div>}
      <div className="card p-4 flex gap-2 items-end">
        <input className="input flex-1" placeholder="email" value={email} onChange={e=>setEmail(e.target.value)} />
        <input className="input" type="password" placeholder="password" value={password} onChange={e=>setPassword(e.target.value)} />
        <select className="input" value={role} onChange={e=>setRole(e.target.value)}>
          <option>analyst</option><option>admin</option><option>viewer</option>
        </select>
        <button className="btn-primary" onClick={create} disabled={!email||!password}>create</button>
      </div>
      <div className="card">
        <table className="w-full text-sm font-mono">
          <thead className="text-mute text-left"><tr><th className="p-3">email</th><th>role</th><th>created</th><th></th></tr></thead>
          <tbody>
            {(data ?? []).map(u => (
              <tr key={u.id} className="border-t border-line">
                <td className="p-3">{u.email}</td>
                <td>
                  <select className="input" value={u.role} onChange={e => patch(u.id, { role: e.target.value })}>
                    <option>analyst</option><option>admin</option><option>viewer</option>
                  </select>
                </td>
                <td className="text-mute">{new Date(u.created_at).toLocaleString()}</td>
                <td className="p-3"><button className="btn" onClick={()=>del(u.id)}>delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
