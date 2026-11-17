"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const items = [
  { href: "/",              label: "dashboard" },
  { href: "/investigations",label: "investigations" },
  { href: "/integrations",  label: "sources" },
  { href: "/modules",       label: "modules" },
  { href: "/scratchpad",    label: "scratchpad" },
  { href: "/analytics",     label: "analytics" },
  { href: "/schedules",     label: "schedules" },
  { href: "/templates",     label: "templates" },
  { href: "/reports",       label: "reports" },
  { href: "/users",         label: "users" },
  { href: "/audit",         label: "audit" },
];

export default function Sidebar() {
  const p = usePathname();
  return (
    <aside className="w-56 border-r border-line bg-panel p-4 flex flex-col">
      <div className="text-acc font-mono font-bold text-lg mb-6 tracking-widest">BASE</div>
      <nav className="flex-1 space-y-1">
        {items.map(it => (
          <Link key={it.href} href={it.href}
            className={clsx("block px-3 py-1.5 rounded font-mono text-sm",
              p === it.href || (it.href !== "/" && p?.startsWith(it.href))
                ? "bg-soft text-acc" : "text-mute hover:text-ink hover:bg-soft")}>
            {it.label}
          </Link>
        ))}
      </nav>
      <div className="text-xs text-mute font-mono pt-4 border-t border-line">v0.1.0</div>
    </aside>
  );
}
