"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const items = [
  { href: "/",               label: "Dashboard" },
  { href: "/investigations", label: "Investigations" },
  { href: "/integrations",   label: "Sources" },
  { href: "/modules",        label: "Modules" },
  { href: "/scratchpad",     label: "Scratchpad",    note: "one-shot" },
  { href: "/analytics",      label: "Analytics" },
  { href: "/schedules",      label: "Schedules" },
  { href: "/templates",      label: "Templates" },
  { href: "/reports",        label: "Reports" },
  { href: "/users",          label: "Users",         admin: true },
  { href: "/audit",          label: "Audit log",     admin: true },
  { href: "/settings",       label: "Settings",      admin: true },
];

// pick a quip at random on mount so it feels a bit off-kilter
const quips = [
  "please investigate responsibly",
  "all paths lead to a .env file",
  "shodan knows what you did",
  "mind the robots.txt",
  "ask forgiveness, document everything",
  "one dork from disaster",
];

export default function Sidebar() {
  const p = usePathname();
  const quip = quips[Math.floor(Math.random() * quips.length)];
  return (
    <aside className="w-56 border-r border-line bg-panel flex flex-col">
      <div className="px-4 py-4 border-b border-line">
        <div className="flex items-baseline gap-2">
          <div className="font-semibold text-ink text-lg tracking-tight">base</div>
          <div className="text-xs text-mute font-mono">v0.1</div>
        </div>
        <div className="text-[11px] text-mute mt-0.5">intelligence, assembled</div>
      </div>
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto scroll-thin">
        {items.map(it => {
          const active = p === it.href || (it.href !== "/" && p?.startsWith(it.href));
          return (
            <Link key={it.href} href={it.href}
              className={clsx(
                "flex items-center justify-between px-2.5 py-1.5 text-sm transition-colors rounded",
                active ? "bg-soft text-ink" : "text-mute hover:text-ink hover:bg-soft"
              )}>
              <span className="flex items-center gap-2">
                {active && <span className="w-0.5 h-3 bg-acc rounded" />}
                <span className={active ? "" : "pl-[10px]"}>{it.label}</span>
              </span>
              {it.admin && <span className="text-[9px] uppercase tracking-wider text-dim">admin</span>}
              {it.note && <span className="text-[9px] uppercase tracking-wider text-dim">{it.note}</span>}
            </Link>
          );
        })}
      </nav>
      <div className="px-4 py-3 border-t border-line text-[11px] text-dim italic leading-snug">
        “{quip}”
      </div>
    </aside>
  );
}
