// Quip catalogue, keyed by finding (source + kind) or entity signals.
// Each trigger has a pool so the same event doesn't say the same thing twice.
// Keep lines short. Keep tone dry. Nothing celebratory about the target.

export type Severity = "whisper" | "notable" | "loud" | "oh_no";

export type Quip = {
  text: string;
  severity: Severity;
};

const pools: Record<string, Quip[]> = {
  // ─── huge chain-back ────────────────────────────────────────────────
  cascade_strong: [
    { text: "well, well, well — the chain closes.", severity: "loud" },
    { text: "that's a lot of rope you've just handed us.", severity: "loud" },
    { text: "two hops, not clever enough.", severity: "loud" },
    { text: "the whole thing links back. tidy.", severity: "loud" },
    { text: "root-proximity is not a drill.", severity: "loud" },
  ],
  cascade_root_locked: [
    { text: "every road leads home.", severity: "oh_no" },
    { text: "you live inside the graph now.", severity: "oh_no" },
    { text: "the receipts are talking to each other.", severity: "oh_no" },
  ],

  // ─── breach / credential dumps ─────────────────────────────────────
  hibp_breaches: [
    { text: "the password from 2014 is still in use. love that.", severity: "notable" },
    { text: "linkedin, adobe, dropbox. a tasting menu.", severity: "notable" },
    { text: "found in {n} breaches. keep it up.", severity: "loud" },
  ],
  hibp_pastes: [
    { text: "pasted somewhere. optimistic of them.", severity: "notable" },
  ],
  intelx_search: [
    { text: "intelx said 'oh, this one'.", severity: "loud" },
    { text: "the stealer logs remember.", severity: "oh_no" },
  ],
  secrets_scan: [
    { text: "AKIA. really. in a pdf.", severity: "loud" },
    { text: "tokens where tokens should not be.", severity: "loud" },
    { text: "a private key is not a loyalty card.", severity: "oh_no" },
  ],

  // ─── exposure ──────────────────────────────────────────────────────
  "nuclei_lite:scan": [
    { text: "they just left /.git/ out on the porch.", severity: "loud" },
    { text: "phpinfo. in {year}. truly.", severity: "notable" },
    { text: "unauthenticated kibana. a classic.", severity: "loud" },
  ],
  open_services: [
    { text: "redis without a password. living dangerously.", severity: "loud" },
    { text: "the docker socket says hello.", severity: "oh_no" },
  ],
  takeover: [
    { text: "a subdomain pointing at nothing. free real estate.", severity: "loud" },
    { text: "dangling CNAME. somebody's getting phished.", severity: "loud" },
  ],

  // ─── reputation / threat ───────────────────────────────────────────
  cisa_kev: [
    { text: "actively exploited. ransomware operators say thanks.", severity: "oh_no" },
    { text: "it's on the KEV. you know what that means.", severity: "oh_no" },
  ],
  urlhaus: [
    { text: "urlhaus knows this address personally.", severity: "loud" },
  ],
  phishing_lexicon: [
    { text: "this host is cosplaying as paypal, badly.", severity: "notable" },
  ],
  abuseipdb: [
    { text: "AbuseIPDB file: thick.", severity: "notable" },
  ],

  // ─── sanctions / darkweb ───────────────────────────────────────────
  opensanctions: [
    { text: "oh no he's in the list.", severity: "oh_no" },
    { text: "sanctions hit. bank's gonna love that.", severity: "oh_no" },
  ],
  ahmia: [
    { text: "ahmia found a mirror. keep walking.", severity: "notable" },
  ],

  // ─── squatting / impersonation ─────────────────────────────────────
  typosquat: [
    { text: "someone is quietly stalking this brand.", severity: "notable" },
  ],
  idn_homograph: [
    { text: "that 'a' isn't an 'a'. you're welcome.", severity: "loud" },
  ],

  // ─── identity ──────────────────────────────────────────────────────
  "username:profile_matches": [
    { text: "the same handle on {n} sites. a trail, not a coincidence.", severity: "notable" },
  ],
  github_user: [
    { text: "their github bio did the work for us.", severity: "notable" },
  ],
  gravatar: [
    { text: "one md5 and a spill of linked accounts.", severity: "notable" },
  ],
  discord_lookup: [
    { text: "snowflake decoded. that account is older than they said.", severity: "notable" },
    { text: "discord profile is not the privacy move they think it is.", severity: "notable" },
  ],

  // ─── crypto ────────────────────────────────────────────────────────
  "mempool:tx": [
    { text: "the blockchain, famously, does not forget.", severity: "notable" },
  ],

  // ─── structural big-finds ──────────────────────────────────────────
  co_hosted: [
    { text: "the whole neighbourhood is on one guy's VPS.", severity: "notable" },
  ],
  mass_subdomain: [
    { text: "{n} subdomains. somebody's been busy.", severity: "notable" },
  ],

  // ─── catch-all ─────────────────────────────────────────────────────
  generic_big: [
    { text: "that's going in the report.", severity: "whisper" },
    { text: "noted. receipts filed.", severity: "whisper" },
  ],
};

export function pickQuip(key: string, vars: Record<string, string | number> = {}): Quip | null {
  const pool = pools[key];
  if (!pool || pool.length === 0) return null;
  const q = pool[Math.floor(Math.random() * pool.length)];
  let text = q.text;
  for (const [k, v] of Object.entries(vars)) text = text.replaceAll("{" + k + "}", String(v));
  text = text.replaceAll("{year}", String(new Date().getFullYear()));
  return { ...q, text };
}

/** Classify a finding into a trigger key + optional template vars. */
export function classify(f: { module: string; source: string; kind: string; data: any }): { key: string; vars: Record<string, any> } | null {
  const d = f.data || {};
  const k = (sub: string) => ({ key: sub, vars: {} as Record<string, any> });

  // reputation-heavy hits
  if (f.source === "hibp" && f.kind === "breaches" && (d.count ?? 0) > 0)
    return { key: "hibp_breaches", vars: { n: d.count } };
  if (f.source === "hibp_pastes" && (d.count ?? 0) > 0) return k("hibp_pastes");
  if (f.source === "intelx" && f.kind === "search" && (d.count ?? 0) > 0) return k("intelx_search");
  if (f.source === "secrets_scan" && f.kind === "summary" && (d.total_hits ?? 0) > 0) return k("secrets_scan");

  if (f.module === "nuclei_lite" && f.kind === "scan" && (d.hits?.length ?? 0) > 0) return { key: "nuclei_lite:scan", vars: {} };
  if (f.source === "open_services" && d.hit) return k("open_services");
  if (f.module === "takeover" && f.kind === "scan" && (d.candidates?.length ?? 0) > 0) return k("takeover");

  if (f.source === "cisa_kev" && (d.hit_count ?? 0) > 0) return k("cisa_kev");
  if (f.source === "urlhaus" && (d.query_status === "ok" || (d.urls?.length ?? 0) > 0)) return k("urlhaus");
  if (f.module === "phishing_lexicon" && (d.verdict || "").includes("brand")) return k("phishing_lexicon");
  if (f.source === "abuseipdb" && ((d?.data?.abuseConfidenceScore ?? 0) >= 50)) return k("abuseipdb");

  if (f.source === "opensanctions" && f.kind === "search" && (d.count ?? 0) > 0) return k("opensanctions");
  if (f.source === "ahmia" && (d.onions_found ?? 0) > 0) return k("ahmia");

  if (f.module === "typosquat" && f.kind === "live" && (d.count ?? 0) > 0) return k("typosquat");
  if (f.module === "idn_homograph" && d.verdict === "suspicious") return k("idn_homograph");

  if (f.source === "sherlock" && (d.hits ?? 0) >= 5)
    return { key: "username:profile_matches", vars: { n: d.hits } };
  if (f.module === "github_user" && f.kind === "profile" && (d.email || d.company || d.blog)) return k("github_user");
  if (f.source === "gravatar" && f.kind === "profile") return k("gravatar");
  if (f.source === "discord_lookup" && f.kind === "user") return k("discord_lookup");

  if (f.source === "mempool" && f.kind === "txs" && (d.count ?? 0) > 0) return { key: "mempool:tx", vars: {} };

  if (f.source === "passive_dns" && f.kind === "merged" && (d.total_unique ?? 0) >= 100)
    return { key: "mass_subdomain", vars: { n: d.total_unique } };

  return null;
}

/** Called for high-proximity cascade promotions. */
export function cascadeQuip(proximity: number): Quip | null {
  if (proximity >= 0.6) return pickQuip("cascade_root_locked");
  if (proximity >= 0.35) return pickQuip("cascade_strong");
  return null;
}
