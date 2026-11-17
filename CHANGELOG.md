# Changelog

All notable changes from the initial scaffold to the present day. Each
entry maps to a git commit on `main`.

## Unreleased (current HEAD)

### Module count: 100

### Highlights
- Crypto OSINT: `btc_addr` (mempool.space), `eth_addr` (Blockscout), with
  `btc` and `eth` as first-class subject types.
- Deep CTI: `nvd_cpe` free-form product → CVE walk.
- Shareable investigations, forking, live screenshot gallery, entity
  SVG bar chart, inline findings search.
- Full TAXII 2.1 server mode (each investigation is a collection).
- Prometheus `/metrics` scrape endpoint.
- 40 tests passing. Live-tested against iana.org → 324 merged
  subdomains across 7 passive-DNS sources, 300+ entities.

### Batches (git log, newest first)
25. BTC/ETH blockchain OSINT + NVD CPE
24. Pulsedive, ip-api.com, reverse-NS, fork, JWT tool
23. Progress %, screenshot gallery, honeypot cleanup
22. ASN prefixes, Spamhaus DBL, shareable links
21. GitHub dorks, historic WHOIS, SVG entity chart
20. Cloud provider detection, URL unshortener
19. Azure+GCS buckets, PGP keys, /metrics endpoint
18. CAA, S3 enum, ipapi geo
17. OpenSanctions, Ahmia, HIBP pastes, URL liveness
16. DNSBL, TAXII server mode, API integration tests
15. Blocklists (Tor+Spamhaus+ET+Firehol), Robtex, big README
14. Bluesky, Mastodon, Reddit, OSV, npm/PyPI typosquat
13. Phishing feeds, CrowdSec, DNSSEC+AXFR, CSP analyzer
12. Tranco rank, security.txt, OpenGraph, templates UI
11. CertSpotter, favicon cluster, auto-enrichment
10. Subdomain takeover, secrets scanner, risk scorer
9.  Templates, entity notes, graph traversal, honeypot
8.  EmailRep, Shodan DNS, webhook notifier, stats, CLI
7.  Bug-bounty scope, MITRE ATT&CK, wappalyzer, findings search
6.  Cert pivot, email permute, IOC bulk ingest, diff
5.  Playwright screenshot, Gravatar, SPF/DMARC/DKIM, user mgmt
4.  Typosquat, favicon, port probe, TAXII, abuse.ch, OpenCTI,
    GraphML / GEXF
3.  Shodan InternetDB, FOFA, ZoomEye, GitHub, phone, plugin loader,
    dagre layout
2.  Amass-level passive DNS, STIX, schedules, RBAC, deeper company,
    Alembic
1.  Real end-to-end collection + Maltego-style transforms + MISP export
0.  Initial scaffold: 11 modules, correlation, reports, dashboard
