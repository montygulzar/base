# Modules

Every module implements:

```python
async def run(subject: str, ctx: RunContext) -> CollectionResult
```

returning `findings` (evidence with provenance), `entities` (graph nodes) and
`relationships` (typed graph edges). No module ever fabricates data; unconfigured
sources emit `source_unavailable` findings.

| Key | Subject types | Built-in sources | Optional keys |
| --- | --- | --- | --- |
| `domain` | domain, url | DNS, WHOIS, crt.sh, TLS, HTTP | VirusTotal, SecurityTrails |
| `ip` | ip | RDNS, RDAP, bgpview, RIPEstat | Shodan, GreyNoise, AbuseIPDB, IPinfo |
| `email` | email | DNS/MX/SPF/DMARC | HIBP |
| `username` | username | ~50 public platforms | — |
| `company` | company | SEC EDGAR | OpenCorporates |
| `media` | media | ExifTool, Pillow, imagehash | — |
| `documents` | document | PyMuPDF, python-docx, openpyxl | — |
| `cti` | ip, domain, url, document | ThreatFox, NVD, OTX | OTX key |
| `web` | url, domain | HTTP probe, HTML parse, robots, sitemap, security.txt | — |

## Subject types

`domain | ip | email | username | company | url | document | media`

`document` / `media` subjects are local absolute paths created by the upload endpoint.
