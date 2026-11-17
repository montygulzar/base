#!/usr/bin/env python3
"""Headless CLI for base. Authenticates and drives the API.

Usage:
    scripts/base_cli.py login ADMIN@EMAIL PASSWORD  [--url http://localhost:8000]
    scripts/base_cli.py new NAME [--subject type:value] ...
    scripts/base_cli.py run INV_ID [--modules a,b,c]
    scripts/base_cli.py findings INV_ID [--module m] [--source s]
    scripts/base_cli.py ingest INV_ID FILE
    scripts/base_cli.py export INV_ID {json,md,html,pdf,csv,stix,misp,graphml,gexf}
"""
import argparse
import json
import os
import sys
from pathlib import Path
import urllib.request
import urllib.parse

CFG = Path.home() / ".config" / "base" / "cli.json"


def load_cfg() -> dict:
    if CFG.exists():
        return json.loads(CFG.read_text())
    return {}


def save_cfg(cfg: dict):
    CFG.parent.mkdir(parents=True, exist_ok=True)
    CFG.write_text(json.dumps(cfg))


def _req(cfg, method, path, data=None, raw=False):
    url = cfg["url"] + path
    body = None
    headers = {"authorization": f"Bearer {cfg.get('token', '')}"}
    if data is not None:
        if isinstance(data, dict) or isinstance(data, list):
            body = json.dumps(data).encode()
            headers["content-type"] = "application/json"
        else:
            body = data
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw_body = r.read()
            if raw:
                return raw_body, r.headers.get("content-type", "")
            return json.loads(raw_body)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code}: {e.read().decode()[:300]}\n")
        sys.exit(1)


def cmd_login(args):
    body = urllib.parse.urlencode({"username": args.email, "password": args.password}).encode()
    req = urllib.request.Request(args.url + "/api/auth/login", data=body, method="POST",
                                 headers={"content-type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        j = json.loads(r.read())
    save_cfg({"url": args.url, "token": j["access_token"]})
    print("ok")


def cmd_new(args):
    cfg = load_cfg()
    subjects = []
    for s in args.subject or []:
        if ":" not in s:
            continue
        t, v = s.split(":", 1)
        subjects.append({"type": t, "value": v})
    r = _req(cfg, "POST", "/api/investigations",
             {"name": args.name, "description": args.description or "", "subjects": subjects})
    print(r["id"])


def cmd_run(args):
    cfg = load_cfg()
    body = {}
    if args.modules:
        body["modules"] = args.modules.split(",")
    r = _req(cfg, "POST", f"/api/investigations/{args.inv}/run", body)
    print(json.dumps(r, indent=2))


def cmd_findings(args):
    cfg = load_cfg()
    q = []
    if args.module: q.append(f"module={args.module}")
    if args.source: q.append(f"source={args.source}")
    qs = ("?" + "&".join(q)) if q else ""
    r = _req(cfg, "GET", f"/api/investigations/{args.inv}/findings{qs}")
    print(json.dumps(r, indent=2))


def cmd_ingest(args):
    cfg = load_cfg()
    text = Path(args.file).read_text()
    r = _req(cfg, "POST", f"/api/ingest/{args.inv}", {"text": text})
    print(json.dumps(r, indent=2))


def cmd_export(args):
    cfg = load_cfg()
    fmt = args.fmt
    path_map = {
        "json": f"/api/reports/{args.inv}.json",
        "md": f"/api/reports/{args.inv}.md",
        "html": f"/api/reports/{args.inv}.html",
        "pdf": f"/api/reports/{args.inv}.pdf",
        "csv": f"/api/reports/{args.inv}.csv",
        "stix": f"/api/stix/{args.inv}.stix.json",
        "misp": f"/api/misp/{args.inv}.misp.json",
        "graphml": f"/api/exports/{args.inv}.graphml",
        "gexf": f"/api/exports/{args.inv}.gexf",
    }
    if fmt not in path_map:
        print("unknown format", file=sys.stderr); sys.exit(2)
    body, ct = _req(cfg, "GET", path_map[fmt], raw=True)
    sys.stdout.buffer.write(body)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("login"); s.add_argument("email"); s.add_argument("password")
    s.add_argument("--url", default=os.environ.get("BASE_URL", "http://localhost:8000"))
    s.set_defaults(fn=cmd_login)
    s = sub.add_parser("new"); s.add_argument("name"); s.add_argument("--description", default="")
    s.add_argument("--subject", action="append"); s.set_defaults(fn=cmd_new)
    s = sub.add_parser("run"); s.add_argument("inv"); s.add_argument("--modules")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("findings"); s.add_argument("inv"); s.add_argument("--module")
    s.add_argument("--source"); s.set_defaults(fn=cmd_findings)
    s = sub.add_parser("ingest"); s.add_argument("inv"); s.add_argument("file")
    s.set_defaults(fn=cmd_ingest)
    s = sub.add_parser("export"); s.add_argument("inv")
    s.add_argument("fmt", choices=["json", "md", "html", "pdf", "csv", "stix", "misp", "graphml", "gexf"])
    s.set_defaults(fn=cmd_export)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
