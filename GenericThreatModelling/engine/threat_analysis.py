#!/usr/bin/env python3
"""Command line entry of the inductive threat analysis.

    python3 threat_analysis.py SETUP.json [-o OUT.json] [--format raw] [--html [REPORT.html]] [--images] [--feedback FILE] [--serve [PORT]]

Reads one setup (JSON, see SetupOntology.schema.json), checks it and the static data, analyses every threat on every
matching entity and writes the raw analysis data. The human-readable format is not implemented yet.

With --serve the report is opened from a small server on this computer (127.0.0.1 only): its "save overrides" button then
writes the overrides into the analysis file next to the setup, runs the analysis again and rewrites the report. Opened
from the file, the page can only download the overrides (see --feedback).
"""
import argparse
import hmac
import http.server
import json
import secrets
import sys
from collections import Counter
from pathlib import Path

import analyze
import feedback
import report


def serve(setup, out, html_path, images, port):
    token = secrets.token_urlsafe(24)
    state = {"html": html_path.read_text(encoding="utf-8")}
    host = f"127.0.0.1:{port}"

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, body, ctype):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def local(self):
            return self.headers.get("Host") in (host, f"localhost:{port}")

        def do_GET(self):
            if self.path.split("?")[0] not in ("/", "/index.html") or not self.local():
                return self.reply(404, "not found", "text/plain")
            page = state["html"].replace("<!--SERVE-->", f"<script>window.SERVE = {{ token: {json.dumps(token)}, file: {json.dumps(out.name)} }};</script>")
            self.reply(200, page, "text/html")

        def do_POST(self):
            if self.path != "/save" or not self.local():
                return self.reply(404, "not found", "text/plain")
            if not hmac.compare_digest(self.headers.get("X-Token", ""), token):
                return self.reply(403, json.dumps({"errors": ["wrong token: open the report from the address the tool printed"]}), "application/json")
            length = int(self.headers.get("Content-Length") or 0)
            if length > 2_000_000:
                return self.reply(413, json.dumps({"errors": ["too much data"]}), "application/json")
            try:
                items = json.loads(self.rfile.read(length)).get("overrides", [])
            except (ValueError, AttributeError):
                return self.reply(400, json.dumps({"errors": ["no valid JSON"]}), "application/json")
            given = {"overrides": [feedback.clean(o) for o in items]}
            result = analyze.analyze(setup, given=given)
            if result.get("errors"):
                return self.reply(400, json.dumps({"errors": result["errors"]}), "application/json")
            analyze.write_raw(result, out)
            report.write_html(result, setup, html_path, images=images)
            state["html"] = html_path.read_text(encoding="utf-8")
            print(f"{len(given['overrides'])} overrides saved to {out}", file=sys.stderr)
            self.reply(200, json.dumps({"ok": True, "overrides": len(given["overrides"]), "file": out.name}), "application/json")

    with http.server.HTTPServer(("127.0.0.1", port), Handler) as server:
        print(f"report at http://{host}/ (stop with Ctrl+C)", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("setup", help="setup JSON")
    ap.add_argument("-o", "--output", help="output file (default: next to the setup, *.analysis.json)")
    ap.add_argument("--format", choices=["raw", "human"], default="raw")
    ap.add_argument("--html", nargs="?", const="", metavar="FILE", help="also write the interactive report (default: next to the setup, *.report.html)")
    ap.add_argument("--check-only", action="store_true", help="validate setup and static data, then stop")
    ap.add_argument("--feedback", metavar="FILE", help="overrides exported from the report (or taken from another analysis file); merged into those that the output file already holds and kept in the new one")
    ap.add_argument("--images", action="store_true", help="show pictures of the signing devices in the report; they come with a licence that requires an attribution, which the report then shows")
    ap.add_argument("--serve", nargs="?", const=8765, type=int, metavar="PORT", help="after writing, serve the report on 127.0.0.1 (default port 8765) so that its \"save overrides\" button can write the overrides into the analysis file; needs --html")
    args = ap.parse_args(argv)
    if args.serve is not None and args.html is None:
        ap.error("--serve needs --html")
    if args.format == "human":
        print("The human-readable output is not implemented yet; use --format raw.", file=sys.stderr)
        return 2
    setup = Path(args.setup)
    out = Path(args.output) if args.output else setup.with_name(setup.stem + ".analysis.json")

    given = feedback.read(out)
    if args.feedback:
        given = feedback.merge(given, feedback.read(args.feedback))
    result = analyze.analyze(setup, check_only=args.check_only, given=given,
                             progress=lambda n, total: print(f"\r{n}/{total} threat instances", end="", file=sys.stderr))
    print(file=sys.stderr)
    if result.get("errors"):
        for e in result["errors"]:
            print("ERROR", e, file=sys.stderr)
        return 1
    for w in result["warnings"]:
        print("WARNING", w, file=sys.stderr)
    if args.check_only:
        print("setup and static data are valid", file=sys.stderr)
        return 0
    analyze.write_raw(result, out)
    if args.html is not None:
        html = Path(args.html) if args.html else setup.with_name(setup.stem + ".report.html")
        report.write_html(result, setup, html, images=args.images)
        print(f"report written to {html}", file=sys.stderr)
    else:
        html = None
    risks = Counter(r["R"] for r in result["rows"])
    print(f"{len(result['rows'])} rows written to {out}", file=sys.stderr)
    print("risk 4..0: " + ", ".join(f"{k}: {risks.get(k, 0)}" for k in (4, 3, 2, 1, 0)), file=sys.stderr)
    print(f"{len(result['asks'])} questions for the owner, {len(result['warnings'])} warnings", file=sys.stderr)
    if args.serve is not None:
        serve(setup, out, html, args.images, args.serve)
    return 0


if __name__ == "__main__":
    sys.exit(main())
