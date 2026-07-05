"""huntkit block — the bundled known-bad blocklist.

Ships a snapshot of C2 / botnet / Tor-exit indicators and refreshes from free, keyless,
redistributable feeds (abuse.ch Feodo Tracker + SSL Blacklist, and the Tor exit list). Match an
IP/indicator against it, or update the local snapshot. Everything cached offline.

    huntkit block match 1.2.3.4        is this indicator on the blocklist?
    huntkit block stats                how many indicators are loaded
    huntkit block list [N]             sample N indicators (default 20)
    huntkit block update               refresh the snapshot from the live feeds
"""
from __future__ import annotations
import argparse
import os
import sys
import urllib.request
from typing import List, Optional, Set

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
BUNDLED = os.path.join(DATA_DIR, "blocklist.txt")
CACHE = os.path.join(os.path.expanduser("~"), ".huntkit", "blocklist.txt")

# free, keyless, redistributable indicator feeds
FEEDS = {
    "feodo_c2": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "sslbl_c2": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "tor_exit": "https://check.torproject.org/torbulkexitlist",
}
_UA = {"User-Agent": "huntkit-blocklist/1.0 (defensive; honors feed TOS)"}


def _parse(text: str) -> Set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        out.add(line.split(",")[0].split()[0])  # first token = the indicator
    return out


def load() -> Set[str]:
    ind: Set[str] = set()
    for f in (BUNDLED, CACHE):
        if os.path.isfile(f):
            try:
                ind |= _parse(open(f, encoding="utf-8", errors="replace").read())
            except Exception:
                pass
    return ind


def update(log=print) -> int:
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    all_ind: Set[str] = set()
    for name, url in FEEDS.items():
        try:
            data = urllib.request.urlopen(urllib.request.Request(url, headers=_UA), timeout=25).read().decode("utf-8", "replace")
            got = _parse(data)
            all_ind |= got
            log(f"  {name}: {len(got)} indicators")
        except Exception as e:
            log(f"  {name}: FETCH FAILED ({e})")
    if all_ind:
        with open(CACHE, "w", encoding="utf-8") as fh:
            fh.write("# huntkit blocklist cache — refreshed from abuse.ch + Tor feeds\n")
            fh.write("\n".join(sorted(all_ind)) + "\n")
        log(f"cached {len(all_ind)} indicators -> {CACHE}")
    return len(all_ind)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="huntkit block", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd")
    pm = sub.add_parser("match"); pm.add_argument("indicator")
    sub.add_parser("stats")
    pl = sub.add_parser("list"); pl.add_argument("n", nargs="?", type=int, default=20)
    sub.add_parser("update")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    cmd = args.cmd or "stats"

    if cmd == "update":
        print("refreshing blocklist from live feeds…")
        n = update()
        print("done." if n else "no indicators fetched (offline?); bundled snapshot still active.")
        return 0

    ind = load()
    if cmd == "match":
        hit = args.indicator.strip() in ind
        print(f"{'BLOCKED' if hit else 'not listed'}: {args.indicator}")
        return 1 if hit else 0
    if cmd == "list":
        for x in sorted(ind)[:args.n]:
            print(f"  {x}")
        return 0
    # stats
    print(f"huntkit blocklist: {len(ind)} indicators loaded")
    print(f"  bundled snapshot: {'present' if os.path.isfile(BUNDLED) else 'none'}")
    print(f"  live cache:       {'present' if os.path.isfile(CACHE) else 'none — run `huntkit block update`'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
