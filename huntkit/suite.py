"""huntkit — detection-engineering kit. One command, many detectors, a rule library, a blocklist."""
from __future__ import annotations
import sys, importlib

SUBS = {'ioc': 'iocextract.cli', 'rep': 'iocrep.cli', 'stix': 'stixgen.cli', 'yara': 'yararun.cli', 'yaragen': 'yaragen.cli', 'sigma': 'sigmacheck.cli', 'elastic': 'elastdetect.cli', 'siem': 'sentrylog.cli', 'attack': 'attackmap.cli', 'rules': 'huntkit.rules_cli', 'block': 'huntkit.block_cli'}
DESC = {'ioc': 'extract & defang IOCs (IPs/domains/hashes/URLs) from any text', 'rep': 'score IOCs against offline reputation / allow-lists', 'stix': 'build STIX 2.1 bundles from observables', 'yara': 'run YARA-style rules over files and directories', 'yaragen': 'generate candidate YARA rules from sample files', 'sigma': 'lint & unit-test Sigma detection rules', 'elastic': 'validate, diff & deploy Elastic detection rules', 'siem': 'single-file SIEM: run Sigma rules over logs, timeline & alert', 'attack': 'map findings to MITRE ATT&CK techniques + coverage', 'rules': 'the bundled detection-rule library — list, search, validate, run', 'block': 'the bundled known-bad blocklist — query, match, and update from live feeds'}

def _run(modpath, args):
    mod = importlib.import_module(modpath)
    try:
        return mod.main(list(args))
    except TypeError:
        old = sys.argv[:]; sys.argv = [modpath] + list(args)
        try: return mod.main()
        finally: sys.argv = old

def _usage():
    print("huntkit — detection-engineering kit\n\nusage: huntkit <module> [args...]\n\nmodules:")
    for k in SUBS: print(f"  {k:<9} {DESC[k]}")
    print("\nrun `huntkit <module> --help` for a module's options.")

def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in SUBS: return _run(SUBS[argv[0]], argv[1:])
    if argv and argv[0] in ("-h", "--help", "help"): _usage(); return 0
    _usage(); return 0

if __name__ == "__main__":
    raise SystemExit(main())
