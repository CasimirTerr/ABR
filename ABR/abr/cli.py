"""Command line entry point: `abr scan -m manifest.json -p policy.json`."""

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze
from .iam import load_policies
from .manifest import load_manifest
from .report import RENDERERS


def build_parser():
    parser = argparse.ArgumentParser(
        prog="abr",
        description="ABR (Agent Blast Radius): see what a hijacked AI agent could do in your AWS account.",
    )
    parser.add_argument("--version", action="version", version=f"abr {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyze an agent's tools against its IAM policies")
    scan.add_argument("-m", "--manifest", required=True, help="agent tool manifest (JSON)")
    scan.add_argument("-p", "--policy", required=True, action="append",
                      help="IAM policy JSON attached to the agent's role (repeat for several)")
    scan.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    scan.add_argument("-o", "--output", help="write the report to a file instead of the screen")
    scan.add_argument("--write-policy", metavar="PATH",
                      help="save the suggested least-privilege policy to this file")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none",
                      help="exit with code 1 if any finding is at or above this severity (for CI)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        statements = load_policies(args.policy)
    except (OSError, ValueError) as exc:
        print(f"abr: error: {exc}", file=sys.stderr)
        return 2

    result = analyze(manifest, statements)
    report = RENDERERS[args.format](result, manifest)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    if args.write_policy:
        with open(args.write_policy, "w", encoding="utf-8") as fh:
            json.dump(result.least_privilege_policy, fh, indent=2)
            fh.write("\n")

    return 1 if result.worst_at_or_above(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
