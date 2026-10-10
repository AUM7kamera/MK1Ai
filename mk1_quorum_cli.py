"""Create individual quorum signatures and combine them for target verification."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from mk1_quorum import (
    QuorumError,
    _read_bounded_file,
    combine_approval_records,
    create_approval_record_from_files,
)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    approve = commands.add_parser("approve")
    approve.add_argument("--signer-id", required=True)
    approve.add_argument("--release-challenge", required=True, type=Path)
    approve.add_argument("--private-key", required=True, type=Path)
    combine = commands.add_parser("combine")
    combine.add_argument(
        "--record",
        required=True,
        action="append",
        type=Path,
    )
    args = parser.parse_args()

    try:
        if args.command == "approve":
            result = create_approval_record_from_files(
                args.signer_id,
                args.release_challenge,
                args.private_key,
            )
        else:
            records = [
                _read_bounded_file(path, maximum_bytes=2048)
                for path in args.record
            ]
            result = combine_approval_records(records)
        os.write(1, result + b"\n")
    except (OSError, QuorumError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
