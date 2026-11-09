#!/usr/bin/env python3
"""
hashfiles.py - Parallel SHA-256 / SHA-512 file hashing.

Usage:
    ./hashfiles.py FILE [FILE ...]
    ./hashfiles.py -j 8 FILE [FILE ...]
    ./hashfiles.py -o hashes.txt FILE [FILE ...]
    ./hashfiles.py --no-sha512 FILE [FILE ...]

Both hashes are calculated concurrently for each file.
Multiple files are processed concurrently.

Output:
    SHA256  <digest>  <filename>
    SHA512  <digest>  <filename>
"""

import argparse
import concurrent.futures
import hashlib
import os
import sys
import threading


CHUNK_SIZE = 1024 * 1024


def hash_file(filename, algorithms):
    """Hash one file using all requested algorithms."""

    hashers = {
        name: hashlib.new(name)
        for name in algorithms
    }

    try:
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                for hasher in hashers.values():
                    hasher.update(chunk)

        return filename, {
            name: hasher.hexdigest()
            for name, hasher in hashers.items()
        }, None

    except OSError as exc:
        return filename, None, str(exc)


def main():
    parser = argparse.ArgumentParser(
        description="Parallel SHA-256 / SHA-512 file hashing."
    )

    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help="Maximum concurrent file workers (default: all CPU cores)."
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Append results to FILE instead of stdout."
    )

    parser.add_argument(
        "--no-sha256",
        action="store_true",
        help="Disable SHA-256."
    )

    parser.add_argument(
        "--no-sha512",
        action="store_true",
        help="Disable SHA-512."
    )

    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Files to hash."
    )

    args = parser.parse_args()

    if args.jobs < 1:
        parser.error("--jobs must be at least 1")

    algorithms = []

    if not args.no_sha256:
        algorithms.append("sha256")

    if not args.no_sha512:
        algorithms.append("sha512")

    if not algorithms:
        parser.error("At least one hashing algorithm must be enabled")

    output = (
        open(args.output, "a", encoding="utf-8")
        if args.output else sys.stdout
    )

    write_lock = threading.Lock()
    errors = 0

    def emit(text):
        """Serialize complete output records."""
        with write_lock:
            output.write(text + "\n")
            output.flush()

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.jobs
        ) as executor:

            futures = [
                executor.submit(hash_file, filename, algorithms)
                for filename in args.files
            ]

            for future in concurrent.futures.as_completed(futures):
                filename, digests, error = future.result()

                if error:
                    errors += 1
                    emit(f"ERROR  {filename}: {error}")
                    continue

                for algorithm in algorithms:
                    emit(
                        f"{algorithm.upper():6s}  "
                        f"{digests[algorithm]}  "
                        f"{filename}"
                    )

    finally:
        if args.output:
            output.close()

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
