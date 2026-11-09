#!/usr/bin/env python3
"""
hashfiles.py

Parallel GNU-compatible SHA-256 and SHA-512 checksum generator.

Features:
  - SHA-256 and SHA-512 calculated together from one file read.
  - Multiple files processed concurrently.
  - Default worker count: all available CPU cores.
  - Separate GNU-compatible output files.
  - GNU filename escaping for backslashes and newlines.
  - Thread-safe output serialization.
  - Append by default; optional truncation.
  - Optional Linux POSIX_FADV_SEQUENTIAL / NOREUSE advice.
  - Configurable read buffer size.

Usage:
  ./hashfiles.py FILE [FILE ...]
  ./hashfiles.py -j 16 FILE [FILE ...]
  ./hashfiles.py -o256 SHA256SUMS -o512 SHA512SUMS FILES...
  ./hashfiles.py --chunk-mib 32 FILES...
  ./hashfiles.py --truncate FILES...
"""

import argparse
import concurrent.futures
import hashlib
import os
import sys
import threading


DEFAULT_CHUNK_MIB = 8


def hash_file(filename, chunk_size, advise):
    """Calculate both hashes using a single sequential file read."""

    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    try:
        with open(filename, "rb") as f:

            if advise and hasattr(os, "posix_fadvise"):

                if hasattr(os, "POSIX_FADV_SEQUENTIAL"):
                    os.posix_fadvise(
                        f.fileno(), 0, 0,
                        os.POSIX_FADV_SEQUENTIAL
                    )

                if hasattr(os, "POSIX_FADV_NOREUSE"):
                    os.posix_fadvise(
                        f.fileno(), 0, 0,
                        os.POSIX_FADV_NOREUSE
                    )

            while True:
                chunk = f.read(chunk_size)

                if not chunk:
                    break

                sha256.update(chunk)
                sha512.update(chunk)

        return (
            filename,
            sha256.digest(),
            sha512.digest(),
            None
        )

    except OSError as exc:
        return filename, None, None, str(exc)


def checksum_line(digest, filename):
    """
    Produce a GNU sha256sum/sha512sum compatible binary-mode record.

    GNU escaping convention:
      - Prefix entire line with backslash if filename contains
        a backslash or newline.
      - Escape backslashes as double backslashes.
      - Escape newlines as backslash-n.

    Filename is encoded using filesystem encoding, preserving
    arbitrary filesystem filename bytes on Unix.
    """

    name = os.fsencode(filename)

    escaped = b"\\" in name or b"\n" in name

    if escaped:
        name = (
            name
            .replace(b"\\", b"\\\\")
            .replace(b"\n", b"\\n")
        )

    prefix = b"\\" if escaped else b""

    return (
        prefix
        + digest.hex().encode("ascii")
        + b" *"
        + name
        + b"\n"
    )


def same_file(path1, path2):
    """Check whether two paths refer to the same filesystem object."""

    if os.path.abspath(path1) == os.path.abspath(path2):
        return True

    try:
        return os.path.samefile(path1, path2)
    except (OSError, ValueError):
        return (
            os.path.realpath(path1)
            == os.path.realpath(path2)
        )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Parallel GNU-compatible SHA-256/SHA-512 "
            "checksum generator."
        )
    )

    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help="Maximum concurrent file workers (default: all CPU cores)."
    )

    parser.add_argument(
        "-o256", "--output256",
        default="SHA256SUMS",
        metavar="FILE",
        help="SHA-256 output file (default: SHA256SUMS)."
    )

    parser.add_argument(
        "-o512", "--output512",
        default="SHA512SUMS",
        metavar="FILE",
        help="SHA-512 output file (default: SHA512SUMS)."
    )

    parser.add_argument(
        "--chunk-mib",
        type=int,
        default=DEFAULT_CHUNK_MIB,
        metavar="N",
        help="Read buffer size in MiB (default: 8)."
    )

    parser.add_argument(
        "--truncate",
        action="store_true",
        help="Truncate output files instead of appending."
    )

    parser.add_argument(
        "--no-advice",
        action="store_true",
        help="Disable Linux sequential/NOREUSE filesystem advice."
    )

    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Input files to hash."
    )

    args = parser.parse_args()

    if args.jobs < 1:
        parser.error("--jobs must be at least 1")

    if args.chunk_mib < 1:
        parser.error("--chunk-mib must be at least 1")

    chunk_size = args.chunk_mib * 1024 * 1024

    out256 = args.output256
    out512 = args.output512

    # Prevent output files from overwriting each other.
    if same_file(out256, out512):
        parser.error("SHA-256 and SHA-512 output files must differ")

    # Prevent output files from also being input files.
    for output_path in (out256, out512):
        for filename in args.files:
            if same_file(output_path, filename):
                parser.error(
                    f"Output file is also an input file: {filename}"
                )

    # Binary streams preserve arbitrary filesystem filename bytes.
    mode = "wb" if args.truncate else "ab"

    try:
        sha256_out = open(out256, mode)
        try:
            sha512_out = open(out512, mode)
        except OSError:
            sha256_out.close()
            raise

    except OSError as exc:
        parser.error(f"Cannot open output file: {exc}")

    write_lock = threading.Lock()
    errors = 0

    try:

        with sha256_out, sha512_out:

            def write_result(filename, digest256, digest512):
                """Serialize a completed file's two checksum records."""

                line256 = checksum_line(digest256, filename)
                line512 = checksum_line(digest512, filename)

                with write_lock:
                    sha256_out.write(line256)
                    sha512_out.write(line512)

                    sha256_out.flush()
                    sha512_out.flush()

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.jobs
            ) as executor:

                futures = [
                    executor.submit(
                        hash_file,
                        filename,
                        chunk_size,
                        not args.no_advice
                    )
                    for filename in args.files
                ]

                for future in concurrent.futures.as_completed(futures):

                    filename, digest256, digest512, error = (
                        future.result()
                    )

                    if error:
                        errors += 1
                        print(
                            f"ERROR: {filename}: {error}",
                            file=sys.stderr
                        )
                        continue

                    write_result(
                        filename,
                        digest256,
                        digest512
                    )

                    print(
                        f"OK: {filename}",
                        file=sys.stderr
                    )

    except OSError as exc:
        print(f"OUTPUT ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"Completed: {len(args.files) - errors} successful, "
        f"{errors} failed.",
        file=sys.stderr
    )

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
