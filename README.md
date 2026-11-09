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

  
chmod +x hashfiles.py

# Default: all CPU cores, 8 MiB chunks
./hashfiles.py *.bin

# 16 workers, 32 MiB chunks
./hashfiles.py -j 16 --chunk-mib 32 *.bin

# Custom output names
./hashfiles.py \
    -o256 sha256.txt \
    -o512 sha512.txt \
    *.bin

# Start fresh rather than append
./hashfiles.py --truncate *.bin

# Disable filesystem access advice
./hashfiles.py --no-advice *.bin


The utility produces two independent GNU-compatible checksum files, hashes each input only once, and calculates SHA-256 and SHA-512 from the same read buffers.

It also handles GNU's escaped-filename convention for filenames containing backslashes, newlines, or other non-printable characters. Output is appended by default, with separate output destinations and serialized writes.

Implementation notes
1. Output ordering: Records are written in file-completion order. Each file's two records are serialized together under one lock.
2. Append semantics: Output is appended by default. --truncate starts fresh.
3. Filename compatibility: Uses filesystem byte encoding and GNU's backslash/newline escaping convention.
4. Filesystem advice: Sequential and NOREUSE advice are optional and silently omitted where unsupported.
5. Memory: Each worker holds one read buffer. At 32 MiB and 16 workers, nominal read-buffer allocation is 512 MiB.
6. Failure handling: Individual input failures don't stop other workers. Exit status is nonzero if any input fails.
One qualification: the lock prevents competing threads in this process from interleaving records. It does not provide a transactional guarantee across the two separate output files in the event of a process crash or disk failure. For ordinary checksum generation, this is generally sufficient.

