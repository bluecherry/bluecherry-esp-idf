# @file firmware_fingerprint.py
# @author Arnoud Devoogdt <arnoud@dptechnics.com>
# @brief Print the fingerprint BlueCherry records for an ESP-IDF firmware image.
# @version 1.4.0
# @date 2026-10-16
# @copyright Copyright (c) 2026 DPTechnics BV <info@dptechnics.com>
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Lesser General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""Print the fingerprint BlueCherry records for an ESP-IDF firmware image.

BlueCherry identifies firmware by the SHA-256 that ESP-IDF appends to every app image. It is what
the platform stores when an update is uploaded, and what a device reports for the firmware it runs.

The hash sits right after the image's checksum. An unsigned image ends there, so it is the file's
last 32 bytes. A signed image does not: Secure Boot V2 signing appends a 4 KB signature sector after
the hash, mostly 0xFF. This tool walks the image from its header instead, which finds the hash in
both cases, verifies it against the image, and explains whatever follows it.

Anything that is not a single ESP-IDF app image is rejected: a bootloader, a merged flash image, a
truncated or corrupted file, or data appended after the image that is not a signature sector.

usage: python firmware_fingerprint.py [-q] FIRMWARE.bin [FIRMWARE.bin ...]

  -q   print only the fingerprint (with the file name when given several files), reasons for a
       rejection go to stderr. Exits 1 if any file was rejected.

In a project that uses the library, `idf.py fingerprint` runs this on the project's own image.
"""

import hashlib
import struct
import sys
import zlib

IMAGE_MAGIC = 0xE9
HEADER_LEN = 24  # esp_image_header_t
SEGMENT_HEADER_LEN = 8  # load address, data length
HASH_LEN = 32
APP_DESC_MAGIC = 0xABCD5432  # esp_app_desc_t, at the start of an app's first segment
SECTOR = 4096
SIG_BLOCK_LEN = 1216
SIG_BLOCK_MAGIC = 0xE7
SIG_BLOCK_SCHEMES = {0x02: "RSA", 0x03: "ECDSA"}


class NotAnAppImage(Exception):
    pass


def _cstr(raw):
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


def find_hash(data):
    """Return (offset, digest) of the appended SHA-256, verified against the image."""
    if len(data) < HEADER_LEN or data[0] != IMAGE_MAGIC:
        raise NotAnAppImage("no ESP-IDF image header (0xE9) at offset 0")
    if data[23] != 1:
        raise NotAnAppImage("the image header says no SHA-256 is appended")

    off = HEADER_LEN
    for n in range(data[1]):
        if off + SEGMENT_HEADER_LEN > len(data):
            raise NotAnAppImage(f"segment {n} header runs past the end of the file")
        _, length = struct.unpack_from("<II", data, off)
        off += SEGMENT_HEADER_LEN + length
        if off > len(data):
            raise NotAnAppImage(f"segment {n} runs past the end of the file")

    # One checksum byte, padded so that the image is a multiple of 16 bytes.
    hash_off = (off + 16) & ~15
    digest = data[hash_off:hash_off + HASH_LEN]
    if len(digest) != HASH_LEN:
        raise NotAnAppImage("the file ends before the appended SHA-256")
    if hashlib.sha256(data[:hash_off]).digest() != digest:
        raise NotAnAppImage("the appended SHA-256 does not match the image: corrupt or truncated")
    return hash_off, digest


def describe_trailer(data, end):
    """Explain what follows the hash: nothing, or a Secure Boot V2 signature sector."""
    if end == len(data):
        return "none, the image is unsigned"

    sig_off = -(-end // SECTOR) * SECTOR
    if any(b != 0xFF for b in data[end:sig_off]) or len(data) - sig_off != SECTOR:
        raise NotAnAppImage(f"{len(data) - end} bytes follow the image and are not a signature "
                            "sector: not a single app image (a merged flash image?)")

    image_digest = hashlib.sha256(data[:sig_off]).digest()
    blocks = []
    for i in range(3):
        blk = data[sig_off + i * SIG_BLOCK_LEN:sig_off + (i + 1) * SIG_BLOCK_LEN]
        if blk[0] != SIG_BLOCK_MAGIC:
            break
        scheme = SIG_BLOCK_SCHEMES.get(blk[1], f"version 0x{blk[1]:02x}")
        crc = struct.unpack_from("<I", blk, 1196)[0] == zlib.crc32(blk[:1196]) & 0xFFFFFFFF
        checks = [f"crc {'ok' if crc else 'BAD'}"]
        if blk[1] == 0x02:
            checks.append(f"image digest {'ok' if blk[4:36] == image_digest else 'BAD'}")
        blocks.append(f"{scheme} ({', '.join(checks)})")
    if not blocks:
        raise NotAnAppImage("a 4 KB sector follows the image but holds no signature block")

    padding = f", after {sig_off - end} bytes of 0xFF padding" if sig_off > end else ""
    return (f"Secure Boot V2 signature sector at 0x{sig_off:06x}{padding}: "
            + "; ".join(blocks))


def fingerprint(data):
    """Return the fingerprint of an app image, signed or not, and a description of the image.

    Raises NotAnAppImage for anything that is not a single, intact ESP-IDF app image.
    """
    hash_off, digest = find_hash(data)
    if struct.unpack_from("<I", data, 32)[0] != APP_DESC_MAGIC:
        raise NotAnAppImage("valid image, but not an application: a bootloader, or a merged "
                            "flash image that starts with one")
    trailer = describe_trailer(data, hash_off + HASH_LEN)

    tail = data[-HASH_LEN:]
    report = [
        ("size", f"{len(data)} bytes"),
        ("app", f"'{_cstr(data[80:112])}' version '{_cstr(data[48:80])}', "
                f"ESP-IDF {_cstr(data[144:176])}, {data[1]} segments"),
        ("hash", f"at 0x{hash_off:06x}, matches the image"),
        ("after it", trailer),
        ("tail -c 32", tail.hex()),
        ("fingerprint", digest.hex() + ("" if tail == digest else "   <- differs from the tail")),
    ]
    return digest, report


def main(args):
    quiet = "-q" in args
    paths = [a for a in args if a != "-q"]
    if not paths:
        print(__doc__.split("usage: ", 1)[1].strip(), file=sys.stderr)
        return 2

    failed = False
    for path in paths:
        try:
            with open(path, "rb") as f:
                digest, report = fingerprint(f.read())
        except (NotAnAppImage, OSError) as e:
            failed = True
            if quiet:
                print(f"{path}: {e}", file=sys.stderr)
            else:
                print(f"{path}\n  {'REJECT':<13} {e}")
            continue

        if quiet:
            print(digest.hex() if len(paths) == 1 else f"{digest.hex()}  {path}")
        else:
            print(path)
            for label, text in report:
                print(f"  {label:<13} {text}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
