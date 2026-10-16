import subprocess
import os
import sys
import argparse
import re
import struct

# ==============================================================================
# ESP32 OTA Package Header Format (21 bytes, Little Endian)
# ==============================================================================
# Structure Mapping:
#   <       : Little Endian
#   6s      : Magic ("OTAPKG", 6-byte ASCII literal)
#   B       : Framework ID (uint8, 0 for ESP-IDF)
#   B       : Header Version (uint8, set to 1)
#   B       : Version Major (uint8)
#   B       : Version Minor (uint8)
#   H       : Version Patch (uint16)
#   I       : Length of Binary Data (uint32)
#   I       : Length of Signature Data (uint32)
#   B       : Secure Boot Version (uint8)
# ==============================================================================
HEADER_FORMAT = '<6sBBBBHIIB'  
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
NAMESPACE = "ota-update"

MAGIC_STRING = b"OTAPKG"
FRAMEWORK_ESP_IDF = 0
HEADER_VERSION = 1


def parse_version(version_str):
    """Safely split and parse semantic-ish version strings (e.g., '1.2.3', 'v2.0-dirty')."""
    clean_str = version_str.lstrip('vV')
    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', clean_str)
    
    major, minor, patch = 0, 0, 0
    if match:
        major = int(match.group(1)) if match.group(1) else 0
        minor = int(match.group(2)) if match.group(2) else 0
        patch = int(match.group(3)) if match.group(3) else 0
        
    return major, minor, patch


def sign_and_package(signing_key, input_file, output_file, sb_version, version_str):
    """Sign a binary file and package it into the updated OTA format."""
    # 1. Parse project semantic version fields
    major, minor, patch = parse_version(version_str)

    # 2. Generate the signature (OpenSSH format)
    sig_file = input_file + ".sig"
    cmd = ["ssh-keygen", "-Y", "sign", "-f", signing_key, "-n", NAMESPACE, input_file]

    # This triggers the YubiKey PIN/Touch request
    subprocess.run(cmd, check=True)

    # 3. Read binary and signature data
    with open(input_file, 'rb') as f_bin, open(sig_file, 'rb') as f_sig:
        bin_data = f_bin.read()
        sig_data = f_sig.read()

    # 4. Package into updated 21-byte header layout
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC_STRING,
        FRAMEWORK_ESP_IDF,
        HEADER_VERSION,
        major,
        minor,
        patch,
        len(bin_data),
        len(sig_data),
        sb_version
    )
    
    ota_package = header + bin_data + sig_data
    with open(output_file, 'wb') as f_out:
        f_out.write(ota_package)

    os.remove(sig_file)
    print(f"Success! {output_file} is ready for upload.")
    print(f"-> Version parsed: {major}.{minor}.{patch}")
    print(f"-> Secure Boot Version field: {sb_version}")


def main():
    parser = argparse.ArgumentParser(
        description="Sign and package an OTA update binary with an ED25519 key"
    )
    parser.add_argument(
        "signing_key",
        help="Path to the ED25519 signing key (private key)"
    )
    parser.add_argument(
        "input_file",
        help="Path to the input binary file to sign"
    )
    parser.add_argument(
        "output_file",
        help="Path to the output signed and packaged file"
    )
    parser.add_argument(
        "sb_version",
        type=int,
        help="Secure boot version (1: V1, 2: V2, 0: Disabled)"
    )
    parser.add_argument(
        "project_ver",
        help="Raw project version string from the ESP-IDF build environment"
    )
    args = parser.parse_args()

    # Resolve paths to safely handle home directory (~) and relative paths (./)
    signing_key = os.path.abspath(os.path.expanduser(args.signing_key))
    input_file = os.path.abspath(os.path.expanduser(args.input_file))
    output_file = os.path.abspath(os.path.expanduser(args.output_file))
    sb_version = args.sb_version
    project_ver = args.project_ver

    # Validate arguments
    errors = []

    # Check if signing_key exists
    if not os.path.isfile(signing_key):
        errors.append(f"Error: Signing key '{args.signing_key}' does not exist (Resolved: '{signing_key}')")

    # Check if input_file exists
    if not os.path.isfile(input_file):
        errors.append(f"Error: Input file '{args.input_file}' does not exist (Resolved: '{input_file}')")

    # Check if output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.isdir(output_dir):
        errors.append(f"Error: Output directory '{os.path.dirname(args.output_file)}' does not exist (Resolved: '{output_dir}')")

    # Report errors if any
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        sys.exit(1)

    # Execute packager
    try:
        sign_and_package(signing_key, input_file, output_file, sb_version, project_ver)
    except subprocess.CalledProcessError as e:
        print(f"Error: ssh-keygen command failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()