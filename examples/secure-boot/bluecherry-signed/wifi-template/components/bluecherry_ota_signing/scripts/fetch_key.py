import os
import sys
import shutil
import subprocess
import tempfile

# The name given when generating the key on the Yubikey
key_name = "OTA_update"
# The expected private key file
expected_private_key_file = f"id_ed25519_sk_rk_{key_name}"

def main():
    if len(sys.argv) < 2:
        print("Usage: fetch_key.py <target_key_path>")
        sys.exit(1)
        
    target_path = os.path.abspath(os.path.expanduser(sys.argv[1]))
    target_dir = os.path.dirname(target_path)
    
    print(f"[*] Preparing to safely pull resident key '{key_name}' from your security key...")
    print(f"[*] Target destination: {target_path}")
    
    # Ensure the target destination directory exists (e.g. creating ~/.ssh if missing)
    os.makedirs(target_dir, exist_ok=True)
    
    # Use a pristine temporary directory to isolate ssh-keygen output
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Run the extraction inside the temp directory
            subprocess.run(["ssh-keygen", "-K"], cwd=tmpdir, check=True)
        except subprocess.CalledProcessError:
            print("[!] Error: ssh-keygen -K failed or was aborted.", file=sys.stderr)
            sys.exit(1)
            
        # Discover what files ssh-keygen dropped
        files = os.listdir(tmpdir)
        
        # FIXED: Variable name matched to 'expected_private_key_file' and indentation corrected to spaces
        priv_keys = [f for f in files if f == expected_private_key_file]
        
        # FIXED: More descriptive error handling if the targeted key name isn't on the YubiKey
        if not priv_keys:
            print(f"[!] Error: The resident key profile '{key_name}' was not found on this device.", file=sys.stderr)
            print(f"    Available keys discovered: {[f for f in files if not f.endswith('.pub')]}", file=sys.stderr)
            sys.exit(1)
              
        src_priv = os.path.join(tmpdir, priv_keys[0])
        src_pub = src_priv + ".pub"
        
        dest_priv = target_path
        dest_pub = target_path + ".pub"
        
        # Move and rename the files to perfectly match the target destination
        if os.path.exists(dest_priv):
            os.remove(dest_priv)
        shutil.move(src_priv, dest_priv)
        
        if os.path.exists(src_pub):
            if os.path.exists(dest_pub):
                os.remove(dest_pub)
            shutil.move(src_pub, dest_pub)
            
        # Explicitly apply strict 600 permissions to keep SSH agents happy
        os.chmod(dest_priv, 0o600)
        
        print(f"\n[+] Success! Your targeted YubiKey key handle has been imported:")
        print(f"    -> Private Handle: {dest_priv}")
        print(f"    -> Public Key:     {dest_pub}")

if __name__ == "__main__":
    main()