import boto3
import os
import json
import tempfile
import threading
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from tqdm import tqdm

# Optional compression support
try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False

# ===================================================
# Configuration & Environment Variables
# ===================================================
load_dotenv("keys.env")

AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
BUCKET_NAME    = os.environ.get("BUCKET_NAME")
REGION         = os.environ.get("REGION")

S3_KEY         = os.environ.get("S3_KEY")
OUTPUT_DIR     = os.environ.get("OUTPUT_DIR", "decrypted")

RESTORE_TIMESTAMP = os.environ.get("RESTORE_TIMESTAMP")
MANIFEST_KEY      = os.environ.get("MANIFEST_KEY")
MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "12")))
MAX_RETRIES = max(0, int(os.environ.get("MAX_RETRIES", "3")))
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks

if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
    raise ValueError("❌ Missing AWS credentials! Check your keys.env file.")
if not BUCKET_NAME or not REGION:
    raise ValueError("❌ Missing BUCKET_NAME or REGION in keys.env file!")


s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION,
    config=boto3.session.Config(
        signature_version='s3v4',
        s3={'addressing_style': 'virtual'}
    )
)

with open("encryption_key.key", "rb") as f:
    key = f.read()
if len(key) != 32:
    raise ValueError("❌ encryption_key.key must be exactly 32 bytes (AES-256 key).")

console_lock = threading.Lock()


# Module-Level Helpers
class HashWriter:
    """Wraps a file object to calculate SHA256 on the fly without loading into RAM."""
    def __init__(self, file_obj, hasher):
        self.file_obj = file_obj
        self.hasher = hasher

    def write(self, data):
        self.hasher.update(data)
        self.file_obj.write(data)

    def flush(self):
        self.file_obj.flush()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# Core Processing Logic
def process_s3_file(s3_key: str, output_path: str, expected_sha256: str = None) -> str:
    """
    Downloads an encrypted file, streams decryption/decompression,
    verifies hash, and writes to disk.
    """
    try:
        with tempfile.TemporaryFile() as f_enc:
            # Download with Retries
            for attempt in range(MAX_RETRIES + 1):
                f_enc.seek(0)
                f_enc.truncate()

                try:
                    s3.download_fileobj(Bucket=BUCKET_NAME, Key=s3_key, Fileobj=f_enc)
                    break
                except Exception as e:
                    if attempt == MAX_RETRIES:
                        raise RuntimeError(f"Download failed after {MAX_RETRIES} retries: {e}") from e
                    wait = 2 ** attempt
                    with console_lock:
                        print(f"⚠️  Download attempt {attempt+1}/{MAX_RETRIES+1} failed for {s3_key} — retrying in {wait}s...")
                    time.sleep(wait)

            f_enc.seek(0, 2)
            enc_size = f_enc.tell()
            f_enc.seek(0)

            nonce = f_enc.read(12)
            comp_flag_byte = f_enc.read(1)
            if len(nonce) != 12 or len(comp_flag_byte) != 1:
                raise ValueError("Invalid file format: missing header")

            is_compressed = comp_flag_byte == b'\x01'
            if is_compressed and not ZSTD_AVAILABLE:
                raise RuntimeError("File is compressed but 'zstandard' library is not installed.")


            if enc_size < 29:  # 13 byte header + 16 byte tag minimum
                raise ValueError("Invalid file format: file too short")

            f_enc.seek(-16, 2)  # Go to 16 bytes before the end
            tag = f_enc.read(16)
            f_enc.seek(13)      # Go to start of ciphertext

            ct_remaining = enc_size - 29  # Total size minus header and tag

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            parent = os.path.dirname(output_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

            with open(output_path, "wb") as f_out:
                hasher = hashlib.sha256() if expected_sha256 else None
                base_writer = HashWriter(f_out, hasher) if hasher else f_out

                if is_compressed:
                    dctx = zstd.ZstdDecompressor()
                    target_writer = dctx.stream_writer(base_writer)
                else:
                    target_writer = base_writer

                with target_writer:
                    while ct_remaining > 0:
                        to_read = min(CHUNK_SIZE, ct_remaining)
                        chunk = f_enc.read(to_read)
                        if not chunk:
                            break

                        decrypted_chunk = decryptor.update(chunk)
                        target_writer.write(decrypted_chunk)
                        ct_remaining -= len(chunk)

                    try:
                        decryptor.finalize()
                    except InvalidTag as e:
                        if os.path.exists(output_path):
                            os.remove(output_path)
                        raise ValueError("Security Warning: GCM authentication tag mismatch! File may be tampered with or corrupted.") from e

            if hasher and expected_sha256:
                actual_hash = hasher.hexdigest()
                if actual_hash != expected_sha256:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    raise ValueError(f"Integrity check failed! Expected {expected_sha256}, got {actual_hash}")

            return output_path

    except Exception as e:
        raise RuntimeError(f"Failed {s3_key}: {e}") from e


# Execution Modes
def _resolve_sha256_for_single_file(s3_key: str) -> str | None:
    """
    Attempts to locate the SHA-256 for s3_key by fetching its parent manifest.

    The backup layout is:  backups/<timestamp>/<relative_path>
    The manifest lives at: backups/<timestamp>/MANIFEST.json

    Returns the hex digest string if found, None otherwise.
    """
    parts = s3_key.split("/")
    if len(parts) < 3 or parts[0] != "backups":
        return None

    manifest_key = "/".join(parts[:2]) + "/MANIFEST.json"

    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=manifest_key)
        manifest = json.loads(response["Body"].read().decode("utf-8"))
    except Exception:
        return None


    relative_path = "/".join(parts[2:])
    entry = manifest.get("files", {}).get(relative_path)
    return entry.get("sha256") if entry else None


def decrypt_single_file():
    if not S3_KEY:
        raise ValueError("❌ S3_KEY must be set in keys.env to use single file mode.")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = os.path.basename(S3_KEY)
    output_path = os.path.join(OUTPUT_DIR, filename)

    print(f"🔓 Single file mode: {S3_KEY}")

    # --- FIX: resolve SHA-256 from the parent manifest when possible ---
    expected_sha256 = _resolve_sha256_for_single_file(S3_KEY)

    if expected_sha256:
        print(f"🔍 SHA-256 found in manifest — integrity check will run after decryption.")
    else:
        print(f"⚠️  No SHA-256 available for this file (manifest not found or key not in it). "
              f"Integrity check will be SKIPPED. GCM authentication will still run.")
    # -------------------------------------------------------------------

    result = process_s3_file(S3_KEY, output_path, expected_sha256)
    print(f"✅ Decrypted and saved as: {result}")


def restore_folder():
    if MANIFEST_KEY:
        manifest_key = MANIFEST_KEY
    elif RESTORE_TIMESTAMP:
        manifest_key = f"backups/{RESTORE_TIMESTAMP}/MANIFEST.json"
    else:
        raise ValueError("❌ Set either RESTORE_TIMESTAMP or MANIFEST_KEY in keys.env")

    print(f"📋 Loading manifest: {manifest_key}")
    response = s3.get_object(Bucket=BUCKET_NAME, Key=manifest_key)
    manifest = json.loads(response['Body'].read().decode('utf-8'))

    backup_timestamp = manifest["backup_timestamp"]
    restore_base = os.path.join("restored", backup_timestamp)
    os.makedirs(restore_base, exist_ok=True)

    print(f"🚀 Restoring backup from {backup_timestamp} → ./{restore_base}/ (using {MAX_WORKERS} workers)\n")

    files_to_restore = []
    for relative_path, info in manifest["files"].items():
        s3_key = info["s3_key"]
        expected_sha256 = info.get("sha256")
        output_path = os.path.join(restore_base, relative_path)

        # Path traversal security check
        if not os.path.abspath(output_path).startswith(os.path.abspath(restore_base)):
            raise ValueError(f"Unsafe path in manifest: {relative_path}")

        files_to_restore.append((s3_key, output_path, relative_path, expected_sha256))

    success = []
    failed = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_info = {
            executor.submit(process_s3_file, s3_key, out_path, sha): rel
            for s3_key, out_path, rel, sha in files_to_restore
        }

        with tqdm(total=len(files_to_restore), desc="Files restored", unit="file", leave=True) as pbar:
            for future in as_completed(future_to_info):
                rel = future_to_info[future]
                try:
                    future.result()
                    success.append(rel)
                except Exception as e:
                    with console_lock:
                        print(f"\n❌ {e}")
                    failed.append(rel)
                pbar.update(1)

    print(f"\n--- Restore Complete ---")
    print(f"✅ Succeeded: {len(success)} files")
    print(f"❌ Failed:    {len(failed)} files")

    if failed:
        print("\nFailed files:")
        for f in failed:
            print(f"   - {f}")

    print(f"\n📁 Restored to: ./{restore_base}/")


if __name__ == "__main__":
    if S3_KEY:
        decrypt_single_file()
    else:
        restore_folder()
