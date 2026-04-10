import boto3
import os
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from tqdm import tqdm
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

if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
    raise ValueError("❌ Missing AWS credentials! Check your keys.env file.")
if not BUCKET_NAME or not REGION:
    raise ValueError("❌ Missing BUCKET_NAME or REGION in keys.env file!")
# ===================================================
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


def decrypt_single_file(s3_key: str):
    print(f"📥 Downloading & decrypting: {s3_key}")
    try:
        with tempfile.TemporaryFile() as f_enc:
            s3.download_fileobj(Bucket=BUCKET_NAME, Key=s3_key, Fileobj=f_enc)
            f_enc.seek(0)

            nonce = f_enc.read(12)
            if len(nonce) != 12:
                raise ValueError("Invalid file format: missing or corrupted nonce")

            ct_tag = f_enc.read()
            if len(ct_tag) < 16:
                raise ValueError("Invalid file format: file too short (missing tag)")

            ciphertext = ct_tag[:-16]
            tag = ct_tag[-16:]

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            os.makedirs(OUTPUT_DIR, exist_ok=True)
            output_path = os.path.join(OUTPUT_DIR, os.path.basename(s3_key))

            with open(output_path, "wb") as f_out:
                f_out.write(decrypted_data)

            print(f"✅ Decrypted and saved as: {output_path}")
    except Exception as e:
        print(f"❌ Failed to decrypt {s3_key}: {e}")
        raise


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
        original_size = info.get("original_size_bytes")
        output_path = os.path.join(restore_base, relative_path)

        if not os.path.abspath(output_path).startswith(os.path.abspath(restore_base)):
            raise ValueError(f"Unsafe path in manifest: {relative_path}")

        files_to_restore.append((s3_key, output_path, relative_path, original_size))

    success = []
    failed = []

    def restore_one(s3_key: str, output_path: str, relative_path: str, original_size):
        size_str = f" ({original_size:,} bytes)" if original_size else ""

        print(f"⬇️  Downloading{size_str}: {relative_path}")

        try:
            with tempfile.TemporaryFile() as f_enc:
                s3.download_fileobj(Bucket=BUCKET_NAME, Key=s3_key, Fileobj=f_enc)
                f_enc.seek(0)

                nonce = f_enc.read(12)
                if len(nonce) != 12:
                    raise ValueError("Invalid file format: missing or corrupted nonce")

                ct_tag = f_enc.read()
                if len(ct_tag) < 16:
                    raise ValueError("Invalid file format: file too short (missing tag)")

                ciphertext = ct_tag[:-16]
                tag = ct_tag[-16:]

                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()

                parent = os.path.dirname(output_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)

                with open(output_path, "wb") as f_out:
                    f_out.write(decrypted)

            return relative_path

        except Exception as e:
            raise RuntimeError(f"Failed {relative_path}: {e}") from e

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_info = {
            executor.submit(restore_one, s3_key, out_path, rel, size): rel
            for s3_key, out_path, rel, size in files_to_restore
        }

        with tqdm(total=len(files_to_restore), desc="Files restored", unit="file", leave=True) as pbar:
            for future in as_completed(future_to_info):
                rel = future_to_info[future]
                try:
                    future.result()
                    success.append(rel)
                except Exception as e:
                    print(f"\n❌ {e}")
                    failed.append(rel)
                pbar.update(1)

    print(f"\n--- Restore Complete ---")
    print(f"✅ Succeeded: {len(success)} files")
    print(f"❌ Failed:    {len(failed)} files")
    if failed:
        for f in failed:
            print(f"   - {f}")
    print(f"\n📁 Restored to: ./{restore_base}/")


if __name__ == "__main__":
    if S3_KEY:
        decrypt_single_file(S3_KEY)
    else:
        restore_folder()
