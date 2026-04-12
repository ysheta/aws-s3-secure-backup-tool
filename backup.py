import boto3
import os
import json
import tempfile
import threading
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
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

if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
    raise ValueError("❌ Missing AWS credentials! Check your keys.env file.")
if not BUCKET_NAME or not REGION:
    raise ValueError("❌ Missing BUCKET_NAME or REGION in keys.env file!")

_folder_raw = os.environ.get("FOLDER_TO_BACKUP")
if not _folder_raw:
    raise ValueError("❌ Missing FOLDER_TO_BACKUP in keys.env file!")

FOLDER_TO_BACKUP = os.path.expanduser(_folder_raw)
SHARE_EXPIRATION = int(os.environ.get("SHARE_EXPIRATION", 3600))
MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "12")))
MAX_RETRIES = max(0, int(os.environ.get("MAX_RETRIES", "3")))
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks
COMPRESSION_LEVEL = max(1, min(22, int(os.environ.get("COMPRESSION_LEVEL", "3"))))

# Progress bar logic
SHOW_PER_FILE_PROGRESS = os.environ.get("SHOW_PER_FILE_PROGRESS")
if SHOW_PER_FILE_PROGRESS is None:
    SHOW_PER_FILE_PROGRESS = MAX_WORKERS <= 4
else:
    SHOW_PER_FILE_PROGRESS = str(SHOW_PER_FILE_PROGRESS).strip() == "1"

if not os.path.exists(FOLDER_TO_BACKUP) or not os.path.isdir(FOLDER_TO_BACKUP):
    raise ValueError(f"❌ Folder not found or is not a directory: {FOLDER_TO_BACKUP}")

if not ZSTD_AVAILABLE:
    print("⚠️  'zstandard' not installed. Backing up WITHOUT compression. (pip install zstandard)")

# ===================================================
# Extensions that are already compressed or binary-packed.
# Compressing these wastes CPU and slightly increases file size.
# ===================================================
INCOMPRESSIBLE_EXTENSIONS = {
    # Video
    ".mp4", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".webm", ".m4v",
    ".mpg", ".mpeg", ".3gp", ".hevc", ".ts",
    # Audio
    ".mp3", ".aac", ".ogg", ".flac", ".m4a", ".wma", ".opus",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif",
    ".bmp", ".tiff", ".tif", ".avif",
    # Archives & packages
    ".zip", ".gz", ".bz2", ".xz", ".zst", ".lz4", ".br",
    ".rar", ".7z", ".tar",
    ".pkg", ".dmg", ".iso", ".deb", ".rpm", ".apk", ".ipa",
    # Documents with built-in compression
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".epub",
    # Compiled / binary formats
    ".exe", ".dll", ".so", ".dylib", ".wasm",
    ".pyc", ".pyd", ".class",
}


def should_compress(file_path: str, file_size: int) -> bool:
    """
    Returns True only when compression is expected to be beneficial:
      - zstd is available
      - file is non-empty
      - file extension is not in the known-incompressible set
    """
    if not ZSTD_AVAILABLE or file_size == 0:
        return False
    ext = os.path.splitext(file_path)[1].lower()
    return ext not in INCOMPRESSIBLE_EXTENSIONS


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

def get_or_create_key():
    """Fetches existing AES key or generates a new one for the restore script to use."""
    key_file = "encryption_key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("❌ encryption_key.key must be exactly 32 bytes (AES-256 key).")
        return key
    else:
        key = os.urandom(32)
        with open(key_file, "wb") as f:
            f.write(key)
        print("✅ New 32-byte AES-256 encryption key generated and saved to encryption_key.key")
        return key

key = get_or_create_key()
console_lock = threading.Lock()

def make_callback(pbar):
    def callback(bytes_transferred):
        with console_lock:
            pbar.update(bytes_transferred)
    return callback

# Module-Level Helpers
class EncryptorWriter:
    """Pipes data directly into the AES encryptor and out to a file object."""
    def __init__(self, encryptor, file_obj):
        self.encryptor = encryptor
        self.file_obj = file_obj

    def write(self, data):
        self.file_obj.write(self.encryptor.update(data))

    def flush(self):
        pass

# Core Processing Logic
def process_single_file(file_path: str, relative_path: str, s3_key: str) -> dict:
    """
    Reads file, hashes it, optionally compresses it, encrypts it, and uploads to S3.
    """
    original_size = os.path.getsize(file_path)
    sha256_hash = hashlib.sha256()

    use_compression = should_compress(file_path, original_size)      # skip compression for already-compressed / binary extensions

    try:
        with open(file_path, "rb") as f_in:
            with tempfile.TemporaryFile() as f_enc:
                if not SHOW_PER_FILE_PROGRESS:
                    comp_tag = " (zstd)" if use_compression else ""
                    print(f"🔐 Processing{comp_tag}: {relative_path}")

                nonce = os.urandom(12)
                comp_flag = b'\x01' if use_compression else b'\x00'
                f_enc.write(nonce)
                f_enc.write(comp_flag)

                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                writer = EncryptorWriter(encryptor, f_enc)

                if use_compression:
                    cctx = zstd.ZstdCompressor(level=COMPRESSION_LEVEL)
                    with cctx.stream_writer(writer) as compressor:
                        while True:
                            chunk = f_in.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            sha256_hash.update(chunk)
                            compressor.write(chunk)
                else:
                    while True:
                        chunk = f_in.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        sha256_hash.update(chunk)
                        writer.write(chunk)

                encryptor.finalize()
                f_enc.write(encryptor.tag)

                f_enc.seek(0, 2)
                encrypted_size = f_enc.tell()

                for attempt in range(MAX_RETRIES + 1):
                    f_enc.seek(0)
                    attempt_label = f" (retry {attempt})" if attempt > 0 else ""

                    try:
                        if SHOW_PER_FILE_PROGRESS:
                            with tqdm(
                                total=encrypted_size,
                                unit='B',
                                unit_scale=True,
                                unit_divisor=1024,
                                desc=f"↑ {relative_path}",
                                leave=False,
                                mininterval=0.5
                            ) as pbar:
                                s3.upload_fileobj(
                                    f_enc,
                                    BUCKET_NAME,
                                    s3_key,
                                    Callback=make_callback(pbar)
                                )
                        else:
                            print(f"⬆️  Uploading{attempt_label}: {relative_path} ({encrypted_size:,} bytes)")
                            s3.upload_fileobj(f_enc, BUCKET_NAME, s3_key)

                        break

                    except Exception as e:
                        if attempt == MAX_RETRIES:
                            raise RuntimeError(f"Upload failed after {MAX_RETRIES} retries: {e}") from e
                        wait = 2 ** attempt
                        print(f"⚠️  Attempt {attempt+1}/{MAX_RETRIES+1} failed — retrying in {wait}s... ({e})")
                        time.sleep(wait)

                presigned_url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': BUCKET_NAME, 'Key': s3_key},
                    ExpiresIn=SHARE_EXPIRATION
                )

                return {
                    "s3_key": s3_key,
                    "presigned_url": presigned_url,
                    "original_size_bytes": original_size,
                    "encrypted_size_bytes": encrypted_size,
                    "sha256": sha256_hash.hexdigest(),
                    "compression": "zstd" if use_compression else "none"
                }

    except IOError as e:
        raise RuntimeError(f"File read error for {relative_path}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Failed processing {relative_path}: {e}") from e


# Main Backup Orchestrator
def backup_folder():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    print(f"🚀 Starting PARALLEL backup at {timestamp}... "
          f"({MAX_WORKERS} threads | {MAX_RETRIES} retries | Zstd: {'Available' if ZSTD_AVAILABLE else 'Unavailable'})\n")

    files_to_process = []
    for root, _, filenames in os.walk(FOLDER_TO_BACKUP, followlinks=False):
        for filename in filenames:
            file_path     = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, FOLDER_TO_BACKUP)
            s3_key        = f"backups/{timestamp}/{relative_path}"
            files_to_process.append((file_path, relative_path, s3_key))

    print(f"📦 Found {len(files_to_process)} files to backup.\n")

    success = []
    failed = []
    manifest = {
        "backup_timestamp": timestamp,
        "source_folder": FOLDER_TO_BACKUP,
        "encryption": "AES-256-GCM (12-byte nonce + 1-byte comp flag + ciphertext + 16-byte tag)",
        "files": {}
    }

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_info = {
            executor.submit(process_single_file, fp, rp, sk): (fp, rp)
            for fp, rp, sk in files_to_process
        }

        with tqdm(total=len(files_to_process), desc="Total Progress", unit="file") as pbar:
            for future in as_completed(future_to_info):
                fp, rp = future_to_info[future]
                try:
                    manifest_entry = future.result()
                    manifest["files"][rp] = manifest_entry
                    success.append(fp)
                except Exception as e:
                    with console_lock:
                        print(f"❌ {e}")
                    failed.append(fp)
                pbar.update(1)

    if manifest["files"]:
        manifest_key = f"backups/{timestamp}/MANIFEST.json"
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=manifest_key,
            Body=json.dumps(manifest, indent=2).encode('utf-8')
        )

        manifest_presigned = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': manifest_key},
            ExpiresIn=SHARE_EXPIRATION
        )

        print(f"\n📋 Manifest created with {len(manifest['files'])} files")
        print(f"🔗 Manifest Download Link ({SHARE_EXPIRATION}s):")
        print(manifest_presigned)

    print(f"\n--- Backup Complete ---")
    print(f"✅ Succeeded: {len(success)} files")
    print(f"❌ Failed:    {len(failed)} files")

    if failed:
        print("\nFailed files:")
        for f in failed:
            print(f"   - {f}")

if __name__ == "__main__":
    backup_folder()
