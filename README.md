# AWS S3 Secure Backup Tool

Secure automated backup tool that **encrypts files locally** before uploading to AWS S3.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)
![boto3](https://img.shields.io/badge/boto3-FF9900?style=for-the-badge&logo=amazon&logoColor=white)

A robust Python backup solution that encrypts files using **AES-256-GCM** before uploading them to AWS S3. Designed for security, performance, and ease of restoration.

---

## What's New in v2.1

- **SHA-256 integrity verification** — Plaintext hash computed during backup and verified after decryption, end-to-end
- **Smart compression** — Zstandard (zstd) compression applied automatically; skipped for already-compressed formats (`.mp4`, `.jpg`, `.zip`, `.pdf`, `.pkg`, and many more) to save CPU and avoid size inflation
- **Explicit GCM tag error handling** — `InvalidTag` exceptions are caught, the corrupt output file is deleted, and a clear security warning is raised
- **Single-file integrity check** — When decrypting a single file, the parent manifest is fetched automatically to retrieve the expected SHA-256; an explicit warning is printed if verification cannot run
- **Self-describing file format** — Encrypted files now carry a compression flag in the header (`nonce[12] + comp_flag[1] + ciphertext + tag[16]`), so restore never needs to guess

---

## What's New in v2.0

- **True streaming AES-256-GCM encryption** — Low memory usage even for large files
- **Parallel uploads & downloads** — Configurable concurrency with `ThreadPoolExecutor`
- **Smart retry logic** — Automatic retries with exponential backoff on transient failures
- **Manifest-based restore** — Full folder restore using `MANIFEST.json`
- **Path traversal protection** — Safe restoration even from untrusted manifests
- **Clean progress reporting** — Improved console output with `tqdm`

---

## Features

- **End-to-end encryption** — Files are encrypted locally with AES-256-GCM (authenticated encryption). Plaintext never touches S3.
- **End-to-end integrity** — SHA-256 of the original plaintext is stored in the manifest and re-verified after decryption.
- **Smart compression** — zstd compression is applied where it helps. Known incompressible formats (video, audio, images, archives, office documents, compiled binaries) are automatically skipped.
- **Streaming processing** — Low memory footprint; suitable for large files and folders.
- **Timestamped backups** — Each run creates a unique folder: `backups/YYYY-MM-DD_HH-MM-SS/`
- **Manifest file** — `MANIFEST.json` contains metadata, SHA-256 hashes, compression info, presigned URLs, and original/encrypted sizes.
- **Parallel operations** — Fast backup and restore with configurable worker count.
- **Retry resilience** — Exponential backoff on both upload and download; handles transient S3/network errors gracefully.
- **Two restore modes** — Full folder restore by timestamp, or single file decrypt with automatic manifest lookup.
- **Tamper detection** — GCM authentication tag mismatch and SHA-256 mismatches both produce explicit errors and delete the corrupt output file.

---

## Technologies Used

- Python 3.10+
- boto3 (AWS SDK)
- cryptography (AES-256-GCM via `hazmat`)
- zstandard (optional — compression support)
- python-dotenv
- tqdm (progress bars)
- AWS S3

---

## Setup

### 1. Install dependencies

```bash
pip3 install boto3 cryptography python-dotenv tqdm
```

For compression support (recommended):

```bash
pip3 install zstandard
```

If `zstandard` is not installed, the tool runs normally without compression and prints a warning at startup.

### 2. Configure `keys.env`

Copy `keys.env.example` to `keys.env` and fill in your details:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
BUCKET_NAME=your-bucket-name
REGION=us-east-1
FOLDER_TO_BACKUP=~/Documents

# Optional tuning
MAX_WORKERS=4
MAX_RETRIES=3
COMPRESSION_LEVEL=3
SHARE_EXPIRATION=3600
SHOW_PER_FILE_PROGRESS=0

# For restore only
RESTORE_TIMESTAMP=2025-01-01_12-00-00
# S3_KEY=backups/2025-01-01_12-00-00/subdir/file.txt
# MANIFEST_KEY=backups/2025-01-01_12-00-00/MANIFEST.json
# OUTPUT_DIR=decrypted
```

### 3. First Run

The first time you run the backup script, it will automatically generate `encryption_key.key`. **Keep this file safe and backed up separately** — it is required to decrypt your backups and cannot be recovered if lost.

---

## How to Use

### 1. Run a Backup

```bash
python3 backup.py
```

Each run produces a timestamped folder in S3 (`backups/YYYY-MM-DD_HH-MM-SS/`) containing the encrypted files and a `MANIFEST.json`.

### 2. Restore an Entire Backup

Set `RESTORE_TIMESTAMP` in `keys.env` to the timestamp of the backup you want to restore, then run:

```bash
python3 decrypt_restore.py
```

Files are restored to `./restored/<timestamp>/` preserving the original folder structure. SHA-256 is verified for every file.

### 3. Decrypt a Single File

Set `S3_KEY` in `keys.env` to the full S3 key of the file, then run:

```bash
python3 decrypt_restore.py
```

The script will automatically fetch the parent manifest to retrieve the expected SHA-256 and run an integrity check. If the manifest is unavailable, a warning is printed and GCM authentication still runs. The decrypted file is saved to `OUTPUT_DIR` (default: `decrypted/`).

---

## Encrypted File Format

Each encrypted file on S3 has the following binary layout:

```
[ 12 bytes — AES-GCM nonce ]
[  1 byte  — compression flag: 0x00 = none, 0x01 = zstd ]
[  N bytes — ciphertext (optionally zstd-compressed plaintext) ]
[ 16 bytes — AES-GCM authentication tag ]
```

The compression flag is part of the authenticated ciphertext, so any tampering with it is detected by GCM.

---

## Security Notes

- Plaintext data never leaves your machine — only encrypted files are uploaded to S3.
- AES-256-GCM provides both confidentiality and integrity (authenticated encryption).
- SHA-256 provides an additional end-to-end plaintext integrity guarantee independent of the encryption layer.
- Keep `encryption_key.key` safe and backed up separately — losing it means your backups are permanently unrecoverable.
- Use an IAM user with least-privilege permissions (S3 read/write for your bucket only).
- If GCM tag validation fails during restore, the output file is deleted immediately and an explicit security warning is raised.

---

## Changelog

### v2.1.0 (Current)

- Added SHA-256 plaintext integrity hashing on backup; verified after decryption on restore
- Added Zstandard (zstd) compression with automatic skip for incompressible file types
- Added `EncryptorWriter` and `HashWriter` stream-wrapper classes for clean pipeline composition
- Explicit `InvalidTag` handling in restore — corrupt output deleted, security warning raised
- Single-file decrypt now auto-fetches parent manifest for SHA-256 verification; warns explicitly when unavailable
- File header extended with 1-byte compression flag (`nonce[12] + comp_flag[1] + ciphertext + tag[16]`)
- `MANIFEST.json` extended with `sha256`, `compression`, and `encrypted_size_bytes` fields per file
- `CHUNK_SIZE` and `COMPRESSION_LEVEL` promoted to configurable module-level constants

### v2.0.0

- Upgraded from Fernet to AES-256-GCM streaming encryption
- Added true low-memory streaming for backup and restore
- Parallel processing with thread-safe progress bars
- Added `MANIFEST.json`, retry logic, and path traversal protection
- Improved console output and error handling

### v1.0.0

- Initial Fernet-based implementation
