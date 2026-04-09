import boto3
import os
import io
from cryptography.fernet import Fernet
from datetime import datetime
from dotenv import load_dotenv

# ====================================================
load_dotenv("keys.env")

AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
BUCKET_NAME    = os.environ.get("BUCKET_NAME")
REGION         = os.environ.get("REGION")

if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
    raise ValueError("❌ Missing AWS credentials! Check your keys.env file.")
if not BUCKET_NAME or not REGION:
    raise ValueError("❌ Missing BUCKET_NAME or REGION in keys.env file!")

# ====================================================
_folder_raw = os.environ.get("FOLDER_TO_BACKUP")
if not _folder_raw:
    raise ValueError("❌ Missing FOLDER_TO_BACKUP in keys.env file!")

FOLDER_TO_BACKUP = os.path.expanduser(_folder_raw)
SHARE_EXPIRATION = int(os.environ.get("SHARE_EXPIRATION", 3600))
# ====================================================

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
    key_file = "encryption_key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        print("✅ New encryption key generated and saved.")
        return key

key    = get_or_create_key()
cipher = Fernet(key)

def backup_folder():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    print(f"🚀 Starting backup at {timestamp}...\n")

    success = []
    failed  = []

    for root, dirs, files in os.walk(FOLDER_TO_BACKUP):
        for file in files:
            file_path     = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, FOLDER_TO_BACKUP)
            s3_key        = f"backups/{timestamp}/{relative_path}"

            try:
                with open(file_path, "rb") as f:
                    data = f.read()

                encrypted_data = cipher.encrypt(data)
                file_obj       = io.BytesIO(encrypted_data)
                s3.upload_fileobj(file_obj, BUCKET_NAME, s3_key)
                print(f"✅ Uploaded (encrypted): {s3_key}")

                presigned_url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': BUCKET_NAME, 'Key': s3_key},
                    ExpiresIn=SHARE_EXPIRATION
                )
                print(f"🔒 Download Link ({SHARE_EXPIRATION}s):\n{presigned_url}\n")

                success.append(file_path)

            except Exception as e:
                print(f"❌ Failed: {file_path} — {e}")
                failed.append(file_path)

    print(f"\n--- Backup Complete ---")
    print(f"✅ Succeeded: {len(success)} files")
    print(f"❌ Failed:    {len(failed)} files")
    if failed:
        for f in failed:
            print(f"   - {f}")

if __name__ == "__main__":
    backup_folder()
