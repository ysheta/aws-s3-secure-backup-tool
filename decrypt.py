import boto3
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# ====================================================
load_dotenv("keys.env")

AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
BUCKET_NAME    = os.environ.get("BUCKET_NAME")
REGION         = os.environ.get("REGION")
S3_KEY         = os.environ.get("S3_KEY")

if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
    raise ValueError("❌ Missing AWS credentials! Check your keys.env file.")
if not BUCKET_NAME or not REGION:
    raise ValueError("❌ Missing BUCKET_NAME or REGION in keys.env file!")
if not S3_KEY:
    raise ValueError("❌ Missing S3_KEY in keys.env file!")
# ====================================================

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)

with open("encryption_key.key", "rb") as f:
    key = f.read()
cipher = Fernet(key)

def download_and_decrypt():
    try:
        print(f"📥 Downloading encrypted file: {S3_KEY}")
        response       = s3.get_object(Bucket=BUCKET_NAME, Key=S3_KEY)
        encrypted_data = response['Body'].read()
        decrypted_data = cipher.decrypt(encrypted_data)

        OUTPUT_FILENAME = os.path.basename(S3_KEY)
        with open(OUTPUT_FILENAME, "wb") as f:
            f.write(decrypted_data)

        print(f"✅ Successfully decrypted and saved as: {OUTPUT_FILENAME}")

    except Exception as e:
        print(f"❌ Failed to decrypt file: {e}")

if __name__ == "__main__":
    download_and_decrypt()    try:
        print(f"📥 Downloading encrypted file: {S3_KEY}")
        
        response = s3.get_object(Bucket=BUCKET_NAME, Key=S3_KEY)
        encrypted_data = response['Body'].read()

        decrypted_data = cipher.decrypt(encrypted_data)

        OUTPUT_FILENAME = os.path.basename(S3_KEY)

        with open(OUTPUT_FILENAME, "wb") as f:
            f.write(decrypted_data)

        print(f"✅ Successfully decrypted and saved as: {OUTPUT_FILENAME}")

    except Exception as e:
        print(f"❌ Failed to decrypt file: {e}")

if __name__ == "__main__":
    download_and_decrypt()
