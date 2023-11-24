import os, sys
import hashlib
import json
from datetime import datetime
from dateutil import parser
from flask import Flask, render_template, request, jsonify, redirect
from google.auth.transport import requests
from google.oauth2 import id_token
from google.cloud import storage, kms_v1
from base64 import b64encode, b64decode


def md5(str):
    return hashlib.md5(str.encode('utf-8')).hexdigest()

def logthis(str):
    print(str)
    sys.stdout.flush()  


app = Flask(__name__)
app.jinja_env.filters.update(md5=md5)

# Initialize the GCS and KMS clients
storage_client = storage.Client()
client = kms_v1.KeyManagementServiceClient()

# GCS bucket and KMS details
BUCKET_NAME = '{your bucket}'
PROJECT_ID = '{your gcp project here}'
REGION_ID = 'asia-east1'
KMS_KEY_RING = f'projects/{PROJECT_ID}/locations/{REGION_ID}/keyRings/secrets-sharing'
KMS_KEY_NAME = f'{KMS_KEY_RING}/cryptoKeys/secrets-sharing'
EXPIRED_SECRET_5_MINUTES = 5
AUDIENCE = '{your audience here}'


@app.route('/')
def index():
    # Read email addresses from a file
    try:
        with open('emails.txt', 'r') as file:
            email_list = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        email_list = []  # No emails found, or file doesn't exist

    return render_template('index.html', emails=email_list)


class TimeExpired(Exception):
    pass


def create_crypto_key(key_id):
    """
    Create new crypto key.
    """
    # Initialize request argument(s)
    request = kms_v1.CreateCryptoKeyRequest(
        parent=KMS_KEY_RING,
        crypto_key_id=key_id,
        crypto_key=kms_v1.CryptoKey(purpose='ENCRYPT_DECRYPT'),
    )

    # Make the request
    return client.create_crypto_key(request=request)


def encrypt_data(plaintext):
    """
    Encrypt data using the KMS key.
    """
    # Initialize request argument(s)
    request = kms_v1.EncryptRequest(
        name=KMS_KEY_NAME,
        plaintext=plaintext,
    )

    response = client.encrypt(request=request)
    return b64encode(response.ciphertext).decode('utf-8')


def save_to_gcs(encrypted_data, filename):
    """
    Save the encrypted data to a file in GCS.
    """
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(filename)
    blob.upload_from_string(encrypted_data, content_type='application/json')


@app.route('/submit_secrets', methods=['POST'])
def submit_secrets():
    # Retrieve selected emails and the secret
    emails = request.form.getlist('emails')
    secret = request.form['secret']

    # Capture secrets and encrypt it
    text_data = request.form.get('secret', '')
    encrypted_data = encrypt_data(text_data.encode('utf-8'))
    _now = datetime.now()
    create_date = _now.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

    for email in emails:
        email_md5 = hashlib.md5(email.encode('utf-8')).hexdigest()
        # Create and save the encrypted data object
        data_object = {
            "key": email_md5,
            "data": encrypted_data,
            "created": create_date,
            "email": email,
        }
        json_data = json.dumps(data_object)
        filename = f'{email_md5}.json'
        save_to_gcs(json_data, filename)

    return render_template('secret_submitted.html', emails=emails)


@app.route('/secret/<hash>', methods=['GET'])
def retrieve_secrets(hash):
    # Get the ID token sent by the client
    id_token_from_header = request.headers.get(
        "Authorization", 
        request.headers.get("x-goog-iap-jwt-assertion")
    )

    try:
        if not id_token_from_header:
            raise ValueError('Not authenticated, no token found')
        
        decoded_jwt = id_token.verify_token(
            id_token_from_header,
            requests.Request(),
            audience=AUDIENCE,
            certs_url="https://www.gstatic.com/iap/verify/public_key",
        )
        user_email = decoded_jwt['email']

        if hash != md5(user_email):
            raise ValueError('This secret is not meant for you')
    except ValueError as ve:
        # Invalid token
        logthis(f'Exception: {ve}')
        return render_template('not_authorized.html', error=ve)

    try:
        # Retrieve the file from GCS
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f'{hash}.json')
        encrypted_data = blob.download_as_bytes()
        data_object = json.loads(encrypted_data)

        # Check for expiration (5 minutes)
        create_dt = parser.parse(data_object['created'])
        elapsed_time = (datetime.now() - create_dt).total_seconds() / 60
        if elapsed_time > EXPIRED_SECRET_5_MINUTES:
            raise TimeExpired('Secret has expired')

        # Decrypt the data
        decrypted_data = decrypt_data(data_object['data'])

        return render_template('retrieve_secrets.html', data=decrypted_data)

    except TimeExpired as te:
        return render_template('not_authorized.html', error=te)

    except Exception as e:
        # Handle exceptions
        return render_template('not_authorized.html', error=e)


def decrypt_data(ciphertext):
    """
    Decrypt data using the KMS key.
    """
    # Decode the base64 encoded ciphertext
    decoded_ciphertext = b64decode(ciphertext)

    # Decrypt the data
    response = client.decrypt(request={'name': KMS_KEY_NAME, 'ciphertext': decoded_ciphertext})
    return response.plaintext.decode('utf-8')

        
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 80)))
