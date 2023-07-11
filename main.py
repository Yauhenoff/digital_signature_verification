from fastapi import FastAPI, UploadFile, Response, status, File
from fastapi.responses import FileResponse
from ecdsa import SigningKey, NIST256p
from ecdsa.keys import BadSignatureError
from ecdsa.util import sigdecode_der, sigencode_der
from hashlib import sha256
import os


app = FastAPI()


def write_binary_file(path, data):
    with open(path, 'wb') as file:
        file.write(data)


def read_binary_file(path):
    with open(path, 'rb') as file:
        data = file.read()
    return data


@app.post("/sign/")
async def get_signature(
        response: Response, message_file: UploadFile=File(...)):

    if message_file:
        private_key = SigningKey.generate(curve=NIST256p, hashfunc=sha256)
        user_file = await message_file.read()
        signature = private_key.sign(user_file, hashfunc=sha256,
                                     sigencode=sigencode_der,
                                     allow_truncate=False)

        os.mkdir("./secrets")
        write_binary_file('secrets/private_key.pem', private_key.to_pem())
        write_binary_file('secrets/signature.sign', signature)

        return FileResponse('secrets/signature.sign')
    response.status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    return False


@app.post("/verify/")
async def verify(
        response: Response, message_file: UploadFile=File(...),
        signature: UploadFile=File(...)):

    if message_file and ".sign" in signature.filename:

        encoding_key = read_binary_file('secrets/private_key.pem')
        private_key = SigningKey.from_pem(encoding_key, hashfunc=sha256)
        public_key = private_key.verifying_key

        user_file = await message_file.read()
        user_signature = await signature.read()

        try:
            public_key.verify(signature=user_signature, data=user_file,
                              hashfunc=sha256, sigdecode=sigdecode_der)
            return "VALID"
        except BadSignatureError:
            return "INVALID"
    response.status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    return False
