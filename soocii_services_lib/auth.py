import binascii
import json  # import simplejson if json not work
import time

import os
from .crypter import AESCipher


def _decode_token(token, secret_key):
    # convert the pre-defined secret from hex string.
    bin_secret = binascii.unhexlify(secret_key)
    aes = AESCipher(bin_secret)
    return aes.decrypt(token)


def _generate_token(raw, secret_key):
    # convert the pre-defined secret from hex string
    bin_secret = binascii.unhexlify(secret_key)

    aes = AESCipher(bin_secret)
    return aes.encrypt(raw)


class AccessTokenValidationFail(Exception):
    pass


class RefreshTokenValidationFail(Exception):
    pass


def _get_token_info():
    return {
        "access": {
            "secret_key": os.getenv('ACCESS_TOKEN_SECRET', 'None'),
            "age": 43200,
            "exception": AccessTokenValidationFail
        },
        "refresh": {
            "secret_key": os.getenv('REFRESH_TOKEN_SECRET', 'None'),
            "age": 604800,
            "exception": RefreshTokenValidationFail
        },
    }


def decode_access_token(token, check_timestamp=True):
    info = _get_token_info()['access']

    if not token:
        raise info["exception"]

    token = json.loads(_decode_token(token, info["secret_key"]).decode('utf-8'))

    if check_timestamp and token["timestamp"] + info["age"] < int(time.time()):
        raise info["exception"]

    return token


def generate_access_token(pid, uid, id, uuid, lang='EN-US', tz=8, device_type='', soocii_id=''):
    token = _generate_token(json.dumps({
        "pid": pid,
        "uid": uid,
        "id": id,
        "uuid": uuid,
        "timestamp": int(time.time()),
        "lang": lang,
        # Time Zone
        "tz": tz,
        "device_type": device_type,
        "soocii_id": soocii_id
    }, ensure_ascii=False), _get_token_info()["access"]["secret_key"])

    return token


def generate_refresh_token(access_token):
    token = _generate_token(json.dumps({
        "access_token": access_token,
        "timestamp": int(time.time()),
    }, ensure_ascii=False), _get_token_info()["refresh"]["secret_key"])

    return token
