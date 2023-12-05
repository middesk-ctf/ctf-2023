"""
This package implements the draft specification of
JSON Object Signing and Encryption (JOSE) for JSON Web Signatures (JWTs)
Reference:
https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-15
"""
import base64
import hashlib
import hmac
import json

# JSON Web Signature spec requires these two algorithms.
# https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-15#section-3.1


# JWS HMAC With SHA-2 (HS256).
# https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-15#section-3.2
class _AlgorithmHS256:
    NAME = "HS256"

    @staticmethod
    def sign(payload, secret):
        return _base64_encode(
            hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
        )

    @staticmethod
    def verify(header_encoded, payload_encoded, signature, secret):
        expected_signature = _AlgorithmHS256.sign(
            f"{header_encoded}.{payload_encoded}", secret
        )
        return _constant_time_compare(signature, expected_signature)


# The 'none' Algorithm.
# https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-15#section-3.6
class _AlgorithmNone:
    NAME = "none"

    @staticmethod
    def sign(*_):
        return ""

    @staticmethod
    def verify(*_):
        return True


def _get_alg(alg):
    if alg == _AlgorithmHS256.NAME:
        return _AlgorithmHS256
    if alg == _AlgorithmNone.NAME:
        return _AlgorithmNone
    raise ValueError("Unsupported algorithm")


def encode(payload, secret, alg=_AlgorithmHS256):
    """
    Encodes a payload to a JWT token.
    """
    header = {"typ": "JWT", "alg": alg.NAME}
    header_encoded = _base64_encode(json.dumps(header).encode())
    payload_encoded = _base64_encode(json.dumps(payload).encode())

    payload = f"{header_encoded}.{payload_encoded}"
    signature = alg.sign(payload, secret)

    return f"{payload}.{signature}"


def decode(token, secret):
    """
    Decodes a JWT token and verifies its signature.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    header_encoded, payload_encoded, signature = parts
    header = json.loads(_base64_decode(header_encoded))

    if header.get("typ") != "JWT":
        raise ValueError("Invalid JWS type")

    alg = _get_alg(header.get("alg"))

    if not alg.verify(header_encoded, payload_encoded, signature, secret):
        raise ValueError("Invalid token signature")

    return json.loads(_base64_decode(payload_encoded))


def _base64_encode(data: bytes):
    """
    Encodes data to base64 URL safe string.
    """
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _base64_decode(data: bytes):
    """
    Decodes data from base64 URL safe string.
    """
    padding_needed = 4 - len(data) % 4
    data += "=" * padding_needed
    return base64.urlsafe_b64decode(data).decode()


def _constant_time_compare(val1, val2):
    """
    Compares two strings in a way that is resistant to timing attacks.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0
