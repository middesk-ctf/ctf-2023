import base64
from hashlib import sha256
from ecdsa.curves import NIST256p


# The JWT library from CTF Level 5
import level_5_jwt as jwt


# Decode base64 URL safe strings
def base64_url_decode(input):
    padding_needed = 4 - len(input) % 4
    input += "=" * padding_needed
    return base64.urlsafe_b64decode(input)


# Decode tokens into signature point and payload hashes
def decode_token(token):
    header_b64, claimset_b64, signature_b64 = token.split('.')

    signature = base64_url_decode(signature_b64)
    r = int.from_bytes(signature[:32], 'big') # first 32 bytes.
    s = int.from_bytes(signature[32:], 'big') # last 32 bytes

    payload = f'{header_b64}.{claimset_b64}'
    m = int.from_bytes(sha256(payload.encode()).digest(), 'big')

    return r, s, m


def get_d(token):
    r, s, m = decode_token(token)

    # Known k value (from the xkcd random number generator)
    k = 4

    n = NIST256p.order

    # Compute multiplicative inverse of r (modulo n)
    r_inv = pow(r, -1, n)

    # Need to perform the following calculation modulo n:
    #   d = (s*k - m) * r_inv
    d = ((s*k - m) * r_inv) % n

    return d.to_bytes(32, 'big')  # Private key in bytes format


token = 'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.eyJzdWIiOiAiamxoYXduIiwgImV4cCI6IDE3MDU2NTA0NjF9.4lNKNTLQj7ugLd5lnuYr0AMf4tt4VZbvUJMCRGsDCFIwBnXORvNQAVIo_LTALaTDY6PQX-22uj0yoWYhzMWTpw'

d = get_d(token)

key = jwt.SigningKeyES256(d)

new_token = key.encode({'sub':'admin','exp':2e9})

print(new_token)
