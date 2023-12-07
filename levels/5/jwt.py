"""
This package implements the draft specification of
JSON Object Signing and Encryption (JOSE) for JSON Web Signatures (JWTs)
Reference: https://datatracker.ietf.org/doc/html/rfc7519
"""
import base64
import hashlib
import json
from abc import ABC, abstractmethod

import ecdsa


class SigningKey(ABC):
    """Abstract Base Class for JWT Signing Keys"""

    def encode(self, claimset: dict) -> str:
        """
        Encodes a claimset into a JSON Web Token.
        """
        header = {"typ": "JWT", "alg": self.alg()}
        header_b64 = _base64_encode(json.dumps(header).encode())
        claimset_b64 = _base64_encode(json.dumps(claimset).encode())

        # Signature payload is a concatenation of
        # the base64-encoded header and claimeset.
        payload = f"{header_b64}.{claimset_b64}"
        signature = self.sign(payload.encode())

        signature_b64 = _base64_encode(signature)

        # The final JWT is the payload concatenated
        # with the base64-encoded signature.
        return f"{payload}.{signature_b64}"

    def decode(self, token: str) -> dict:
        """
        Decodes a JWT token and verifies its signature.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        header_b64, claimset_b64, signature_b64 = parts
        header = json.loads(_base64_decode(header_b64))

        if header.get("typ") != "JWT":
            raise ValueError("Invalid JWS type")

        if header.get("alg") != self.alg():
            raise ValueError(
                f"Expected Signing Algorithm {self.alg()} but got {header.get('alg')}"
            )

        # Signature payload is a concatenation of
        # the base64-encoded header and claimeset.
        payload = f"{header_b64}.{claimset_b64}".encode()
        signature = _base64_decode(signature_b64)

        if not self.verify(payload, signature):
            raise ValueError("Invalid token signature")

        return json.loads(_base64_decode(claimset_b64))

    @staticmethod
    @abstractmethod
    def alg() -> str:
        """This static method should be implemented by any subclass"""
        pass

    @abstractmethod
    def sign(self, payload: bytes, secret: bytes) -> bytes:
        """This static method should be implemented by any subclass"""
        pass

    @abstractmethod
    def verify(self, payload: bytes, signature: bytes, secret: bytes) -> bool:
        """This static method should be implemented by any subclass"""
        pass

    @abstractmethod
    def to_jwk(self) -> dict:
        """This static method should be implemented by any subclass"""
        pass


class SigningKeyES256(SigningKey):
    """
    JSON Web Signature: ECDSA using P-256 and SHA-256 (ES256).
    Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
    """

    def __init__(self, secret: bytes):
        # `NIST P-256` also known as `SECG secp256r1` and `ANSI prime256v1`
        self.curve = ecdsa.NIST256p

        if len(secret) != self.curve.baselen:
            raise ValueError(
                f"secret value must be exactly {self.curve.baselen} bytes long"
            )

        # The name from_string here is a misnomer from the python 2 days when
        # binary strings and character strings were the same type.
        # The argument is actually bytes. Thanks Obama.
        self.private_key = ecdsa.SigningKey.from_string(
            secret, curve=self.curve, hashfunc=hashlib.sha256
        )
        self.public_key = self.private_key.verifying_key

    @staticmethod
    def alg() -> str:
        return "ES256"

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload, k=self.get_random_number())

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            return self.public_key.verify(signature, payload)
        except ecdsa.BadSignatureError:
            return False

    @staticmethod
    def get_random_number() -> int:
        """
        RFC 1149.5 specifies 4 as the standard IEEE-vetted random number.
        Chosen by fair dice roll. Guaranteed to be random.
        Reference: https://xkcd.com/221/
        """
        return 4

    def to_jwk(self) -> dict:
        """
        Returns this elliptic curve key in JWK format.
        Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
        """
        x = self.public_key.pubkey.point.x()
        y = self.public_key.pubkey.point.y()
        d = self.private_key.privkey.secret_multiplier
        return {
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "x": _base64_encode(x.to_bytes(self.curve.baselen)),
            "y": _base64_encode(y.to_bytes(self.curve.baselen)),
            "d": _base64_encode(d.to_bytes(self.curve.baselen)),
        }


def _base64_encode(data: bytes) -> str:
    """
    Encodes data to base64 URL safe string in the format
    expected for JSON Web Signatures (no trailing '=' characters).
    """
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _base64_decode(data: str) -> bytes:
    """
    Decodes data from base64 URL safe string in the format
    expected for JSON Web Signatures (no trailing '=' characters).
    """
    padding_needed = 4 - len(data) % 4
    data += "=" * padding_needed
    return base64.urlsafe_b64decode(data)
