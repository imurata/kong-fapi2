#!/usr/bin/env python3
"""Convert kong-rp-private.pem to JWK formats:
- kong-rp-private.jwk.json (private JWK for Kong's client_jwk)
- kong-rp-public.jwks.json (public JWKS for Keycloak's jwks.string)
"""
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key

KEY_ID = "kong-rp-key-1"
ALG = "PS256"

HERE = Path(__file__).parent

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def int_to_b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url(n.to_bytes(length, "big"))

priv = load_pem_private_key((HERE / "kong-rp-private.pem").read_bytes(), password=None)
pub_nums = priv.public_key().public_numbers()
priv_nums = priv.private_numbers()

public_jwk = {
    "kty": "RSA",
    "use": "sig",
    "alg": ALG,
    "kid": KEY_ID,
    "n": int_to_b64(pub_nums.n),
    "e": int_to_b64(pub_nums.e),
}

private_jwk = {
    **public_jwk,
    "d": int_to_b64(priv_nums.d),
    "p": int_to_b64(priv_nums.p),
    "q": int_to_b64(priv_nums.q),
    "dp": int_to_b64(priv_nums.dmp1),
    "dq": int_to_b64(priv_nums.dmq1),
    "qi": int_to_b64(priv_nums.iqmp),
}

(HERE / "kong-rp-private.jwk.json").write_text(json.dumps(private_jwk, indent=2) + "\n")
(HERE / "kong-rp-public.jwks.json").write_text(json.dumps({"keys": [public_jwk]}, indent=2) + "\n")

print("Wrote kong-rp-private.jwk.json (Kong client_jwk)")
print("Wrote kong-rp-public.jwks.json (Keycloak jwks.string)")
