#!/usr/bin/env python3
"""FAPI 2.0 DPoP end-to-end verification: PAR → login → auth code → DPoP token → Kong API"""
import json, hashlib, base64, secrets, time, sys, os, urllib.parse, re
from html.parser import HTMLParser
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import requests

KEYCLOAK_BASE = "http://keycloak.localhost:9080"
REALM         = "fapi2"
CLIENT_ID     = "fapi2-test-client"
CLIENT_SECRET = "fapi2-test-secret"
REDIRECT_URI  = "http://localhost:8000/anything"
KONG_URL      = "http://localhost:8000/anything"
KC_PAR_URL    = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/ext/par/request"
KC_AUTH_URL   = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL  = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/token"
USERNAME      = "alice"
PASSWORD      = "alice-pass"

# ── DPoP helpers ─────────────────────────────────────────────────────────────
def load_or_generate_key(path="dpop-private.pem"):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    key = generate_private_key(SECP256R1())
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return key

def key_to_jwk(private_key):
    nums = private_key.public_key().public_numbers()
    b64  = lambda n: base64.urlsafe_b64encode(n.to_bytes(32, 'big')).rstrip(b'=').decode()
    return {"kty": "EC", "crv": "P-256", "x": b64(nums.x), "y": b64(nums.y)}

def jwk_thumbprint(jwk):
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(',', ':')
    )
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b'=').decode()

def make_dpop_proof(private_key, jwk, htm, htu, access_token=None):
    def b64j(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(',', ':')).encode()).rstrip(b'=').decode()
    header  = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"jti": secrets.token_urlsafe(16), "htm": htm, "htu": htu, "iat": int(time.time())}
    if access_token:
        payload["ath"] = base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode()).digest()
        ).rstrip(b'=').decode()
    msg     = f"{b64j(header)}.{b64j(payload)}".encode()
    r, s    = decode_dss_signature(private_key.sign(msg, ECDSA(hashes.SHA256())))
    sig     = base64.urlsafe_b64encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).rstrip(b'=').decode()
    return f"{b64j(header)}.{b64j(payload)}.{sig}"

# ── HTML form parser ──────────────────────────────────────────────────────────
class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = {}
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and not self.action:
            self.action = a.get("action")
        if tag == "input":
            name = a.get("name")
            if name:
                self.fields[name] = a.get("value", "")

# ── Helpers ───────────────────────────────────────────────────────────────────
def ok(msg):   print(f"  ✓ {msg}")
def err(msg):  print(f"  ✗ {msg}"); sys.exit(1)

print("=" * 60)
print("  FAPI 2.0 DPoP End-to-End Verification")
print("=" * 60)

# [1] DPoP key
private_key = load_or_generate_key()
jwk         = key_to_jwk(private_key)
jkt         = jwk_thumbprint(jwk)
ok(f"DPoP key  jkt={jkt[:24]}...")

# [2] PKCE
verifier  = secrets.token_urlsafe(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
ok(f"PKCE  verifier={verifier[:10]}...")

# [3] PAR
print(f"\n[3] PAR")
session = requests.Session()
par = session.post(KC_PAR_URL, data={
    "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    "response_type": "code", "scope": "openid profile",
    "redirect_uri": REDIRECT_URI,
    "code_challenge": challenge, "code_challenge_method": "S256",
})
print(f"    {par.status_code}  {par.text[:120]}")
if par.status_code != 201:
    err(f"PAR failed: {par.status_code}")
request_uri = par.json()["request_uri"]
ok(f"request_uri={request_uri[:40]}...")

# [4] Fetch login form
print(f"\n[4] Auth page / login form")
auth_url   = f"{KC_AUTH_URL}?client_id={CLIENT_ID}&request_uri={urllib.parse.quote(request_uri)}"
login_resp = session.get(auth_url, allow_redirects=True)
print(f"    {login_resp.status_code}  {login_resp.url[:90]}")

fp = FormParser()
fp.feed(login_resp.text)
if not fp.action:
    err("Could not parse login form")
ok(f"Form action: {fp.action[:60]}...")

# [5] POST credentials — must manually carry cookies (Python won't send for .localhost)
print(f"\n[5] POST credentials ({USERNAME})")
cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
data       = dict(fp.fields)
data["username"] = USERNAME
data["password"] = PASSWORD

post_resp = requests.post(
    fp.action, data=data,
    headers={"Cookie": cookie_hdr},
    allow_redirects=False
)
print(f"    {post_resp.status_code}  Location={post_resp.headers.get('Location','NONE')[:100]}")
if post_resp.status_code not in (301, 302, 303, 307, 308):
    err(f"Login POST did not redirect: {post_resp.status_code}")

loc     = post_resp.headers.get("Location", "")
params  = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
if "error" in params:
    err(f"Auth error: {params}")
if "code" not in params:
    err(f"No code in redirect: {loc[:200]}")

auth_code = params["code"][0]
ok(f"auth_code={auth_code[:20]}...")

# [6] Token exchange with DPoP
print(f"\n[6] Token exchange (DPoP)")
dpop1     = make_dpop_proof(private_key, jwk, "POST", KC_TOKEN_URL)
tok_resp  = requests.post(KC_TOKEN_URL, data={
    "grant_type":    "authorization_code",
    "client_id":     CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "code":          auth_code,
    "redirect_uri":  REDIRECT_URI,
    "code_verifier": verifier,
}, headers={"DPoP": dpop1})
print(f"    {tok_resp.status_code}")
if tok_resp.status_code != 200:
    print(f"    {tok_resp.text[:400]}")
    err("Token exchange failed")

token_data   = tok_resp.json()
access_token = token_data.get("access_token", "")
if not access_token:
    err(f"No access_token: {token_data}")

# Decode payload
pad      = "=" * (4 - len(access_token.split(".")[1]) % 4)
tp       = json.loads(base64.urlsafe_b64decode(access_token.split(".")[1] + pad))
token_jkt= tp.get("cnf", {}).get("jkt", "MISSING")
print(f"    token_type={token_data.get('token_type')}  cnf.jkt={token_jkt}")

if token_jkt == "MISSING":
    err("cnf.jkt missing - DPoP not bound!")
if token_jkt != jkt:
    err(f"jkt mismatch: expected={jkt}  got={token_jkt}")
ok("DPoP-bound token  cnf.jkt ✓")

# [7] Kong API call WITH DPoP proof → expect 200
print(f"\n[7] GET {KONG_URL}  (with DPoP proof)")
dpop2    = make_dpop_proof(private_key, jwk, "GET", KONG_URL, access_token=access_token)
api_resp = requests.get(KONG_URL, headers={
    "Authorization": f"DPoP {access_token}",
    "DPoP":          dpop2,
})
print(f"    {api_resp.status_code}")
if api_resp.status_code == 200:
    ok("Kong accepted DPoP request → 200 OK")
    try:
        body = api_resp.json()
        print(f"    url seen by httpbin: {body.get('url','?')}")
    except Exception:
        pass
else:
    print(f"    {api_resp.text[:400]}")
    err("Kong rejected valid DPoP request")

# [8] Kong API call WITHOUT DPoP proof → expect 401/403
print(f"\n[8] GET {KONG_URL}  (no DPoP proof — must be rejected)")
no_dpop = requests.get(KONG_URL, headers={"Authorization": f"DPoP {access_token}"})
print(f"    {no_dpop.status_code}")
if no_dpop.status_code in (401, 403):
    ok(f"Kong rejected missing DPoP → {no_dpop.status_code} ✓")
else:
    print(f"    {no_dpop.text[:300]}")
    err(f"Expected 401/403, got {no_dpop.status_code}")

print("\n" + "=" * 60)
print("  ALL CHECKS PASSED — FAPI 2.0 DPoP verified!")
print("=" * 60)
