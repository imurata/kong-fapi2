#!/usr/bin/env python3
"""FAPI 2.0 RP × mTLS end-to-end verification.

Identical structure to rp_e2e_verify.py but expects:
  - the kong-rp-mtls-client (client-x509 + cert-bound tokens)
  - Kong using tls_client_auth against Keycloak's HTTPS port 9443
  - access tokens carrying `cnf.x5t#S256` matching the client cert

Steps:
  [1] GET /protected-mtls    → 302 to Keycloak (PAR)
  [2] Login form
  [3] POST credentials       → 302 callback to Kong
  [4] Callback into Kong     → mTLS to Keycloak token endpoint,
                               cert-bound token issued, session set,
                               request forwarded to upstream
  [5] Inspect introspection  → confirm cnf.x5t#S256 matches the
                               Kong client cert SHA-256 thumbprint
"""
import sys
import urllib.parse
import json
import base64
import hashlib
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import requests

KONG_URL          = "http://localhost:8000/protected-mtls"
KEYCLOAK_HOST     = "keycloak.localhost"
USERNAME          = "alice"
PASSWORD          = "alice-pass"

# Kong RP mTLS client certificate (used both by Kong against Keycloak
# AND here to compute the expected cnf.x5t#S256 thumbprint).
CLIENT_CERT = Path(__file__).resolve().parent.parent / "tls" / "kong-rp-mtls-cert.pem"

# Keycloak admin endpoint used to introspect the issued access token
# (so we can read its `cnf.x5t#S256` claim and prove the token is
# certificate-bound).
INTROSPECT_URL    = "http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/token/introspect"
INTROSPECT_CLIENT = "kong"
INTROSPECT_SECRET = "kong-secret"


def ok(msg):  print(f"  ✓ {msg}")
def warn(msg): print(f"  ⚠ {msg}")
def err(msg): print(f"  ✗ {msg}"); sys.exit(1)


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


def cookie_header(jar):
    return "; ".join(f"{c.name}={c.value}" for c in jar)


def b64url_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def cert_thumbprint_b64url(cert_path: Path) -> str:
    """Compute the JWT-style cnf.x5t#S256 of an X.509 cert.

    RFC 8705 §3.1 defines this as the SHA-256 hash of the DER-encoded
    certificate, base64url-encoded without padding.
    """
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"]
    )
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


print("=" * 60)
print("  FAPI 2.0 RP × mTLS Verification")
print("=" * 60)

session = requests.Session()

# ── [1] Initial unauthenticated request to Kong ───────────────────────────────
print("\n[1] GET /protected-mtls (unauthenticated)")
r1 = session.get(KONG_URL, allow_redirects=False)
print(f"    {r1.status_code}  Location={r1.headers.get('Location', '')[:120]}")
if r1.status_code not in (301, 302, 303, 307, 308):
    err(f"Expected redirect to Keycloak, got {r1.status_code}\n     body={r1.text[:300]}")

loc1 = r1.headers["Location"]
parsed1 = urllib.parse.urlparse(loc1)
qs1 = urllib.parse.parse_qs(parsed1.query)
if "request_uri" not in qs1:
    err(f"PAR not used: no request_uri in authorize redirect\n     location={loc1}")
ok(f"PAR engaged: request_uri={qs1['request_uri'][0][:40]}...")
if KEYCLOAK_HOST not in parsed1.netloc:
    err(f"Authorize redirect points away from Keycloak: {parsed1.netloc}")
ok(f"Authorize URL points to Keycloak: {parsed1.netloc}{parsed1.path}")

# ── [2] Fetch Keycloak login form ─────────────────────────────────────────────
print("\n[2] Fetch Keycloak login form")
r2 = session.get(loc1, allow_redirects=True)
print(f"    {r2.status_code}  {r2.url[:90]}")
if r2.status_code != 200:
    err(f"Login form fetch failed: {r2.status_code}")

fp = FormParser()
fp.feed(r2.text)
if not fp.action:
    err("Could not parse Keycloak login form")
ok(f"Form action: {fp.action[:80]}...")

# ── [3] Submit credentials ────────────────────────────────────────────────────
print(f"\n[3] POST credentials ({USERNAME})")
data = dict(fp.fields)
data["username"] = USERNAME
data["password"] = PASSWORD

r3 = requests.post(
    fp.action,
    data=data,
    headers={"Cookie": cookie_header(session.cookies)},
    allow_redirects=False,
)
print(f"    {r3.status_code}  Location={r3.headers.get('Location', '')[:140]}")
if r3.status_code not in (301, 302, 303, 307, 308):
    err(f"Login POST did not redirect: {r3.status_code}\n     body={r3.text[:300]}")

loc3 = r3.headers["Location"]
qs3 = urllib.parse.parse_qs(urllib.parse.urlparse(loc3).query)
if "error" in qs3:
    err(f"Auth error from Keycloak: {qs3}")

# ── [4] Follow callback into Kong → mTLS token exchange + upstream forward ───
print("\n[4] Follow callback into Kong (mTLS token exchange + upstream forward)")
r4 = requests.get(
    loc3,
    headers={"Cookie": cookie_header(session.cookies)},
    allow_redirects=False,
)
print(f"    {r4.status_code}  bytes={len(r4.text)}")

if r4.status_code in (301, 302, 303, 307, 308):
    for c in r4.cookies:
        session.cookies.set_cookie(c)
    r4 = requests.get(
        r4.headers["Location"],
        headers={"Cookie": cookie_header(session.cookies)},
        allow_redirects=False,
    )
    print(f"    follow-up: {r4.status_code}  bytes={len(r4.text)}")

if r4.status_code != 200:
    err(f"Authenticated callback did not return 200: {r4.status_code}\n     body={r4.text[:500]}")

try:
    body = r4.json()
except ValueError:
    err(f"Upstream did not return JSON: {r4.text[:300]}")
ok("Upstream backend (httpbin) returned a response — full RP flow completed")

upstream_headers = body.get("headers", {})
matched = {k: v for k, v in upstream_headers.items() if k.lower().startswith("x-userinfo")}
if matched:
    ok(f"Upstream received userinfo headers: {sorted(matched.keys())}")
else:
    warn("Upstream did not receive any X-Userinfo-* headers")

# Extract the access token forwarded to the upstream so we can
# introspect it on the next step.
forwarded_auth = upstream_headers.get("Authorization", "")
if not forwarded_auth.startswith("Bearer "):
    err(f"Upstream Authorization header is not a Bearer token: {forwarded_auth[:80]}")
access_token = forwarded_auth.split(" ", 1)[1]
ok(f"access_token forwarded to upstream (len={len(access_token)})")

# ── [5] Confirm the access token is certificate-bound (cnf.x5t#S256) ─────────
print("\n[5] Introspect access_token and check cnf.x5t#S256")
expected_thumb = cert_thumbprint_b64url(CLIENT_CERT)
ok(f"Kong client cert SHA-256 thumbprint (b64url): {expected_thumb}")

intro = requests.post(
    INTROSPECT_URL,
    data={
        "client_id": INTROSPECT_CLIENT,
        "client_secret": INTROSPECT_SECRET,
        "token": access_token,
    },
)
if intro.status_code != 200:
    err(f"Introspection failed: {intro.status_code}\n     body={intro.text[:300]}")

intro_body = intro.json()
if not intro_body.get("active"):
    err(f"Introspection says token is inactive: {intro_body}")

cnf = intro_body.get("cnf") or {}
actual_thumb = cnf.get("x5t#S256")
if not actual_thumb:
    err(f"Token has no cnf.x5t#S256 claim — it is NOT certificate-bound. "
        f"introspection: {json.dumps(intro_body, indent=2)[:600]}")

if actual_thumb == expected_thumb:
    ok(f"cnf.x5t#S256 == client cert thumbprint  → token is sender-constrained ✓")
else:
    err(f"cnf.x5t#S256 mismatch.\n"
        f"  expected: {expected_thumb}\n"
        f"  got:      {actual_thumb}")

print("\n" + "=" * 60)
print("  All checks completed — Kong RP issued an mTLS-bound token.")
print("=" * 60)
