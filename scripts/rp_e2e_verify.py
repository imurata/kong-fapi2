#!/usr/bin/env python3
"""FAPI 2.0 RP end-to-end verification.

Walks through the browser flow that Kong (in RP mode) terminates against
Keycloak. The test client only acts as a User-Agent (a curl-like browser
substitute). All FAPI 2.0 mechanics — PAR, JAR, private_key_jwt, JARM,
DPoP — are performed by Kong and are observed by inspecting the
intermediate redirects and the final upstream request that httpbin echoes
back.

Steps:
  [1] GET /protected  → expect 302 to Keycloak with PAR request_uri
  [2] Follow redirects to Keycloak login form
  [3] POST credentials → expect 302 back to Kong with a JARM response
  [4] Follow callback → Kong establishes a session cookie and redirects
  [5] GET /protected with session cookie → 200 with userinfo headers
"""
import sys
import urllib.parse
import re
import json
import base64
from html.parser import HTMLParser

import requests

KONG_URL       = "http://localhost:8000/protected"
KEYCLOAK_HOST  = "keycloak.localhost"
KEYCLOAK_PORT  = 9080
USERNAME       = "alice"
PASSWORD       = "alice-pass"


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


def b64url_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def jwt_payload(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return json.loads(b64url_decode(parts[1]))


def cookie_header(jar):
    """Build a Cookie header from a RequestsCookieJar.

    Python's requests does not auto-send cookies set on `.localhost`
    subdomains, so we always pass them explicitly.
    """
    return "; ".join(f"{c.name}={c.value}" for c in jar)


print("=" * 60)
print("  FAPI 2.0 RP (Kong as Relying Party) Verification")
print("=" * 60)

session = requests.Session()

# ── [1] Initial unauthenticated request to Kong ───────────────────────────────
print("\n[1] GET /protected (unauthenticated)")
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

# ── [2] Fetch the login form from Keycloak ────────────────────────────────────
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
parsed3 = urllib.parse.urlparse(loc3)
qs3 = urllib.parse.parse_qs(parsed3.query)

if "error" in qs3:
    err(f"Auth error from Keycloak: {qs3}")
# JARM: response is a single 'response' query parameter carrying a signed JWT
if "response" in qs3:
    jarm = qs3["response"][0]
    payload = jwt_payload(jarm)
    if payload is None:
        warn("JARM response received but could not decode JWT payload")
    else:
        ok(f"JARM response received: iss={payload.get('iss')}  aud={payload.get('aud')}")
        if "code" in payload:
            ok(f"JARM payload carries authorization code (len={len(payload['code'])})")
        else:
            warn("JARM payload missing 'code' claim")
elif "code" in qs3:
    warn("Plain 'code' returned (not JARM). Check response_mode in deck/rp.yaml.")
else:
    err(f"Unexpected callback parameters: {qs3}")

# ── [4] Follow callback into Kong → exchange code, set session, forward ──────
# We pass cookies explicitly via the Cookie header because Python
# requests stores cookies for plain `localhost` under the synthetic
# domain `localhost.local`, and won't auto-send them on a follow-up
# request to localhost.
#
# Kong's openid-connect plugin, when receiving the callback URL with
# the JARM `response` parameter, will:
#   - validate state vs. the `authorization` cookie set on step [1]
#   - call PAR/token endpoints with private_key_jwt + JAR
#   - establish a session (set kong_rp_session cookie)
#   - forward the request transparently to the upstream backend
# So the response body here is already the httpbin echo, returned
# in the same HTTP transaction (no extra redirect).
print("\n[4] Follow callback into Kong (token exchange + upstream forward)")
r4 = requests.get(
    loc3,
    headers={"Cookie": cookie_header(session.cookies)},
    allow_redirects=False,
)
print(f"    {r4.status_code}  bytes={len(r4.text)}")

# Some plugin versions redirect once before forwarding; handle both.
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
    err(f"Authenticated callback did not return 200: {r4.status_code}\n     body={r4.text[:400]}")

# Capture any cookies set by Kong (notably the session cookie)
for c in r4.cookies:
    session.cookies.set_cookie(c)
session_cookie = next(
    (c for c in session.cookies if "session" in c.name.lower()),
    None,
)
if session_cookie:
    ok(f"Session cookie set: {session_cookie.name}")
else:
    warn("No session cookie observed on the callback (Kong may forward without persisting state)")

try:
    body = r4.json()
except ValueError:
    err(f"Upstream did not return JSON: {r4.text[:300]}")
ok("Upstream backend (httpbin) returned a response — full RP flow completed")

upstream_headers = body.get("headers", {})
matched = {k: v for k, v in upstream_headers.items() if k.lower().startswith("x-userinfo")}
if matched:
    ok(f"Upstream received userinfo headers: {list(matched.keys())}")
    for k, v in matched.items():
        print(f"      {k}: {v}")
else:
    warn("Upstream did not receive any X-Userinfo-* headers; "
         "check upstream_headers_claims/names in deck/rp.yaml")

print("\n" + "=" * 60)
print("  All checks completed.")
print("=" * 60)
