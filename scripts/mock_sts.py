#!/usr/bin/env python3
"""Tiny fake AWS STS for end-to-end tests. Usage: mock_sts.py <port-file> <log-file>
It computes TOTP independently of Cervus, so MFA codes are cross-checked."""
import base64, hashlib, hmac, http.server, json, struct, sys, time, urllib.parse

SEED = base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
PORT_FILE, LOG = sys.argv[1], sys.argv[2]

def totp(t):
    h = hmac.new(SEED, struct.pack(">Q", t // 30), hashlib.sha1).digest()
    o = h[19] & 15
    n = struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF
    return "%06d" % (n % 1000000)

def iso(secs):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + secs))

def creds_xml(action, key, token, secs):
    return ('<%sResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><%sResult><Credentials>'
            '<AccessKeyId>%s</AccessKeyId><SecretAccessKey>SECRET-%s</SecretAccessKey>'
            '<SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials></%sResult></%sResponse>'
            % (action, action, key, key, token, iso(secs), action, action))

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def reply(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def err(self, status, code, msg):
        self.reply(status, "<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error></ErrorResponse>" % (code, msg))

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        q = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
        auth = self.headers.get("Authorization", "")
        key = auth.split("Credential=")[1].split("/")[0] if "Credential=" in auth else ""
        rec = dict(action=q.get("Action"), key=key, serial=q.get("SerialNumber"), code=q.get("TokenCode"),
                   duration=q.get("DurationSeconds"), role=q.get("RoleArn"),
                   signed=auth.startswith("AWS4-HMAC-SHA256") and "Signature=" in auth,
                   token=self.headers.get("X-Amz-Security-Token"))
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")

        try:
            with open(LOG + ".revoked") as f:
                if key in f.read().split():
                    return self.err(403, "InvalidClientTokenId", "The security token included in the request is invalid.")
        except FileNotFoundError:
            pass
        if not (key in ("AKIATESTKEY", "AKIANEWKEY", "AKIAOTHERUSER", "ASIASESSION") or key.startswith("ASIAROLE")):
            return self.err(403, "InvalidClientTokenId", "The security token included in the request is invalid.")
        if q.get("SerialNumber") and q.get("TokenCode") != totp(int(time.time())):
            return self.err(403, "AccessDenied", "MultiFactorAuthentication failed with invalid MFA one time pass code.")

        action = q.get("Action")
        if action == "GetCallerIdentity" and key == "AKIAOTHERUSER":
            return self.reply(200, "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/other</Arn>"
                                   "<UserId>AIDAOTHER</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>")
        if action == "GetCallerIdentity":
            return self.reply(200, "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/tester</Arn>"
                                   "<UserId>AIDATEST</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>")
        if action == "GetSessionToken":
            return self.reply(200, creds_xml("GetSessionToken", "ASIASESSION", "TOKSESSION", int(q.get("DurationSeconds", "3600"))))
        if action == "AssumeRole":
            name = q["RoleArn"].split("role/")[1]
            if name == "Denied":
                return self.err(403, "AccessDenied", "User is not authorized to perform: sts:AssumeRole")
            secs = 120 if name == "Short" else int(q.get("DurationSeconds", "3600"))
            return self.reply(200, creds_xml("AssumeRole", "ASIAROLE" + name, "TOK-" + name, secs))
        self.err(400, "InvalidAction", "unknown action")

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(PORT_FILE, "w").write(str(srv.server_address[1]))
srv.serve_forever()
