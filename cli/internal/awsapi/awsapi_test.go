package awsapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Official AWS SigV4 example (IAM ListUsers, 2015-08-30T12:36:00Z).
func TestSigV4MatchesAWSDocumentationVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	Sign(req, nil, Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}, "us-east-1", "iam", now)

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("signature mismatch\n got: %s\nwant: %s", got, want)
	}
}

func fakeSTS(t *testing.T, check func(url.Values, *http.Request), reply string, status int) *STS {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(b))
		if check != nil {
			check(vals, r)
		}
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return &STS{Region: "us-east-1", Endpoint: srv.URL + "/"}
}

const credsXML = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials>
<AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken>
<Expiration>2026-11-01T10:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`

func TestAssumeRoleSendsMFAAndParsesCredentials(t *testing.T) {
	sts := fakeSTS(t, func(v url.Values, r *http.Request) {
		if v.Get("Action") != "AssumeRole" || v.Get("RoleArn") != "arn:aws:iam::123456789012:role/Admin" ||
			v.Get("SerialNumber") != "arn:aws:iam::123456789012:mfa/me" || v.Get("TokenCode") != "123456" ||
			v.Get("DurationSeconds") != "3600" {
			t.Errorf("unexpected params: %v", v)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIATEST/") {
			t.Errorf("request not signed: %q", r.Header.Get("Authorization"))
		}
	}, credsXML, 200)
	c, err := sts.AssumeRole(Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: "s"},
		"arn:aws:iam::123456789012:role/Admin", "cervus-test", time.Hour,
		"arn:aws:iam::123456789012:mfa/me", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "ASIAEXAMPLE" || c.SessionToken != "token" || c.Expiration.Year() != 2026 {
		t.Fatalf("bad credentials: %+v", c)
	}
}

func TestSessionTokenSigningIncludesSecurityToken(t *testing.T) {
	sts := fakeSTS(t, func(v url.Values, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "x-amz-security-token") ||
			r.Header.Get("X-Amz-Security-Token") != "tok" {
			t.Errorf("security token not signed: %v", r.Header)
		}
	}, strings.ReplaceAll(strings.ReplaceAll(credsXML, "AssumeRole", "GetSessionToken"), "GetSessionTokenResult", "GetSessionTokenResult"), 200)
	if _, err := sts.GetSessionToken(Credentials{AccessKeyID: "ASIA", SecretAccessKey: "s", SessionToken: "tok"}, time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestAPIErrorIsParsed(t *testing.T) {
	sts := fakeSTS(t, nil, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>nope</Message></Error></ErrorResponse>`, 403)
	_, _, err := sts.GetCallerIdentity(Credentials{AccessKeyID: "A", SecretAccessKey: "s"})
	ae, ok := err.(*APIError)
	if !ok || ae.Code != "AccessDenied" || ae.Message != "nope" || ae.Status != 403 {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestGetCallerIdentity(t *testing.T) {
	sts := fakeSTS(t, nil, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/me</Arn><UserId>X</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, 200)
	arn, acct, err := sts.GetCallerIdentity(Credentials{AccessKeyID: "A", SecretAccessKey: "s"})
	if err != nil || arn != "arn:aws:iam::123456789012:user/me" || acct != "123456789012" {
		t.Fatalf("got %q %q %v", arn, acct, err)
	}
}
