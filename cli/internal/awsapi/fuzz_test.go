package awsapi

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type cannedResponse struct {
	status int
	body   string
}

func (c cannedResponse) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.body)), Header: http.Header{}}, nil
}

// Whatever comes back from the network, the client returns an error or credentials: it never panics.
func FuzzSTSResponses(f *testing.F) {
	f.Add(200, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>A</AccessKeyId><SecretAccessKey>B</SecretAccessKey><SessionToken>C</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	f.Add(403, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`)
	f.Add(200, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>a</Arn><Account>1</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	f.Add(200, `<<<not xml`)
	f.Fuzz(func(t *testing.T, status int, body string) {
		if status < 100 || status > 599 {
			return
		}
		s := &STS{Region: "us-east-1", HTTP: &http.Client{Transport: cannedResponse{status, body}}}
		base := Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: "secret"}
		c, err := s.AssumeRole(base, "arn:aws:iam::123456789012:role/x", "s", time.Hour, "", "")
		if err == nil && c.AccessKeyID == "" {
			t.Fatalf("success without credentials from %q", body)
		}
		_, _ = s.GetSessionToken(base, time.Hour, "", "")
		_, _, _ = s.GetCallerIdentity(base)
	})
}
