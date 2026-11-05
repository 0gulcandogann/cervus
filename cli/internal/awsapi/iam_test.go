package awsapi

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestDecodeMFASeedAcceptsTheEncodingAWSUses(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte(testSeed))
	for _, in := range []string{wrapped, testSeed} {
		got, err := decodeMFASeed(in)
		if err != nil || got != testSeed {
			t.Errorf("decode %q: %q, %v", in, got, err)
		}
	}
	if _, err := decodeMFASeed("not a seed!"); err == nil {
		t.Error("garbage must be refused")
	}
}

func TestIAMCallsAreSignedForIAMAndCarryTheRightValues(t *testing.T) {
	var forms []url.Values
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(body))
		forms = append(forms, q)
		auths = append(auths, r.Header.Get("Authorization"))
		if q.Get("Action") == "CreateVirtualMFADevice" {
			w.Write([]byte(`<CreateVirtualMFADeviceResponse><CreateVirtualMFADeviceResult><VirtualMFADevice><SerialNumber>arn:aws:iam::123456789012:mfa/d</SerialNumber><Base32StringSeed>` +
				base64.StdEncoding.EncodeToString([]byte(testSeed)) + `</Base32StringSeed></VirtualMFADevice></CreateVirtualMFADeviceResult></CreateVirtualMFADeviceResponse>`))
			return
		}
		w.Write([]byte(`<Ok/>`))
	}))
	defer srv.Close()
	iam := &IAM{Endpoint: srv.URL + "/"}
	c := Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: "s"}
	serial, seed, err := iam.CreateVirtualMFADevice(c, "d")
	if err != nil || serial != "arn:aws:iam::123456789012:mfa/d" || seed != testSeed {
		t.Fatalf("%q %q %v", serial, seed, err)
	}
	if err := iam.EnableMFADevice(c, "alice", serial, "111111", "222222"); err != nil {
		t.Fatal(err)
	}
	if err := iam.DeleteVirtualMFADevice(c, serial); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(auths[0], "/us-east-1/iam/aws4_request") {
		t.Errorf("signed for the wrong service: %s", auths[0])
	}
	e := forms[1]
	if e.Get("UserName") != "alice" || e.Get("SerialNumber") != serial || e.Get("AuthenticationCode1") != "111111" || e.Get("AuthenticationCode2") != "222222" || e.Get("Version") != "2010-05-08" {
		t.Errorf("enable form: %v", e)
	}
	if forms[2].Get("Action") != "DeleteVirtualMFADevice" {
		t.Errorf("delete form: %v", forms[2])
	}
}

func TestIAMErrorsKeepTheirCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`))
	}))
	defer srv.Close()
	_, _, err := (&IAM{Endpoint: srv.URL + "/"}).CreateVirtualMFADevice(Credentials{AccessKeyID: "A", SecretAccessKey: "s"}, "d")
	if ae, ok := err.(*APIError); !ok || ae.Code != "AccessDenied" {
		t.Fatalf("got %v", err)
	}
}

func TestUserNameFromARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::123456789012:user/alice":          "alice",
		"arn:aws:iam::123456789012:user/team/ops/alice": "alice",
		"arn:aws:iam::123456789012:root":                "",
		"arn:aws:sts::123456789012:assumed-role/r/s":    "",
	}
	for arn, want := range cases {
		if got := UserNameFromARN(arn); got != want {
			t.Errorf("%s: %q", arn, got)
		}
	}
}
