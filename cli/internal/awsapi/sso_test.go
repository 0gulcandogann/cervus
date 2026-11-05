package awsapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fakeIdentityCenter(t *testing.T, tokenReply func(w http.ResponseWriter)) *SSO {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/client/register", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"clientId":"cid","clientSecret":"csec"}`))
	})
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["startUrl"] != "https://acme.awsapps.com/start" || in["clientId"] != "cid" {
			t.Errorf("device_authorization got %v", in)
		}
		w.Write([]byte(`{"deviceCode":"dev","userCode":"ABCD-EFGH","verificationUriComplete":"https://device.example/?code=ABCD","expiresIn":600,"interval":1}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { tokenReply(w) })
	mux.HandleFunc("/federation/credentials", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-amz-sso_bearer_token") != "tok" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("account_id") != "123456789012" || r.URL.Query().Get("role_name") != "Admin" {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte(`{"roleCredentials":{"accessKeyId":"ASIA","secretAccessKey":"sec","sessionToken":"st","expiration":1893456000000}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &SSO{Region: "eu-west-1", Endpoint: srv.URL + "/"}
}

func TestSSOSignInAndRoleCredentials(t *testing.T) {
	s := fakeIdentityCenter(t, func(w http.ResponseWriter) { w.Write([]byte(`{"accessToken":"tok","expiresIn":28800}`)) })
	c, err := s.RegisterClient()
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.StartDeviceAuthorization(c, "https://acme.awsapps.com/start")
	if err != nil || d.UserCode != "ABCD-EFGH" {
		t.Fatalf("%+v %v", d, err)
	}
	tok, exp, err := s.CreateToken(c, d.DeviceCode)
	if err != nil || tok != "tok" || exp != 28800 {
		t.Fatalf("%q %d %v", tok, exp, err)
	}
	cr, err := s.RoleCredentials(tok, "123456789012", "Admin")
	if err != nil || cr.AccessKeyID != "ASIA" || !cr.Expiration.Equal(time.UnixMilli(1893456000000)) {
		t.Fatalf("%+v %v", cr, err)
	}
}

func TestSSOTokenStates(t *testing.T) {
	for reply, want := range map[string]error{`{"error":"authorization_pending"}`: ErrSSOPending, `{"error":"slow_down"}`: ErrSSOSlowDown} {
		s := fakeIdentityCenter(t, func(w http.ResponseWriter) { w.WriteHeader(400); w.Write([]byte(reply)) })
		if _, _, err := s.CreateToken(SSOClient{"a", "b"}, "d"); !errors.Is(err, want) {
			t.Errorf("%s: %v", reply, err)
		}
	}
	s := fakeIdentityCenter(t, func(w http.ResponseWriter) { w.WriteHeader(400); w.Write([]byte(`{"error":"expired_token"}`)) })
	_, _, err := s.CreateToken(SSOClient{"a", "b"}, "d")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "expired_token" {
		t.Errorf("got %v", err)
	}
}

func TestSSOExpiredTokenAsksForALogin(t *testing.T) {
	s := fakeIdentityCenter(t, nil)
	if _, err := s.RoleCredentials("old", "123456789012", "Admin"); !errors.Is(err, ErrSSOLoginNeeded) {
		t.Fatalf("got %v", err)
	}
}

func TestSSOEndpointsFollowTheRegion(t *testing.T) {
	s := &SSO{Region: "eu-west-1"}
	if got := s.oidc("token"); got != "https://oidc.eu-west-1.amazonaws.com/token" {
		t.Error(got)
	}
	if got := s.portal("federation/credentials"); got != "https://portal.sso.eu-west-1.amazonaws.com/federation/credentials" {
		t.Error(got)
	}
}

func FuzzSSOResponses(f *testing.F) {
	f.Add(200, `{"accessToken":"t","expiresIn":1}`)
	f.Add(400, `{"error":"slow_down"}`)
	f.Add(200, `{"roleCredentials":{"accessKeyId":"A","secretAccessKey":"B","expiration":1}}`)
	f.Add(200, `not json`)
	f.Fuzz(func(t *testing.T, status int, body string) {
		if status < 100 || status > 599 {
			return
		}
		s := &SSO{Region: "us-east-1", HTTP: &http.Client{Transport: cannedResponse{status, body}}}
		_, _ = s.RegisterClient()
		_, _ = s.StartDeviceAuthorization(SSOClient{"a", "b"}, "https://x/start")
		_, _, _ = s.CreateToken(SSOClient{"a", "b"}, "d")
		_, _ = s.RoleCredentials("t", "1", "r")
	})
}
