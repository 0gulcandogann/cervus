package awsapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSSOLoginNeeded means the sign-in has ended, and only the person can start a new one.
var ErrSSOLoginNeeded = errors.New("the SSO sign-in has expired")

// Device-flow answers while the person has not finished in the browser.
var (
	ErrSSOPending  = errors.New("authorization_pending")
	ErrSSOSlowDown = errors.New("slow_down")
)

// SSO is the small part of IAM Identity Center that signing in and getting role credentials needs.
type SSO struct {
	Region   string
	Endpoint string // optional override for both services, used by tests
	HTTP     *http.Client
}

func (s *SSO) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *SSO) oidc(path string) string {
	if s.Endpoint != "" {
		return strings.TrimRight(s.Endpoint, "/") + "/" + path
	}
	return fmt.Sprintf("https://oidc.%s.amazonaws.com/%s", s.Region, path)
}

func (s *SSO) portal(path string) string {
	if s.Endpoint != "" {
		return strings.TrimRight(s.Endpoint, "/") + "/" + path
	}
	return fmt.Sprintf("https://portal.sso.%s.amazonaws.com/%s", s.Region, path)
}

// postJSON sends a request and decodes a 2xx reply. An error reply comes back as its "error" field.
func (s *SSO) postJSON(url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	resp, err := s.client().Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot reach AWS IAM Identity Center: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &APIError{Code: e.Error, Message: "IAM Identity Center refused the request", Status: resp.StatusCode}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("unexpected IAM Identity Center response")
	}
	return nil
}

// SSOClient is the registration of this program with IAM Identity Center.
type SSOClient struct {
	ID     string `json:"clientId"`
	Secret string `json:"clientSecret"`
}

func (s *SSO) RegisterClient() (SSOClient, error) {
	var c SSOClient
	err := s.postJSON(s.oidc("client/register"), map[string]string{"clientName": "cervus", "clientType": "public"}, &c)
	if err == nil && (c.ID == "" || c.Secret == "") {
		err = errors.New("unexpected IAM Identity Center response")
	}
	return c, err
}

// SSODevice is a sign-in waiting for the person to approve it in a browser.
type SSODevice struct {
	DeviceCode      string `json:"deviceCode"`
	UserCode        string `json:"userCode"`
	VerificationURI string `json:"verificationUriComplete"`
	ExpiresIn       int    `json:"expiresIn"`
	Interval        int    `json:"interval"`
}

func (s *SSO) StartDeviceAuthorization(c SSOClient, startURL string) (SSODevice, error) {
	var d SSODevice
	err := s.postJSON(s.oidc("device_authorization"), map[string]string{
		"clientId": c.ID, "clientSecret": c.Secret, "startUrl": startURL,
	}, &d)
	if err == nil && (d.DeviceCode == "" || d.VerificationURI == "") {
		err = errors.New("unexpected IAM Identity Center response")
	}
	return d, err
}

// CreateToken asks whether the sign-in was approved. It returns ErrSSOPending or ErrSSOSlowDown until then.
func (s *SSO) CreateToken(c SSOClient, deviceCode string) (token string, expiresIn int, err error) {
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	err = s.postJSON(s.oidc("token"), map[string]string{
		"clientId": c.ID, "clientSecret": c.Secret, "deviceCode": deviceCode,
		"grantType": "urn:ietf:params:oauth:grant-type:device_code",
	}, &out)
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.Code {
		case "authorization_pending":
			return "", 0, ErrSSOPending
		case "slow_down":
			return "", 0, ErrSSOSlowDown
		}
	}
	if err != nil {
		return "", 0, err
	}
	if out.AccessToken == "" {
		return "", 0, errors.New("unexpected IAM Identity Center response")
	}
	return out.AccessToken, out.ExpiresIn, nil
}

// RoleCredentials trades the sign-in token for short-lived credentials of one account and role.
func (s *SSO) RoleCredentials(token, account, role string) (Credentials, error) {
	q := url.Values{"account_id": {account}, "role_name": {role}}
	req, err := http.NewRequest(http.MethodGet, s.portal("federation/credentials")+"?"+q.Encode(), nil)
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("x-amz-sso_bearer_token", token)
	resp, err := s.client().Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("cannot reach AWS IAM Identity Center: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Credentials{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return Credentials{}, ErrSSOLoginNeeded
	}
	if resp.StatusCode/100 != 2 {
		return Credentials{}, &APIError{Code: "SSOError", Message: fmt.Sprintf("role %q in account %s: %s", role, account, resp.Status), Status: resp.StatusCode}
	}
	var out struct {
		C struct {
			AccessKeyID     string `json:"accessKeyId"`
			SecretAccessKey string `json:"secretAccessKey"`
			SessionToken    string `json:"sessionToken"`
			Expiration      int64  `json:"expiration"`
		} `json:"roleCredentials"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.C.AccessKeyID == "" || out.C.SecretAccessKey == "" || out.C.Expiration == 0 {
		return Credentials{}, errors.New("unexpected IAM Identity Center response")
	}
	return Credentials{
		AccessKeyID: out.C.AccessKeyID, SecretAccessKey: out.C.SecretAccessKey, SessionToken: out.C.SessionToken,
		Expiration: time.UnixMilli(out.C.Expiration),
	}, nil
}
