package awsapi

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// STS is a minimal AWS Security Token Service client.
type STS struct {
	Region   string
	Endpoint string // optional override (used by tests); default https://sts.<region>.amazonaws.com/
	HTTP     *http.Client
	Now      func() time.Time
}

// APIError is an error returned by the STS service.
type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string { return fmt.Sprintf("AWS %s: %s", e.Code, e.Message) }

func (s *STS) endpoint() string {
	if s.Endpoint != "" {
		return s.Endpoint
	}
	return fmt.Sprintf("https://sts.%s.amazonaws.com/", s.Region)
}

func (s *STS) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *STS) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *STS) call(c Credentials, params url.Values) ([]byte, error) {
	return postSigned(s.client(), s.endpoint(), s.Region, "sts", "AWS STS", c, params, s.now())
}

// postSigned sends one signed form request and returns the body of a successful reply.
func postSigned(client *http.Client, endpoint, region, service, label string, c Credentials, params url.Values, now time.Time) ([]byte, error) {
	body := []byte(params.Encode())
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	Sign(req, body, c, region, service, now)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", label, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Code    string `xml:"Error>Code"`
			Message string `xml:"Error>Message"`
		}
		if xml.Unmarshal(data, &e) != nil || e.Code == "" {
			e.Code, e.Message = "HTTPError", resp.Status
		}
		return nil, &APIError{Code: e.Code, Message: e.Message, Status: resp.StatusCode}
	}
	return data, nil
}

type xmlCreds struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

func (x xmlCreds) toCredentials() (Credentials, error) {
	exp, err := time.Parse(time.RFC3339, x.Expiration)
	if err != nil || x.AccessKeyID == "" || x.SecretAccessKey == "" {
		return Credentials{}, fmt.Errorf("unexpected STS response")
	}
	return Credentials{
		AccessKeyID: x.AccessKeyID, SecretAccessKey: x.SecretAccessKey,
		SessionToken: x.SessionToken, Expiration: exp,
	}, nil
}

func seconds(d time.Duration) string { return strconv.Itoa(int(d / time.Second)) }

// AssumeRole assumes roleARN using base credentials. mfaSerial/tokenCode are optional.
func (s *STS) AssumeRole(base Credentials, roleARN, sessionName string, d time.Duration, mfaSerial, tokenCode string) (Credentials, error) {
	p := url.Values{}
	p.Set("Action", "AssumeRole")
	p.Set("Version", "2011-06-15")
	p.Set("RoleArn", roleARN)
	p.Set("RoleSessionName", sessionName)
	p.Set("DurationSeconds", seconds(d))
	if mfaSerial != "" {
		p.Set("SerialNumber", mfaSerial)
		p.Set("TokenCode", tokenCode)
	}
	data, err := s.call(base, p)
	if err != nil {
		return Credentials{}, err
	}
	var r struct {
		Creds xmlCreds `xml:"AssumeRoleResult>Credentials"`
	}
	if err := xml.Unmarshal(data, &r); err != nil {
		return Credentials{}, fmt.Errorf("unexpected STS response: %w", err)
	}
	return r.Creds.toCredentials()
}

// GetSessionToken returns temporary credentials for an IAM user, optionally MFA-backed.
func (s *STS) GetSessionToken(base Credentials, d time.Duration, mfaSerial, tokenCode string) (Credentials, error) {
	p := url.Values{}
	p.Set("Action", "GetSessionToken")
	p.Set("Version", "2011-06-15")
	p.Set("DurationSeconds", seconds(d))
	if mfaSerial != "" {
		p.Set("SerialNumber", mfaSerial)
		p.Set("TokenCode", tokenCode)
	}
	data, err := s.call(base, p)
	if err != nil {
		return Credentials{}, err
	}
	var r struct {
		Creds xmlCreds `xml:"GetSessionTokenResult>Credentials"`
	}
	if err := xml.Unmarshal(data, &r); err != nil {
		return Credentials{}, fmt.Errorf("unexpected STS response: %w", err)
	}
	return r.Creds.toCredentials()
}

// GetCallerIdentity reports who the credentials belong to. It needs no IAM permissions.
func (s *STS) GetCallerIdentity(c Credentials) (arn, account string, err error) {
	p := url.Values{}
	p.Set("Action", "GetCallerIdentity")
	p.Set("Version", "2011-06-15")
	data, err := s.call(c, p)
	if err != nil {
		return "", "", err
	}
	var r struct {
		Arn     string `xml:"GetCallerIdentityResult>Arn"`
		Account string `xml:"GetCallerIdentityResult>Account"`
	}
	if err := xml.Unmarshal(data, &r); err != nil || r.Arn == "" {
		return "", "", fmt.Errorf("unexpected STS response")
	}
	return r.Arn, r.Account, nil
}
