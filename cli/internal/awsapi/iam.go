package awsapi

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const iamEndpoint = "https://iam.amazonaws.com/"

var base32SeedRe = regexp.MustCompile(`^[A-Z2-7]{16,128}=*$`)

// IAM is the small part of IAM that enrolling an MFA device needs. IAM is global and is signed for
// us-east-1.
type IAM struct {
	Endpoint string // optional override, used by tests
	HTTP     *http.Client
	Now      func() time.Time
}

func (i *IAM) call(c Credentials, action string, params url.Values) ([]byte, error) {
	params.Set("Action", action)
	params.Set("Version", "2010-05-08")
	endpoint, client := i.Endpoint, i.HTTP
	if endpoint == "" {
		endpoint = iamEndpoint
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	return postSigned(client, endpoint, "us-east-1", "iam", "AWS IAM", c, params, now())
}

// CreateVirtualMFADevice makes a device and returns its serial and base32 seed. The seed is shown by
// AWS only this once.
func (i *IAM) CreateVirtualMFADevice(c Credentials, name string) (serial, seed string, err error) {
	data, err := i.call(c, "CreateVirtualMFADevice", url.Values{"VirtualMFADeviceName": {name}})
	if err != nil {
		return "", "", err
	}
	var r struct {
		Serial string `xml:"CreateVirtualMFADeviceResult>VirtualMFADevice>SerialNumber"`
		Seed   string `xml:"CreateVirtualMFADeviceResult>VirtualMFADevice>Base32StringSeed"`
	}
	if err := xml.Unmarshal(data, &r); err != nil || r.Serial == "" {
		return "", "", errors.New("unexpected IAM response")
	}
	seed, err = decodeMFASeed(r.Seed)
	if err != nil {
		return "", "", err
	}
	return r.Serial, seed, nil
}

// EnableMFADevice ties a device to a user. AWS wants two consecutive codes.
func (i *IAM) EnableMFADevice(c Credentials, user, serial, code1, code2 string) error {
	_, err := i.call(c, "EnableMFADevice", url.Values{
		"UserName": {user}, "SerialNumber": {serial},
		"AuthenticationCode1": {code1}, "AuthenticationCode2": {code2},
	})
	return err
}

func (i *IAM) DeleteVirtualMFADevice(c Credentials, serial string) error {
	_, err := i.call(c, "DeleteVirtualMFADevice", url.Values{"SerialNumber": {serial}})
	return err
}

// decodeMFASeed accepts the seed as the API sends it, a base32 string inside base64, or as plain base32.
// The result is never put in an error: it is a secret.
func decodeMFASeed(s string) (string, error) {
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && base32SeedRe.Match(raw) {
		return strings.TrimRight(string(raw), "="), nil
	}
	if base32SeedRe.MatchString(s) {
		return strings.TrimRight(s, "="), nil
	}
	return "", errors.New("IAM returned an MFA seed in an unknown format")
}

// UserNameFromARN returns the IAM user name in an ARN, or "" for root and anything else that is not a
// user, because those cannot enroll a device this way.
func UserNameFromARN(arn string) string {
	_, rest, ok := strings.Cut(arn, ":user/")
	if !ok {
		return ""
	}
	return rest[strings.LastIndex(rest, "/")+1:]
}
