package apple

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	verifier "work/verify"
)

type Identity struct {
	PublicKeyURL string `json:"public_key_url"`
	Timestamp    uint64 `json:"timestamp"`
	Signature    string `json:"signature"`
	Salt         string `json:"salt"`
	PlayerID     string `json:"player_id"`
	BundleID     string `json:"bundle_id"`
}

func init() {
	verifier.Register("A", verify)
}

func verifyPublicKeyURL(u string) error {
	url, err := url.Parse(u)
	if err != nil {
		return err
	}

	if url.Scheme != "https" {
		return fmt.Errorf("It's not https, %v", u)
	}

	hostParts := strings.Split(url.Host, ".")
	len := len(hostParts)
	domainParts := hostParts[len-2 : len]

	if domainParts[0] != "apple" || domainParts[1] != "com" {
		return fmt.Errorf("The URL must be an apple.com domain, %v", u)
	}

	return nil
}

func getAppleCertificate(publicKeyURL string) (*x509.Certificate, error) {
	err := verifyPublicKeyURL(publicKeyURL)
	if err != nil {
		return nil, err
	}

	res, err := http.Get(publicKeyURL)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate([]byte(body))
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func formPayload(playerID string, bundleID string, timestamp uint64, salt []byte) ([]byte, error) {
	playerIDBytes := []byte(playerID)
	bundleIDBytes := []byte(bundleID)

	payloadBuffer := new(bytes.Buffer)

	written, err := payloadBuffer.Write(playerIDBytes)
	if err != nil {
		return nil, err
	}
	if written != len(playerIDBytes) {
		return nil, fmt.Errorf("Failed writing all bytes. Written: %d Length: %d", written, len(playerIDBytes))
	}

	written, err = payloadBuffer.Write(bundleIDBytes)
	if err != nil {
		return nil, err
	}
	if written != len(bundleIDBytes) {
		return nil, fmt.Errorf("Failed writing all bytes. Written: %d Length: %d", written, len(bundleIDBytes))
	}

	bigEndianTimestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(bigEndianTimestamp, timestamp)

	written, err = payloadBuffer.Write(bigEndianTimestamp)
	if err != nil {
		return nil, err
	}
	if written != len(bigEndianTimestamp) {
		return nil, fmt.Errorf("Failed writing all bytes. Written: %d Length: %d", written, len(bigEndianTimestamp))
	}

	written, err = payloadBuffer.Write(salt)
	if err != nil {
		return nil, err
	}
	if written != len(salt) {
		return nil, fmt.Errorf("Failed writing all bytes. Written: %d Length: %d", written, len(salt))
	}

	return payloadBuffer.Bytes(), nil
}

func verify(identityStr string) error {
	identity := new(Identity)
	err := json.Unmarshal([]byte(identityStr), &identity)
	if err != nil {
		return err
	}

	cert, err := getAppleCertificate(identity.PublicKeyURL)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(identity.Signature)
	saltBytes, err := base64.StdEncoding.DecodeString(identity.Salt)

	payload, err := formPayload(identity.PlayerID, identity.BundleID, identity.Timestamp, saltBytes)
	if err != nil {
		return err
	}

	err = cert.CheckSignature(cert.SignatureAlgorithm, payload, signatureBytes)
	if err != nil {
		return err
	}

	return nil
}
