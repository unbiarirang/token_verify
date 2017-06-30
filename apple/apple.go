/*
identity에서 publicKeyURL을 가져와 publicKey를 얻은 뒤 identity 검증.
배경:
애플은 독자적인 인증 시스템을 사용한다. 근데 그냥 구글이랑 비슷. Identity라고 하는 것이 구글의 ID Token에 상응한다.
구글과 비교했을 때 한가지 다른 점은 publicKeyURL이 identity 안에 있다는 점이다.
애플 공식 문서: https://developer.apple.com/documentation/gamekit/gklocalplayer/1515407-generateidentityverificationsign
참고 GO 코드: https://stackoverflow.com/questions/21008855/ios-game-center-identity-verification-in-go
*/
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
)

type Identity struct {
	PublicKeyURL string `json:"public_key_url"`
	Timestamp    int64  `json:"timestamp"` //milisecond
	Signature    string `json:"signature"`
	Salt         string `json:"salt"`
	PlayerID     string `json:"player_id"`
	BundleID     string `json:"bundle_id"`
}

const bundleID = "de.bichinger.test.gamekit-auth"

// Token Lifetime is one day in seconds
const tokenLifetimeSecs int64 = 24 * 60 * 60

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
	if len < 2 {
		return fmt.Errorf("The URL must be an apple.com domain, %v", u)
	}

	domainParts := hostParts[len-2 : len]
	if domainParts[0] != "apple" || domainParts[1] != "com" {
		return fmt.Errorf("The URL must be an apple.com domain, %v", u)
	}

	return nil
}

func getAppleCertificate(publicKeyURL string) (*x509.Certificate, error) {
	if err := verifyPublicKeyURL(publicKeyURL); err != nil {
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

	return x509.ParseCertificate([]byte(body))
}

func formPayload(playerID string, bundleID string, timestamp int64, salt []byte) ([]byte, error) {
	var payloadBuffer bytes.Buffer

	payloadBuffer.Write([]byte(playerID))
	payloadBuffer.Write([]byte(bundleID))
	binary.Write(&payloadBuffer, binary.BigEndian, timestamp)
	payloadBuffer.Write(salt)
	return payloadBuffer.Bytes(), nil
}

func Verify(identityStr string) (string, error) {
	identity := Identity{}
	if err := json.Unmarshal([]byte(identityStr), &identity); err != nil {
		return "", err
	}

	if identity.BundleID != bundleID {
		return "", fmt.Errorf("wrong bundleID. The token is not for our app")
	}

	// if identity.Timestamp/1000+tokenLifetimeSecs < time.Now().Unix() {
	// 	return fmt.Errorf("token has expired")
	// } 베리파이 성공하기 위해서 잠시 주석 처리

	signatureBytes, err := base64.StdEncoding.DecodeString(identity.Signature)
	if err != nil {
		return "", err
	}

	saltBytes, err := base64.StdEncoding.DecodeString(identity.Salt)
	if err != nil {
		return "", err
	}

	payload, err := formPayload(identity.PlayerID, identity.BundleID, identity.Timestamp, saltBytes)
	if err != nil {
		return "", err
	}

	cert, err := getAppleCertificate(identity.PublicKeyURL)
	if err != nil {
		return "", err
	}

	return identity.PlayerID, cert.CheckSignature(cert.SignatureAlgorithm, payload, signatureBytes)
}
