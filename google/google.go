/*
googleOauth2CertsURL에서 cert 받아와 로컬에서 idToken 검증. cert는 캐시 사용.
배경:
구글 인증은 원래 OpenID를 지원했다. OAuth가 생긴 뒤 OAuth와 OpenID와 OAuth가 결합한 OpenID Connect를 동시에 지원한다.
즉 Access Token과 ID Token 둘 다 검증에 사용 가능한데 ID Token을 선택한 이유는 첫째 구글이 추천하고 둘째 구글에 매번 질의를 하지 않아도 되기 때문이다.
ID Token은 JWT형식으로 header(envelope), payload, signature 세 부분으로 이루어져 있다.
구글의 퍼블릭 키, header와 payload의 해시값으로 signature를 검증한다.
구글 공식 문서: https://developers.google.com/identity/sign-in/web/backend-auth, https://developers.google.com/identity/protocols/OpenIDConnect
구글 공식 nodejs 인증 라이브러리: https://github.com/google/google-auth-library-nodejs/blob/1956db0f24abf7b7eca36638579da1f343300fb7/ts/lib/auth/oauth2client.ts
참고 GO 코드: https://stackoverflow.com/questions/26159658/golang-token-validation-error
*/
package google

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"google.golang.org/api/oauth2/v2"
)

const googleOauth2CertsURL = "https://www.googleapis.com/oauth2/v3/certs"

//Max Token Lifetime is one day in seconds
const maxTokenLifetimeSecs int64 = 24 * 60 * 60

//Clock skew - five minutes in seconds
const clockSkewSecs = 300

//The allowed oauth token issuers.
var issuers = [2]string{"accounts.google.com", "https://accounts.google.com"}

//The audience to test the jwt against. (clientID)
var requiredAud = [...]string{"520941011008-51nckhjbudbat3eijf0kl0gequnbr0pl.apps.googleusercontent.com"}

var _certificateExpiry time.Time
var _certificateCache *oauth2.Jwk

type Envelope struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type Payload struct {
	Iss    string `json:"iss"`
	AtHash string `json:"at_hash"`
	Azp    string `json:"azp"`
	Aud    string `json:"aud"`
	Sub    string `json:"sub"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

func (p *Payload) verify() error {
	now := time.Now().Unix()

	if p.Iat == 0 {
		return errors.New("No issue time in token")
	}

	if p.Exp == 0 {
		return errors.New("No expiration time in token")
	}

	if p.Exp > now+maxTokenLifetimeSecs {
		return errors.New("Expiration time too far in future")
	}

	earliest := p.Iat - clockSkewSecs
	latest := p.Exp + clockSkewSecs

	if now < earliest {
		return fmt.Errorf("Token used to early, %v < %v", now, earliest)
	}

	if now > latest {
		return fmt.Errorf("Token used to late, %v > %v", now, latest)
	}

	if p.Iss != issuers[0] && p.Iss != issuers[1] {
		return fmt.Errorf("Invalid issuer, expected one of [%v, %v] but got %v", issuers[0], issuers[1], p.Iss)
	}

	for _, rAud := range requiredAud {
		if p.Aud == rAud {
			return nil
		}
	}
	return fmt.Errorf("Wrong recipient, payload audience is %v", p.Aud)
}

func Verify(idToken string) (string, error) {
	jwk, err := getCertsFromGoogle()
	if err != nil {
		return "", err
	}

	return verifyIDToken(idToken, jwk.Keys)
}

func getJwk(body []byte) (*oauth2.Jwk, error) {
	var jwk = new(oauth2.Jwk)
	err := json.Unmarshal(body, &jwk)
	return jwk, err
}

const maxAgeKey = "max-age="
const maxAgeKeyLen = len("max-age=")

func doCacheControl(cacheControl string, jwk *oauth2.Jwk) error {
	if cacheControl == "" {
		_certificateExpiry = time.Time{}
		return nil
	}

	b := strings.Index(cacheControl, maxAgeKey)
	e := strings.Index(cacheControl[b:], ",")
	if b == -1 || e == -1 {
		_certificateExpiry = time.Time{}
		return nil
	}

	cacheAge, err := time.ParseDuration(cacheControl[b+maxAgeKeyLen:b+e] + "s")
	if err != nil {
		return err
	}

	_certificateExpiry = time.Now().Add(cacheAge)
	_certificateCache = jwk

	return nil
}

func getCertsFromGoogle() (*oauth2.Jwk, error) {
	if !_certificateExpiry.Equal(time.Time{}) && time.Now().Before(_certificateExpiry) && _certificateCache != nil {
		return _certificateCache, nil
	}

	res, err := http.Get(googleOauth2CertsURL)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	jwk, err := getJwk([]byte(body))
	if err != nil {
		return nil, err
	}

	if err = doCacheControl(res.Header.Get("cache-control"), jwk); err != nil {
		return nil, err
	}

	return jwk, nil
}

func getCert(keys []*oauth2.JwkKeys, envelope []byte) (*oauth2.JwkKeys, error) {
	var envelopeObj = new(Envelope)
	err := json.Unmarshal(envelope, &envelopeObj)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		if key.Kid == envelopeObj.Kid {
			return key, nil
		}
	}

	return nil, errors.New("No certificate found for envelope")
}

func getPublicKey(cert *oauth2.JwkKeys) (*rsa.PublicKey, error) {
	decN, err := base64.RawURLEncoding.DecodeString(cert.N)
	if err != nil {
		return nil, err
	}
	n := big.NewInt(0)
	n.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(cert.E)

	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}

	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func verifyPayload(payload []byte) (string, error) {
	payloadObj := Payload{}
	err := json.Unmarshal(payload, &payloadObj)
	if err != nil {
		return "", err
	}

	return payloadObj.Sub, payloadObj.verify()
}

func verifyIDToken(token string, keys []*oauth2.JwkKeys) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("jws: invalid token received, token must have 3 parts: " + token)
	}

	envelope, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Can't parse token envelope")
	}
	if len(envelope) == 0 {
		return "", errors.New("Can't parse token envelope")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	if len(payload) == 0 {
		return "", errors.New("Can't parse token payload")
	}

	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}

	cert, err := getCert(keys, envelope)
	if err != nil {
		return "", err
	}
	key, err := getPublicKey(cert)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write([]byte(signed))
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), signature)
	if err != nil {
		return "", err
	}

	platformID, err := verifyPayload(payload)
	if err != nil {
		return "", fmt.Errorf("verify fail: %s: %v", payload, err)
	}

	return platformID, nil
}
