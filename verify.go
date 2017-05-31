package verify

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
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"google.golang.org/api/oauth2/v2"
)

const googleOauth2CertsURL = "https://www.googleapis.com/oauth2/v3/certs"

//Max Token Lifetime is one day in seconds
const maxTokenLifetimeSecs = 24 * 60 * 60

//Clock skew - five minutes in seconds
const clockSkewSecs = 300

//The allowed oauth token issuers.
var issuers = [2]string{"accounts.google.com", "https://accounts.google.com"}

//The audience to test the jwt against.
var requiredAud = [...]string{"366667191730-j4fu8pnvc2j1ttkrl1k7ju5n5pim3vet.apps.googleusercontent.com", "520941011008-51nckhjbudbat3eijf0kl0gequnbr0pl.apps.googleusercontent.com"}

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

// //구글API는 v2/certs를 때림
// //v3과 비교했을 때 "n" 끝에 "=="가 더 붙어있음
// func getJwkWithGoogleAPI(httpClient *http.Client) {
// 	s, _ := oauth2.New(httpClient)
// 	x := s.GetCertForOpenIdConnect()
// 	jwk2 := new(oauth2.Jwk)
// 	jwk2, _ = x.Do()
// 	fmt.Println("\njwk2:", jwk2, "\njwk2.Keys:", jwk2.Keys, "\njwk.Keys[0]", jwk2.Keys[0])
// }

// func getIDTokenInfo(accessToken string) (*oauth2.Tokeninfo, error) {
// 	oauth2Service, err := oauth2.New(&http.Client{})
// 	if err != nil {
// 		return nil, err
// 	}
// 	tokenInfoCall := oauth2Service.Tokeninfo()
// 	tokenInfoCall.AccessToken(accessToken)
// 	//tokenInfoCall.IdToken(idToken)
// 	return tokenInfoCall.Do()
// }

//For production purposes
func verifyIDToken(idToken string) error {
	jwk, err := getCertsFromGoogle()
	if err != nil {
		return err
	}

	return verify(idToken, jwk.Keys)
}

func getJwk(body []byte) (*oauth2.Jwk, error) {
	var jwk = new(oauth2.Jwk)
	err := json.Unmarshal(body, &jwk)
	return jwk, err
}

const maxAgeKey = "max-age="
const maxAgeKeyLen = len("max-age=")

func doCacheControl(cacheControl string) error {
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
	fmt.Printf("cacheAge: %v\n", cacheAge)

	_certificateExpiry := time.Now().Add(cacheAge)
	fmt.Printf("_certificateExpiry: %v\n", _certificateExpiry)

	return nil
}

func getCertsFromGoogle() (*oauth2.Jwk, error) {
	if !_certificateExpiry.Equal(time.Time{}) && time.Now().Before(_certificateExpiry) && _certificateCache != nil {
		return _certificateCache, nil
	}

	fmt.Println("hit google endpoint")
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
	log.Printf("jwk.Keys[0] = %+v", jwk.Keys[0])

	if err = doCacheControl(res.Header.Get("cache-control")); err != nil {
		return nil, err
	}
	_certificateCache = jwk

	return jwk, nil
}

func verifyPayload(payload []byte) error {
	payloadObj := new(Payload)
	err := json.Unmarshal(payload, &payloadObj)
	if err != nil {
		return err
	}
	fmt.Println("payloadObj:", payloadObj)

	return payloadObj.verify()
}

func getPem(keys []*oauth2.JwkKeys, envelope []byte) (*oauth2.JwkKeys, error) {
	var envelopeObj = new(Envelope)
	err := json.Unmarshal(envelope, &envelopeObj)
	if err != nil {
		return nil, err
	}
	fmt.Println("envelopeObj:", envelopeObj)

	for _, key := range keys {
		if key.Kid == envelopeObj.Kid {
			return key, nil
		}
	}

	return nil, errors.New("No pem found for envelope")
}

func getPublicKey(pem *oauth2.JwkKeys) (*rsa.PublicKey, error) {
	decN, err := base64.RawURLEncoding.DecodeString(pem.N)
	if err != nil {
		return nil, err
	}
	n := big.NewInt(0)
	n.SetBytes(decN)
	fmt.Println("n:", n)

	decE, err := base64.RawURLEncoding.DecodeString(pem.E)

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
	fmt.Println("e:", e)

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func verify(token string, keys []*oauth2.JwkKeys) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("jws: invalid token received, token must have 3 parts: " + token)
	}

	envelope, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("Can't parse token envelope")
	}
	if len(envelope) == 0 {
		return errors.New("Can't parse token envelope")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return errors.New("Can't parse token payload")
	}
	fmt.Println("payloadStr:", string(payload[:]))

	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	pem, err := getPem(keys, envelope)
	if err != nil {
		return err
	}
	key, err := getPublicKey(pem)
	if err != nil {
		return err
	}
	fmt.Println("key:", key)

	h := sha256.New()
	h.Write([]byte(signed))
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), signature)
	if err != nil {
		return err
	}

	if err := verifyPayload(payload); err != nil {
		return fmt.Errorf("verify fail: %s: %v", payload, err)
	}
	return nil
}
