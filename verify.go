package main

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
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/oauth2/v2"
)

const googleOauth2CertsURL = "https://www.googleapis.com/oauth2/v3/certs"

//Max Token Lifetime is one day in seconds
const maxTokenLifetimeSecs = 86400

//Clock skew - five minutes in seconds
const clockSkewSecs = 300

//The allowed oauth token issuers.
var issuers = [2]string{"accounts.google.com", "https://accounts.google.com"}

//The audience to test the jwt against.
var requiredAud = [...]string{"366667191730-j4fu8pnvc2j1ttkrl1k7ju5n5pim3vet.apps.googleusercontent.com"}

const idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFlOGU0NmMzN2UzOWMzY2ZiMTgxNWI2YjU4MmM2MTNiOTk0N2MxZTQifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6InFmdXFud3NXWWRzLXBzMW1oYkU5cXciLCJhenAiOiIzNjY2NjcxOTE3MzAtajRmdThwbnZjMmoxdHRrcmwxazdqdTVuNXBpbTN2ZXQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzNjY2NjcxOTE3MzAtajRmdThwbnZjMmoxdHRrcmwxazdqdTVuNXBpbTN2ZXQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMzNDAwOTA5MTE5NTQ3NDE2OTYiLCJpYXQiOjEzODMxNDc0MjEsImV4cCI6MTM4MzE1MTMyMX0.Z2NVE5HQxsLXx_zRmG3bxgGPDUv76HffDYvhlU_OpgLDeeIxQnC7cAS2OkAUK-nkDci3rMTM035NeTQUKfHsUziOV_WGyDtuRq_KEBDev0ssr8EeTq0Wg-nYN8eo6nbfKYTtd4UnOMG-xYetyyPIN8SNy3G7P1Aw3CakhbD32I0"

var _certificateExpiray int64

type Envelope struct {
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

type Payload struct {
	Iss    string `json:"iss,omitempty"`
	AtHash string `json:"at_hash,omitempty"`
	Azp    string `json:"azp,omitempty"`
	Aud    string `json:"aud,omitempty"`
	Sub    string `json:"sub,omitempty"`
	Iat    int64  `json:"iat,omitempty"`
	Exp    int64  `json:"exp,omitempty"`
}

//구글API는 v2/certs를 때림
//v3과 비교했을 때 "n" 끝에 "=="가 더 붙어있음
func getJwkWithGoogleAPI(httpClient *http.Client) {
	s, _ := oauth2.New(httpClient)
	x := s.GetCertForOpenIdConnect()
	jwk2 := new(oauth2.Jwk)
	jwk2, _ = x.Do()
	fmt.Println("\njwk2:", jwk2, "\njwk2.Keys:", jwk2.Keys, "\njwk.Keys[0]", jwk2.Keys[0])
}

func getMillTime() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func getSecsTime() int64 {
	return time.Now().UnixNano() / int64(time.Second)
}

//For debugging purposes
func verifyForDebugging(idToken string) (*oauth2.Tokeninfo, error) {
	oauth2Service, err := oauth2.New(&http.Client{})
	if err != nil {
		return nil, err
	}
	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall.IdToken(idToken)
	return tokenInfoCall.Do()
}

//For production purposes
func verifyForReal(idToken string) error {
	jwk, err := getCertsFromGoogle()
	if err != nil {
		return err
	}

	err = verifyIDToken(idToken, jwk.Keys)
	if err != nil {
		fmt.Println(err)
	}

	return nil
}

func getJwk(body []byte) (*oauth2.Jwk, error) {
	var jwk = new(oauth2.Jwk)
	err := json.Unmarshal(body, &jwk)
	return jwk, err
}

func doCacheControl(cacheControl string) error {
	var cacheAge int64 = -1
	var err error

	if cacheControl != "" {
		b := strings.Index(cacheControl, "max-age=")
		e := strings.Index(cacheControl[b:], ",")
		cacheAge, err = strconv.ParseInt(cacheControl[b+8:b+e], 10, 64)
		if err != nil {
			return err
		}
		cacheAge *= 1000
	}

	if _certificateExpiray = -1; cacheAge != -1 {
		_certificateExpiray = getMillTime() + cacheAge
	}

	return nil
}

func getCertsFromGoogle() (*oauth2.Jwk, error) {
	var httpClient = &http.Client{}
	res, err := httpClient.Get(googleOauth2CertsURL)
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
	fmt.Println("jwk:", jwk, "\njwk.Keys:", jwk.Keys, "\njwk.Keys[0]", jwk.Keys[0])

	cacheControl := res.Header.Get("cache-control")
	err = doCacheControl(cacheControl)
	if err != nil {
		return nil, err
	}

	return jwk, nil
}

func verifyPayload(payload []byte) error {
	var payloadObj = new(Payload)
	var payloadStr = string(payload[:])
	err := json.Unmarshal(payload, &payloadObj)
	if err != nil {
		return err
	}
	fmt.Println("payloadObj:", payloadObj)

	iat := payloadObj.Iat
	exp := payloadObj.Exp
	iss := payloadObj.Iss
	aud := payloadObj.Aud

	now := getSecsTime()
	fmt.Println("iat, exp, now:", iat, exp, now)

	if iat == 0 {
		return errors.New("No issue time in token: " + payloadStr)
	}

	if exp == 0 {
		return errors.New("No expiration time in token: " + payloadStr)
	}

	if exp > now+maxTokenLifetimeSecs {
		return errors.New("Expiration time too far in future: " + payloadStr)
	}

	earliest := iat - clockSkewSecs
	//latest := exp + clockSkewSecs

	if now < earliest {
		return errors.New("Token used to early, " + strconv.FormatInt(now, 10) + " < " + strconv.FormatInt(earliest, 10) + ":" + payloadStr)
	}

	// if now > latest {
	// 	return errors.New("Token used to late, " + strconv.FormatInt(now, 10) + " > " + strconv.FormatInt(latest, 10) + ":" + payloadStr)
	// }

	if iss != issuers[0] && iss != issuers[1] {
		return errors.New("Invalid issuer, expected one of [" + issuers[0] + ", " + issuers[1] + "] but got " + iss)
	}

	audVerified := false
	for _, rAud := range requiredAud {
		if aud == rAud {
			audVerified = true
			break
		}
	}
	if !audVerified {
		return errors.New("Wrong recipient, payload audience is " + aud)
	}

	return nil
}

func getPem(keys []*oauth2.JwkKeys, envelope []byte) (*oauth2.JwkKeys, error) {
	certs := make(map[string]*oauth2.JwkKeys)
	for _, key := range keys {
		certs[key.Kid] = key
	}

	var envelopeObj = new(Envelope)
	err := json.Unmarshal(envelope, &envelopeObj)
	if err != nil {
		return nil, err
	}
	fmt.Println("envelopeObj:", envelopeObj)

	envelopeObj.Kid = "3c066add5889b989e9c49803c21fa4b29d1f4ead"

	if certs[envelopeObj.Kid] == nil {
		return nil, errors.New("No pem found for envelope")
	}

	return certs[envelopeObj.Kid], nil
}

func getPublicKey(pemN string, pemE string) (*rsa.PublicKey, error) {
	decN, err := base64.URLEncoding.DecodeString(pemN)
	// if err != nil {
	// 	return err
	// }
	fmt.Println("decN:", decN)
	n := big.NewInt(0)
	n.SetBytes(decN)
	fmt.Println("n:", n)

	decE, err := base64.URLEncoding.DecodeString(pemE)
	// if err != nil {
	// 	return err
	// }
	fmt.Println("decE:", decE)

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

func verifyIDToken(token string, keys []*oauth2.JwkKeys) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("jws: invalid token received, token must have 3 parts")
	}

	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
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
	fmt.Println("payload:", payload, string(payload[:]))

	pem, err := getPem(keys, envelope)
	if err != nil {
		return err
	}
	key, err := getPublicKey(pem.N, pem.E)
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write([]byte(signed))
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), []byte(signature))
	// if err != nil {
	// 	return errors.New(err + "token: " + token)
	// }

	err = verifyPayload(payload)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := verifyForReal(idToken)
	if err != nil {
		fmt.Println(err)
	}
}
