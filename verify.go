package verify

import (
	"crypto/hmac"
	"crypto/sha256"
)

var defaultVerifer = NewProviderHandler()

func Register(name string, verifyFunc func(string) error) {
	defaultVerifer.Providers[name] = verifyFunc
}

func Verify(name string, tokenInfo string) error {
	return defaultVerifer.Providers[name](tokenInfo)
}

type ProviderHandler struct {
	Providers map[string]func(string) error `json:"providers"`
}

func NewProviderHandler() *ProviderHandler {
	p := new(ProviderHandler)
	p.Providers = make(map[string]func(string) error)
	return p
}

func (p *ProviderHandler) Register(name string, verifyFunc func(string) error) {
	p.Providers[name] = verifyFunc
}

func (p *ProviderHandler) Verify(name string, tokenInfo string) error {
	return p.Providers[name](tokenInfo)
}

//이 패키지와 다른 성격의 함수
func checkHMAC(m, mHMAC, key []byte) (bool, error) {
	h := hmac.New(sha256.New, key)
	h.Write(m)
	return hmac.Equal(mHMAC, h.Sum(nil)), nil
}
