package verify

import (
	"bulkytree.com/sevenhearts/auth/apple"
	"bulkytree.com/sevenhearts/auth/facebook"
	"bulkytree.com/sevenhearts/auth/google"
)

var defaultVerifier = NewProviderHandler()

func init() {
	defaultVerifier.Register("A", apple.Verify)
	defaultVerifier.Register("F", facebook.Verify)
	defaultVerifier.Register("G", google.Verify)
	defaultVerifier.Register("B", func(s string) (string, error) { return s, nil }) // 개발 용도 임시 로그인
}

func Register(name string, verifyFunc func(string) (string, error)) {
	defaultVerifier.Register(name, verifyFunc)
}

func Verify(name string, token string) (string, error) {
	return defaultVerifier.Providers[name](token)
}

type ProviderHandler struct {
	Providers map[string]func(string) (string, error) `json:"providers"`
}

func NewProviderHandler() *ProviderHandler {
	p := &ProviderHandler{}
	p.Providers = make(map[string]func(string) (string, error))
	return p
}

func (p *ProviderHandler) Register(name string, verifyFunc func(string) (string, error)) {
	p.Providers[name] = verifyFunc
}

func (p *ProviderHandler) Verify(name string, token string) (string, error) {
	return p.Providers[name](token)
}
