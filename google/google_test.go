package google

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

const code = "4/atxvXWeLfAiGhPw5rTEr8S1G9HSUneJgXln13m5WvBs"

func TestGoogleVerify(t *testing.T) {
	tok := readToken()
	platformID, err := Verify(tok.IDToken)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("platformID:", platformID)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

const tokenFile = "./token.json"

func readToken() *Token {
	dat, err := ioutil.ReadFile(tokenFile)
	check(err)
	t := &Token{}
	check(json.Unmarshal(dat, t))
	return t
}

type Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

func TestGoogleGetToken(t *testing.T) {
	res, err := http.PostForm("https://accounts.google.com/o/oauth2/token", url.Values{
		"client_id":     {"520941011008-51nckhjbudbat3eijf0kl0gequnbr0pl.apps.googleusercontent.com"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {"http://localhost"},
		"client_secret": {"client_secret"},
		"code":          {code},
		"scope":         {""}})

	if err != nil {
		fmt.Println(err)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(body[:]))
	check(ioutil.WriteFile(tokenFile, body, 0644))
}
