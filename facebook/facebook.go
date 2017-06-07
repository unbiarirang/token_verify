package facebook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

const facebookEndPoint = "https://graph.facebook.com/me"
const secret = "my_secret"

func verify(accessToken string, userID string) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", facebookEndPoint, nil)
	if err != nil {
		return err
	}

	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(accessToken))
	appsecretProof := hex.EncodeToString(hash.Sum(nil))

	q := req.URL.Query()
	q.Add("fields", "id")
	q.Add("access_token", accessToken)
	q.Add("appsecret_proof", appsecretProof) //우리 토큰이 도용당하는 것 방지
	req.URL.RawQuery = q.Encode()

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	fmt.Println("res:", res)

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	fmt.Println("body:", body, string(body))

	i := &struct {
		ID string `json:"id"`
	}{}
	err = json.Unmarshal(body, &i)
	if err != nil {
		return err
	}
	ID := i.ID
	if ID == "" {
		return errors.New("failed to get user id")
	}
	fmt.Println("ID:", ID)

	if userID != ID {
		return errors.New("user id and access token do not match. Need to login again")
	}

	return nil
}
