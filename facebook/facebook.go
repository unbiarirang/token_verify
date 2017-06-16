package facebook

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	verifier "work/verify"
)

const facebookEndPoint = "https://graph.facebook.com/me"

func init() {
	verifier.Register("F", verify)
}

func verify(accessToken string) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", facebookEndPoint, nil)
	if err != nil {
		return err
	}

	q := req.URL.Query()
	q.Add("fields", "id")
	q.Add("access_token", accessToken)
	req.URL.RawQuery = q.Encode()

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

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

	return nil
}
