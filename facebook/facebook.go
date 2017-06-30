/*
페이스북은 OAuth2.0을 사용한다. App ID와 App Secret을 가지고 페이스북에 App Token을 요청한 뒤, debug_token endpoint에서 App Token으로 Access Token을 검증하면 된다.
페이스북 공식 문서: https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken, https://developers.facebook.com/docs/facebook-login/access-tokens/#apptokens
기타 참고 자료: https://stackoverflow.com/questions/8605703/how-to-verify-facebook-access-token
*/
package facebook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const appID = "myappid"
const appSecret = "myappsecret"

const facebookAppTokenURL = "https://graph.facebook.com/oauth/access_token"
const facebookDebugTokenURL = "https://graph.facebook.com/debug_token"

func Verify(accessToken string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	appToken, err := getAppToken(client)
	if err != nil {
		return "", err
	}

	return debugToken(client, accessToken, appToken)
}

func getAppToken(client *http.Client) (string, error) {
	req, err := http.NewRequest("GET", facebookAppTokenURL, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("client_id", appID)
	q.Add("client_secret", appSecret)
	q.Add("grant_type", "client_credentials")
	req.URL.RawQuery = q.Encode()

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	res.Body.Close()

	at := struct {
		appToken string `json:"access_token"`
	}{}
	err = json.Unmarshal(body, &at)
	if err != nil {
		return "", err
	}

	appToken := at.appToken
	if appToken == "" {
		return "", errors.New("failed to get app access token")
	}

	return appToken, nil
}

func debugToken(client *http.Client, accessToken, appToken string) (string, error) {
	req, err := http.NewRequest("GET", facebookDebugTokenURL, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("input_token", accessToken)
	q.Add("access_token", appToken)
	req.URL.RawQuery = q.Encode()

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	responseData := struct {
		data struct {
			appID     string `json:"app_id"`
			expiresAt int64  `json:"expires_at"`
			userID    string `json:"user_id"`
		} `json:"data"`
	}{}

	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return "", err
	}

	if responseData.data.appID != appID {
		return "", fmt.Errorf("wrong appID. The token is not for our app")
	}

	if responseData.data.expiresAt < time.Now().Unix() {
		return "", fmt.Errorf("expired access token")
	}

	return responseData.data.userID, nil
}
