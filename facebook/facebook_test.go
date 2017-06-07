package facebook

import "testing"

func TestFacebookVerify(t *testing.T) {
	err := verify("my_access_token", "user_id")
	if err != nil {
		t.Error(err)
	}
}
