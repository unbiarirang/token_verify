package facebook

import "testing"
import "fmt"

var accessToken = `EAACEdEose0cBAEbiV39UvlyobkmJpPWZBLakZA3V1ZB2Kp6yNhmZARNaOqdJiyfEpVEmDKRUGKWL0G4w7VRtWIpshEf367bGIqbdCVFyYOEMa82s8ZAQuUrCeBL2qBttUP9PAIBEUbPPsP1dZBx4P95V4ZCZCQ7EZAxBTI0m5SbNnQAxNmzUVWQ3ujdSHfHKH8fdLCBZBf4cvipwZDZD`

func TestFacebookVerify(t *testing.T) {
	platformID, err := Verify(accessToken)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("platformID:", platformID)
}
