package test

import (
	"fmt"
	"testing"

	"bulkytree.com/sevenhearts/auth"
)

var appleToken = `{
"player_id" : "G:123148854",
"bundle_id" : "de.bichinger.test.gamekit-auth",
"public_key_url" : "https://static.gc.apple.com/public-key/gc-prod-2.cer",
"signature" : "SGKgszgKffUshV4aMe0aQHAvzSointPjBlfF2MK34gHY50DycZlC5gwKDpRb+gBCS2OHQNLSRctYV5WORYsDbjAcNdrzR2Tl0oDMptpBiVJQX+kCilv45Fbs7szEJ2jw/4Xl/CAFlX/HtRxYZKb4oeC/knB5ueuDGcAyjFZJkl8FmFvyRn2ZeO0pGfefzQ2lz3bgHkwgcY+w8ZMQ5wIoHkgt4x44H21hnI5he/G0q48Il0lc3frWiojeZn2UWIo8j601svFHSDkX3mx9SJrYeP4f8goJ8ax1/fVVHxSdh2+uKW+9Zz/gAbrAC4xtVUiz12DjHZf9G6hxZ0etrjZYBQ==",
"salt" : "Yt1c3Q==",
"timestamp" : 1445940012818
}`

var facebookToken = `EAACEdEose0cBAEbiV39UvlyobkmJpPWZBLakZA3V1ZB2Kp6yNhmZARNaOqdJiyfEpVEmDKRUGKWL0G4w7VRtWIpshEf367bGIqbdCVFyYOEMa82s8ZAQuUrCeBL2qBttUP9PAIBEUbPPsP1dZBx4P95V4ZCZCQ7EZAxBTI0m5SbNnQAxNmzUVWQ3ujdSHfHKH8fdLCBZBf4cvipwZDZD`

var googleToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3NGZiMTJhYzJkMDRhOTkyN2Y5YTExMjBjZjA4N2NlNjQyMzI3MjQifQ.eyJhenAiOiI1MjA5NDEwMTEwMDgtNTFuY2toamJ1ZGJhdDNlaWpmMGtsMGdlcXVuYnIwcGwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1MjA5NDEwMTEwMDgtNTFuY2toamJ1ZGJhdDNlaWpmMGtsMGdlcXVuYnIwcGwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDA2MjY0NTY0NjU4MTAwODAxODkiLCJhdF9oYXNoIjoiWDZDN1M5bzJJN1lsdk9SLWJGYlZNQSIsImlzcyI6ImFjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE0OTc1ODQ2MTYsImV4cCI6MTQ5NzU4ODIxNn0.vbbIgdpmWoKA8lNGbXVAgnak64lThkzTH6d7AYupG99853mGT7gDixQejJtCphAKmyeI6fSUzSd0C-y7343Wa959dCtCGBE8vypUhjEC4mTA4twgjIgeI5iv5KU9B4P1he_3CeruhAh6KFpc5GpJBV0bGmPM2x712KvF-fq3VitDsRbr1S_D4eNMfvyLtiSk93fVemJ35FK7BiMAof5v1i_2qpFdOwqF7tXLBLr90CHglNd8e0btSg3JCHhYKRkG2WGc-lIq-dyZZItXepL6RIFzAFdXExYa7xahcmsN6hYUCn3ZmrnLiVo7smfkBNJ9LE4ueae5QiXy7KN0Uqf6ww"

func TestVerify(t *testing.T) {
	pID, err := auth.Verify("B", "myPlatformID1234")
	if err != nil {
		t.Error(err)
	}
	fmt.Println("pID:", pID)

	pID, err = auth.Verify("A", appleToken)
	if err != nil {
		t.Error(err)
	}
	pID, err = auth.Verify("F", facebookToken)
	if err != nil {
		t.Error(err)
	}
	pID, err = auth.Verify("G", googleToken)
	if err != nil {
		t.Error(err)
	}
}
