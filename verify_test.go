package verify

import (
	"testing"
	_ "work/verify/apple"
	_ "work/verify/facebook"
	_ "work/verify/google"
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

var googleToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImIyNzE5ZjMxYzZiYTFlNWZlNjY0ZmJiMWJmMGY3YzA1YjNkM2EwYTEifQ.eyJhenAiOiI1MjA5NDEwMTEwMDgtNTFuY2toamJ1ZGJhdDNlaWpmMGtsMGdlcXVuYnIwcGwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1MjA5NDEwMTEwMDgtNTFuY2toamJ1ZGJhdDNlaWpmMGtsMGdlcXVuYnIwcGwuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDA2MjY0NTY0NjU4MTAwODAxODkiLCJhdF9oYXNoIjoiU3JWTzBuWklKLWlSTVE5WkNwclNZZyIsImlzcyI6ImFjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE0OTY4OTMwOTAsImV4cCI6MTQ5Njg5NjY5MH0.eGgOQVfn6GTuApmUTXujBmqqDls_VhIiYE7CecMXUA_on2cWLPtPghHC2LlSDYP52BayGlbZ_K82201ZtKOwi5YQPosiA00SDqYAL0JVJ_8xubrh_7PTTAMOXaNI8p5p9G4irG1ebwnkvsJRFl0Ef9CoC1Mq1JKXtF1WRoeRnR9ihKI-l8UK1--PPnvyqKRWo3JhOfZRPDhC7WXZweP73BhGRoRuULwPVFV-RGM5olgdMwCezJhh8K7ytBssIeC8I23vXSa8l634J8IZv20wwMTxfb3Rc3wuKlz7MZXAw21QTV9mvAXra8BxYalWX3XjKUuI2TsB4KszOr64xOwNvQ"

func init() {

}

func TestVerify(t *testing.T) {
	err := Verify("A", appleToken)
	err = Verify("F", facebookToken)
	err = Verify("G", googleToken)
	if err != nil {
		t.Error(err)
	}
}
