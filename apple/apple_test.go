package apple

import "testing"

var identity = `{
"player_id" : "G:123148854",
"bundle_id" : "de.bichinger.test.gamekit-auth",
"public_key_url" : "https://static.gc.apple.com/public-key/gc-prod-2.cer",
"signature" : "SGKgszgKffUshV4aMe0aQHAvzSointPjBlfF2MK34gHY50DycZlC5gwKDpRb+gBCS2OHQNLSRctYV5WORYsDbjAcNdrzR2Tl0oDMptpBiVJQX+kCilv45Fbs7szEJ2jw/4Xl/CAFlX/HtRxYZKb4oeC/knB5ueuDGcAyjFZJkl8FmFvyRn2ZeO0pGfefzQ2lz3bgHkwgcY+w8ZMQ5wIoHkgt4x44H21hnI5he/G0q48Il0lc3frWiojeZn2UWIo8j601svFHSDkX3mx9SJrYeP4f8goJ8ax1/fVVHxSdh2+uKW+9Zz/gAbrAC4xtVUiz12DjHZf9G6hxZ0etrjZYBQ==",
"salt" : "Yt1c3Q==",
"timestamp" : 1445940012818
}`

func TestAppleVerify(t *testing.T) {
	err := verify(identity)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}
