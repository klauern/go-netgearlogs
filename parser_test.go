package netgearlogs

import (
	"testing"
	"strings"
)

func createTestParser(val string) (*Parser) {
	r := strings.NewReader(val)
	return NewParser(r)
}

func TestParseWLanAccessRejected(t *testing.T) {
	log := "[WLAN access rejected: incorrect security] from MAC address 10:a5:d0:cd:fc:19, Wednesday, February 17, 2016 16:52:35"
	p := createTestParser(log)
	l, err := p.Parse()
	if err != nil {
		t.Errorf("Error in parsing: %s", err)
	}
	if l.EventType != eventWLANRejectIncorrectSec {
		t.Errorf("Incorrect Event Type. Expected %s, Got %s", eventWLANRejectIncorrectSec, l.EventType)
	}
}
