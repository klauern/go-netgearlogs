package netgearlogs

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func createTestParser(val string) *Parser {
	r := strings.NewReader(val)
	return NewParser(r)
}

func TestParseWLanAccessRejectedIncorrectSec(t *testing.T) {
	log := "[WLAN access rejected: incorrect security] from MAC address 10:a5:d0:cd:fc:19, Wednesday, February 17, 2016 16:52:35"
	p := createTestParser(log)
	l, err := p.Parse()
	if err != nil {
		t.Errorf("Error in parsing: %s", err)
	}
	if l.EventType != eventWLANRejectIncorrectSec {
		t.Errorf("Incorrect Event Type. Expected %s, Got %s", eventWLANRejectIncorrectSec, l.EventType)
	}
	tm, _ := time.Parse(netgearLogDateFmt, "Wednesday, February 17, 2016 16:52:35")
	if l.Time != tm {
		t.Errorf("Time does not match: Expected: %s, Got %s", tm, l.Time)
	}
}

func TestParseSourcePortIPAddress(t *testing.T) {
	log := "] from source : 66.40.255.235 port 80"
	p := createTestParser(log)
	source, err := scanFromSourcePortIPAddress(p)
	if err != nil {
		t.Errorf("Error in parsing: %s", err)
	}
	sourceIp := "66.40.255.235"
	if source != sourceIp {
		t.Errorf("Expected %s, Got %s", sourceIp, source)
	}
}

func TestParseDoSAttack(t *testing.T) {
	dosAttacks := map[string]*NetGearLog{
		"[DoS Attack: SYN/ACK Scan] from source: 68.40.255.235, port 80, Tuesday, February 16, 2016 17:35:23": &NetGearLog{
			EventType:  "DoS Attack: SYN/ACK Scan",
			FromSource: "68.40.255.235",
			//Time: time.Time{
			//
			//},
			//}, "Tuesday, February 16, 2016 17:35:23"),
			ToDest:       "",
			ToMACAddress: "",
		},
		"[DoS Attack: RST Scan] from source: 108.160.172.237, port 443, Tuesday, February 16, 2016 17:39:12": &NetGearLog{
			EventType:  "DoS Attack: RST Scan",
			FromSource: "108.160.172.237",
			// Time: ....
			ToDest:       "",
			ToMACAddress: "",
		},
		"[DoS Attack: TCP/UDP Chargen] from source: 185.130.5.253, port 57022, Tuesday, February 16, 2016 17:50:46": &NetGearLog{
			EventType:  "DoS Attack: TCP/UDP Chargen",
			FromSource: "185.130.5.253",
			// Time
			ToDest:       "",
			ToMACAddress: "",
		},
		"[DoS Attack: ACK Scan] from source: 89.108.72.11, port 80, Tuesday, February 16, 2016 08:28:56": &NetGearLog{
			EventType: "DoS Attack: ACK Scan",
			FromSource: "89.108.72.11",
			// Time
			ToDest: "",
			ToMACAddress: "",
		},
	}

	for k, v := range dosAttacks {
		p := createTestParser(k)
		l, err := p.Parse()
		if err != nil {
			fmt.Errorf("Error in parsing %s: %s", v, err)
		}
		if v.EventType != l.EventType {
			fmt.Errorf("Expected Event Type %s, got %s", v.EventType, l.EventType)
		}
		if v.FromSource != l.FromSource {
			fmt.Errorf("Expected FromSource to be %s, Got %s", v.FromSource, l.FromSource)
		}
		if v.Time != l.Time {
			fmt.Errorf("Time Does Not Match Expected %s, got %s", v.Time, l.Time)
		}
		if v.ToDest != l.ToDest {
			fmt.Errorf("To Dest is supposed to be %s, was %s", v.ToDest, l.ToDest)
		}
		if v.ToMACAddress != l.ToMACAddress {
			fmt.Errorf("To MAC Address did not match.  Expected: %s, Got: %s", v.ToMACAddress, l.ToMACAddress)
		}
	}
}
