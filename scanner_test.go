package netgearlogs

import (
	"strings"
	"testing"
)

// Ensure the scanner can scan tokens correctly.
func TestScanner_Scan(t *testing.T) {
	var tests = []struct {
		s   string
		tok Token
		lit string
	}{
		// Special tokens (EOF, ILLEGAL, WS)
		{s: ``, tok: EOF},
		{s: ` `, tok: WS, lit: " "},
		{s: "\t", tok: WS, lit: "\t"},
		{s: "\n", tok: WS, lit: "\n"},

		// Identifiers
		{s: `foo`, tok: IDENT, lit: `foo`},
		//{s: `Zx12_3U_-`, tok: IDENT, lit: `Zx12_3U_`},

		// Keywords
		{s: eventUPnP, tok: UPNP_SET_EVENT, lit: eventUPnP},
		{s: eventDoSAttack, tok: DOS_ATTACK, lit: eventDoSAttack},
		{s: eventDHCPIP, tok: DHCP_IP, lit: eventDHCPIP},
		{s: eventLANAccessFromRemote, tok: LAN_ACCESS_REMOTE, lit: eventLANAccessFromRemote},
		{s: eventWLANAccessRej, tok: WLAN_ACCESS_REJECTED, lit: eventWLANAccessRej},
		{s: eventAdminLogin, tok: ADMIN_LOGIN, lit: eventAdminLogin},
		{s: eventDHCPIP, tok: DHCP_IP, lit: eventDHCPIP},
		{s: eventTimeSyncNTP, tok: TIME_SYNC_NTP, lit: eventTimeSyncNTP},
		{s: eventDynamicDNS, tok: DYNAMIC_DNS, lit: eventDynamicDNS},
		{s: eventInternetConnected, tok: INTERNET_CONN, lit: eventInternetConnected},
		{s: eventAdminLogin, tok: ADMIN_LOGIN, lit: eventAdminLogin},
		{s: eventEmailSent, tok: EMAIL_SENT, lit: eventEmailSent},
	}

	for i, tt := range tests {
		s := NewScanner(strings.NewReader(tt.s))
		tok, lit := s.Scan()
		if tt.tok != tok {
			t.Errorf("%d. %q token mismatch: exp=%q got=%q <%q>", i, tt.s, tt.tok, tok, lit)
		} else if tt.lit != lit {
			t.Errorf("%d. %q literal mismatch: exp=%q got=%q", i, tt.s, tt.lit, lit)
		}
	}
}