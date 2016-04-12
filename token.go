package netgearlogs

type Token int

const (
	// Special tokens
	ILLEGAL Token = iota
	EOF
	WS

	// Literals
	IDENT // main

	// Misc chars
	ASTERISK
	COMMA
	LEFT_SQUARE_BRACKET
	RIGHT_SQUARE_BRACKET
	COLON // ':'
	SLASH // '/'
	DOT   // '.'

	// Keywords
	DOS_ATTACK
	WLAN_ACCESS_REJECTED
	ACCESS_CONTROL
	LAN_ACCESS_REMOTE
	DHCP_IP
	DYNAMIC_DNS
	UPNP_SET_EVENT
	TIME_SYNC_NTP
	INTERNET_CONN
	ADMIN_LOGIN
	EMAIL_SENT
)
