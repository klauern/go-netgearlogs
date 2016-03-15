package netgearlogs

import (
	"fmt"
	"io"
	"time"
)

// Parser represents a parser.
type Parser struct {
	s   *Scanner
	buf struct {
		tok Token  // last read token
		lit string // last read literal
		n   int    // buffer size (max=1)
	}
}

// NewParser returns a new instance of Parser.
func NewParser(r io.Reader) *Parser {
	return &Parser{s: NewScanner(r)}
}

// Parse parses a NetGear Log statement.
func (p *Parser) Parse() (log *NetGearLog, err error) {
	//log := &NetGearLog{}

	// First token should be a "[" to start a log entry.
	if tok, lit := p.scan(); tok != LEFT_SQUARE_BRACKET {
		return nil, fmt.Errorf("found %q, expected %q", lit, LEFT_SQUARE_BRACKET)
	}

	// Next we will find the type of log statement it is
	for {
		tok, lit := p.scanIgnoreWhitespace()
		switch tok {
		case DOS_ATTACK:
			return p.parseDOSAttack()
		case WLAN_ACCESS_REJECTED:
			return p.parseWlanAccessRejected()
		case ACCESS_CONTROL:
		case LAN_ACCESS_REMOTE:
		case DHCP_IP:
		case DYNAMIC_DNS:
		case UPNP_SET_EVENT:
		case TIME_SYNC_NTP:
		case INTERNET_CONN:
		case ADMIN_LOGIN:
		case EMAIL_SENT:
		default:
			err = fmt.Errorf("Unknown Token Type: %v, Value: %s", tok, lit)
			return
		}
	}

	// Everything below here is unreachable unless I 'break' out of the for loop

	// Next we should loop to the next thing
	for {
		// Read a field.
		tok, lit := p.scanIgnoreWhitespace()
		if tok != IDENT {
			return nil, fmt.Errorf("found %q, expected field", lit)
		}

		// If the next token is not a comma then break the loop.
		if tok, _ := p.scanIgnoreWhitespace(); tok != COMMA {
			p.unscan()
			break
		}
	}

	tok, lit := p.scanIgnoreWhitespace()
	if tok != IDENT {
		return nil, fmt.Errorf("found %q, expected table name", lit)
	}

	// Return the successfully parsed statement.
	return log, nil
}

// scan returns the next token from the underlying scanner.
// If a token has been unscanned then read that instead.
func (p *Parser) scan() (tok Token, lit string) {
	// If we have a token on the buffer, then return it.
	if p.buf.n != 0 {
		p.buf.n = 0
		return p.buf.tok, p.buf.lit
	}

	// Otherwise read the next token from the scanner.
	tok, lit = p.s.Scan()

	// Save it to the buffer in case we unscan later.
	p.buf.tok, p.buf.lit = tok, lit

	return
}

// scanIgnoreWhitespace scans the next non-whitespace token.
func (p *Parser) scanIgnoreWhitespace() (tok Token, lit string) {
	tok, lit = p.scan()
	if tok == WS {
		tok, lit = p.scan()
	}
	return
}

// unscan pushes the previously read token back onto the buffer.
func (p *Parser) unscan() { p.buf.n = 1 }

func (p *Parser) scanColonIdentToRightBracket() (tok Token, lit string) {
	tok, lit = p.scan()
	if tok != COLON {
		return ILLEGAL, lit
	}
	tok, lit = p.scanIgnoreWhitespace()
	if tok == IDENT {
		br, brlit := p.scan()
		if br != RIGHT_SQUARE_BRACKET {
			return ILLEGAL, brlit
		}
	}
	return
}

func (p *Parser) parseWlanAccessRejected() (log *NetGearLog, err error) {
	// [WLAN access rejected: incorrect security] from MAC address 10:a5:d0:cd:fc:19, Wednesday, February 17, 2016 16:52:35
	log = &NetGearLog{}
	log.EventType = eventWLANRejectIncorrectSec
	frMacAddr := []string{"]", "from", "MAC", "address"}
	for _, v := range frMacAddr {
		tok, lit := p.scanIgnoreWhitespace()
		if tok != IDENT && lit != v {
			err = fmt.Errorf("Expected %s, got %s", v, lit)
			return
		}
	}

	if log.FromSource, err = scanMacAddress(p); err != nil {
		return
	}

	p.scan() // ','
	p.scan() // ' '
	if log.Time, err = scanTimestampToNewLineOrEOF(p); err != nil {
		return
	}
	return
}

func (p *Parser) parseDOSAttack() (log *NetGearLog, err error) {
	// [DoS Attack: SYN/ACK Scan] from source: 68.40.255.235, port 80, Tuesday, February 16, 2016 17:35:23
	// [DoS Attack: RST Scan] from source: 108.160.172.237, port 443, Tuesday, February 16, 2016 17:39:12
	// [DoS Attack: TCP/UDP Chargen] from source: 185.130.5.253, port 57022, Tuesday, February 16, 2016 17:50:46
	// [DoS Attack: ACK Scan] from source: 89.108.72.11, port 80, Tuesday, February 16, 2016 08:28:56
	log = &NetGearLog{}
	// Need to figure out what KIND of DoS attack
	// then From Source
	// Then Port
	// Then Timestamp
}

func scanTimestampToNewLineOrEOF(p *Parser) (t time.Time, err error) {
	str := ""
	for {
		tok, lit := p.scan()
		if (tok == WS && lit == "\n") || tok == EOF {
			tok = IDENT
			lit = str
			t, err = parseTime(lit)
			return
		}
		switch tok {
		case COLON, IDENT, COMMA, WS:
			str += lit
		}
	}
	return
}

func parseTime(s string) (t time.Time, err error) {
	return time.Parse(netgearLogDateFmt, s)
}

func scanMacAddress(p *Parser) (mac string, err error) {
	mac = ""
	for i := 0; i < 11; i++ {
		tok, lit := p.scanIgnoreWhitespace()
		switch tok {
		case COLON, IDENT:
			mac += lit
		case ILLEGAL:
			err = fmt.Errorf("Error parsing MAC address: Got %s, %s", tok, lit)
			return
		}
	}
	return
}