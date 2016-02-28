package netgearlogs

import (
	"fmt"
	"io"
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
func (p *Parser) Parse() (*NetGearLog, error) {
	log := &NetGearLog{}

	// First token should be a "[" to start a log entry.
	if tok, lit := p.scan(); tok != '[' {
		return nil, fmt.Errorf("found %q, expected %q", lit, LEFT_SQUARE_BRACKET)
	}

	// Next we will find the type of log statement it is
	for {
		tok, lit := p.scanIgnoreWhitespace()
		switch tok {
		case DOS_ATTACK:
			//tok, lit := p.scanIgnoreWhitespace()
		case WLAN_ACCESS_REJECTED:
			// [WLAN access rejected: incorrect security] from MAC address 10:a5:d0:cd:fc:19, Wednesday, February 17, 2016 16:52:35
			tok, lit = p.scanColonIdentToRightBracket(log)
			if tok == ILLEGAL {
				return nil, fmt.Errorf("Expected %v, Got %v", IDENT, lit)
			}
			log.EventType = eventWLANAccessRej + " " + lit
			tok, lit = p.scanMacAddress(log)
			if tok != IDENT || tok == ILLEGAL {
				return nil, fmt.Errorf("Expected MAC Address, got %q", lit)
			}
			log.FromSource = lit
			tok, lit = p.scanToTimestampNewLine(log)
			if tok != IDENT || tok == ILLEGAL {
				return nil, fmt.Errorf("Expected Timestamp, got %q", lit)
			}
			t, e := parseTime(lit)
			if e != nil {
				return nil, e
			}
			log.Time = t
		case ACCESS_CONTROL:
		case LAN_ACCESS_REMOTE:
		case DHCP_IP:
		case DYNAMIC_DNS:
		case UPNP_SET_EVENT:
		case TIME_SYNC_NTP:
		case INTERNET_CONN:
		case ADMIN_LOGIN:
		case EMAIL_SENT:
		}
	}

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

	// Next we should see the "FROM" keyword.
	//if tok, lit := p.scanIgnoreWhitespace(); tok != FROM {
	//	return nil, fmt.Errorf("found %q, expected FROM", lit)
	//}

	// Finally we should read the table name.
	tok, lit := p.scanIgnoreWhitespace()
	if tok != IDENT {
		return nil, fmt.Errorf("found %q, expected table name", lit)
	}
	//log.TableName = lit

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

func (p *Parser) scanColonIdentToRightBracket(log *NetGearLog) (tok Token, lit string) {
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
