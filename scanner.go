package netgearlogs

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

type Scanner struct {
	r *bufio.Reader
}

func NewScanner(r io.Reader) *Scanner {
	return &Scanner{r: bufio.NewReader(r)}
}

func (s *Scanner) Scan() (tok Token, lit string) {
	// Read the next rune.
	ch := s.read()

	// If we see whitespace then consume all contiguous whitespace.
	// If we see a letter then consume as an ident or reserved word.
	// If we see a digit then consume as a number.
	if isWhitespace(ch) {
		s.unread()
		return s.scanWhitespace()
	} else if isLetter(ch) {
		s.unread()
		return s.scanIdent()
	}

	// Otherwise read the individual character.
	switch ch {
	case eof:
		return EOF, ""
	case '*':
		return ASTERISK, string(ch)
	case ',':
		return COMMA, string(ch)
	}

	return ILLEGAL, string(ch)
}

// scanWhitespace consumes the current rune and all contiguous whitespace.
func (s *Scanner) scanWhitespace() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	// Read every subsequent whitespace character into the buffer.
	// Non-whitespace characters and EOF will cause the loop to exit.
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isWhitespace(ch) {
			s.unread()
			break
		} else {
			buf.WriteRune(ch)
		}
	}

	return WS, buf.String()
}

// scanIdent consumes the current rune and all contiguous ident runes.
func (s *Scanner) scanIdent() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	// Read every subsequent ident character into the buffer.
	// Non-ident characters and EOF will cause the loop to exit.
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isLetter(ch) && !isDigit(ch) {
			s.unread()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}

	// If the string matches a keyword then return that keyword.
	switch strings.ToUpper(buf.String()) {
	case "UPNP":
		s.readRestOfToken(strings.TrimPrefix(eventUPnP, buf.String()), &buf)
		return UPNP_SET_EVENT, buf.String()
	case "DOS":
		s.readRestOfToken(strings.TrimPrefix(eventDoSAttack, buf.String()), &buf)
		return DOS_ATTACK, buf.String()
	case "DHCP":
		s.readRestOfToken(strings.TrimPrefix(eventDHCPIP, buf.String()), &buf)
		return DHCP_IP, buf.String()
	case "LAN":
		s.readRestOfToken(strings.TrimPrefix(eventLANAccessFromRemote, buf.String()), &buf)
		return LAN_ACCESS_REMOTE, buf.String()
	case "WLAN":
		s.readRestOfToken(strings.TrimPrefix(eventWLANAccessRej, buf.String()), &buf)
		return WLAN_ACCESS_REJECTED, buf.String()
	case "ACCESS":
		s.readRestOfToken(strings.TrimPrefix(eventAccessControl, buf.String()), &buf)
		return ACCESS_CONTROL, buf.String()
	case "TIME":
		s.readRestOfToken(strings.TrimPrefix(eventTimeSyncNTP, buf.String()), &buf)
		return TIME_SYNC_NTP, buf.String()
	case "DYNAMIC":
		s.readRestOfToken(strings.TrimPrefix(eventDynamicDNS, buf.String()), &buf)
		return DYNAMIC_DNS, buf.String()
	case "INTERNET":
		s.readRestOfToken(strings.TrimPrefix(eventInternetConnected, buf.String()), &buf)
		return INTERNET_CONN, buf.String()
	case "ADMIN":
		s.readRestOfToken(strings.TrimPrefix(eventAdminLogin, buf.String()), &buf)
		return ADMIN_LOGIN, buf.String()
	case "EMAIL":
		s.readRestOfToken(strings.TrimPrefix(eventEmailSent, buf.String()), &buf)
		return EMAIL_SENT, buf.String()
	}

	// Otherwise return as a regular identifier.
	return IDENT, buf.String()
}

func (s *Scanner) readRestOfToken(lit string, buf *bytes.Buffer) {
	for _, r := range lit {
		// Read every subsequent ident character into the buffer.
		// Non-ident characters and EOF will cause the loop to exit.
		if ch := s.read(); ch == eof || ch != r {
			s.unread()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}
}

// read reads the next rune from the bufferred reader.
// Returns the rune(0) if an error occurs (or io.EOF is returned).
func (s *Scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

// unread places the previously read rune back on the reader.
func (s *Scanner) unread() { _ = s.r.UnreadRune() }

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' || ch == '\n' }

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') }

// isDigit returns true if the rune is a digit.
func isDigit(ch rune) bool { return (ch >= '0' && ch <= '9') }

// eof represents a marker rune for the end of the reader.
var eof = rune(0)
