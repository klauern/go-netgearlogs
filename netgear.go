package netgearlogs

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

type NetGearLog struct {
	Time         time.Time
	FromSource   string
	ToDest       string
	ToMACAddress string
	EventType    string
}

const (
	netgearLogDateFmt      = "Monday, January 2, 2006 15:04:05"

	dosAttackSynAckScan    = "DoS Attack: SYN/ACK Scan"
	dosAttackRstScan       = "DoS Attack: RST Scan"
	dosAttackTcpUdpChargen = "DoS Attack: TCP/UDP Chargen"
	dosAttackAckScan       = "DoS Attack: ACK Scan"
	dosAttackICMPScan      = "DoS Attack: ICMP Scan"
	dosAttackARPAttack     = "DoS Attack: ARP Attack"
	dosAttackTcpUdpEcho    = "DoS Attack: TCP/UDP Echo"

	wlanRejectIncorrectSec = "WLAN access rejected: incorrect security"
	accessControl          = "Access Control"
	lanAccessFromRemote    = "LAN access from remote"
	dhcpIP                 = "DHCP IP"
	dynamicDNS             = "Dynamic DNS"

	upnpAddNatRule         = "UPnP set event: add_nat_rule"
	upnpDelNatRule         = "UPnP set event: del_nat_rule"

	timeSyncWithNTP        = "Time synchronized with NTP server"
	internetConnected      = "Internet connected"
	adminLogin             = "admin login"
	emailSent              = "email sent to"
)

func ParseNetGearLogLine(line string) (*NetGearLog, error) {
	switch {
	case strings.Contains(line, dosAttackSynAckScan):
		return DoSAttack(line, dosAttackSynAckScan)
	case strings.Contains(line, dosAttackRstScan):
		return DoSAttack(line, dosAttackRstScan)
	case strings.Contains(line, dosAttackTcpUdpChargen):
		return DoSAttack(line, dosAttackTcpUdpChargen)
	case strings.Contains(line, dosAttackAckScan):
		return DoSAttack(line, dosAttackAckScan)
	case strings.Contains(line, dosAttackTcpUdpEcho):
		return DoSAttack(line, dosAttackTcpUdpEcho)
	case strings.Contains(line, dosAttackICMPScan):
		return DoSAttackNoIP(line, dosAttackICMPScan)
	case strings.Contains(line, dosAttackARPAttack):
		return DoSAttackNoIP(line, dosAttackARPAttack)
	case strings.Contains(line, wlanRejectIncorrectSec):
		return WLANRejectIncorrectSecurity(line)
	case strings.Contains(line, timeSyncWithNTP):
		return TimeSyncWithNTP(line)
	case strings.Contains(line, dhcpIP):
		return DhcpIPAssign(line)
	case strings.Contains(line, internetConnected):
		return InternetConnected(line)
	case strings.Contains(line, upnpAddNatRule):
		return UPnPAddNatRule(line)
	case strings.Contains(line, upnpDelNatRule):
		return UPnPDelNatRule(line)
	case strings.Contains(line, accessControl):
		return ParseAccessControl(line)
	case strings.Contains(line, lanAccessFromRemote):
		return ParseLANAccessRemote(line)
	case strings.Contains(line, adminLogin):
		return ParseAdminLogin(line)
	case strings.Contains(line, emailSent):
		return ParseEmailSent(line)
	case strings.Contains(line, dynamicDNS):
		return ParseDynamicDNS(line)
	default:
		return nil, fmt.Errorf("Log Line Not Parseable: \n%s", line)
	}
	return nil, fmt.Errorf("Unknown")
}

func LogLines(r io.Reader) [][]string {
	lines := make([][]string, 0)
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		lines = append(lines, fields)
	}
	return lines
}

func ParseSourceString(source string) string {
	return strings.TrimRight(source, ", ")
}

func ParseTimeString(pieces []string) (time.Time, error) {
	t := strings.Join(pieces, " ")
	tm, err := time.Parse(netgearLogDateFmt, t)
	if err != nil {
		return time.Now(), err
	}
	return tm, nil
}

func ParseIPAddress(s string) string {
	return strings.Trim(s, "]")
}

func DoSAttack(line, eventType string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, terr := ParseTimeString(pieces[9:14])
	if terr != nil {
		return nil, terr
	}
	s := ParseSourceString(pieces[6])
	log := &NetGearLog{
		Time:       t,
		FromSource: s,
		EventType:  eventType,
	}
	return log, nil
}

func DoSAttackNoIP(line, eventType string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	//fmt.Println(eventType)
	//for i, v := range pieces {
	//	fmt.Printf("%d %s\n", i, v)
	//}
	t, terr := ParseTimeString(pieces[7:12])
	if terr != nil {
		return nil, terr
	}
	s := ParseSourceString(pieces[6])
	log := &NetGearLog{
		Time:       t,
		FromSource: s,
		EventType:  eventType,
	}
	return log, nil
}

func DhcpIPAssign(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[7:12])
	if err != nil {
		return nil, err
	}
	ip := strings.Trim(pieces[2], "]")
	mac := strings.Trim(pieces[6], ",")
	log := &NetGearLog{
		Time:         t,
		FromSource:   ip,
		ToMACAddress: mac,
		EventType:    dhcpIP,
	}
	return log, nil
}

func TimeSyncWithNTP(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[5:10])
	if err != nil {
		return nil, err
	}
	log := &NetGearLog{
		EventType: timeSyncWithNTP,
		Time:      t,
	}
	return log, nil
}

func WLANRejectIncorrectSecurity(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[9:14])
	if err != nil {
		return nil, err
	}
	log := &NetGearLog{
		ToMACAddress: strings.Trim(pieces[8], ", "),
		Time:         t,
		EventType:    wlanRejectIncorrectSec,
	}
	return log, nil
}

func InternetConnected(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[5:10])
	if err != nil {
		return nil, err
	}
	ip := ParseIPAddress(pieces[4])
	log := &NetGearLog{
		EventType:  internetConnected,
		Time:       t,
		FromSource: ip,
	}
	return log, nil
}

func UPnPAddNatRule(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[7:12])
	if err != nil {
		return nil, err
	}
	ip := ParseIPAddress(pieces[6])
	log := &NetGearLog{
		FromSource: ip,
		Time:       t,
		EventType:  upnpAddNatRule,
	}
	return log, nil
}

func UPnPDelNatRule(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[7:12])
	if err != nil {
		return nil, err
	}
	ip := ParseIPAddress(pieces[6])
	log := &NetGearLog{
		FromSource: ip,
		Time:       t,
		EventType:  upnpDelNatRule,
	}
	return log, nil
}

func ParseNetGearLog(r io.Reader) ([]*NetGearLog, map[string]error) {
	logs := make([]*NetGearLog, 0)
	errors := make(map[string]error)
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		t := scanner.Text()
		log, err := ParseNetGearLogLine(t)
		if err != nil {
			errors[t] = err
		}
		logs = append(logs, log)
	}
	return logs, errors
}

func ParseLANAccessRemote(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[8:13])
	if err != nil {
		return nil, err
	}
	src := ParseIPAddress(pieces[5])
	dest := ParseIPAddress(pieces[7])
	log := &NetGearLog{
		EventType:  lanAccessFromRemote,
		Time:       t,
		FromSource: src,
		ToDest:     dest,
	}
	return log, nil
}

func ParseAccessControl(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[14:19])
	if err != nil {
		return nil, err
	}
	blk := strings.Trim(pieces[9], " ")
	mac := strings.Trim(pieces[7], " ")
	log := &NetGearLog{
		EventType:    accessControl + " " + blk,
		Time:         t,
		ToMACAddress: mac,
	}
	return log, nil
}

func ParseAdminLogin(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[5:10])
	if err != nil {
		return nil, err
	}
	src := ParseIPAddress(pieces[4])
	log := &NetGearLog{
		EventType:  adminLogin,
		Time:       t,
		FromSource: src,
	}
	return log, nil
}

func ParseEmailSent(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[4:9])
	if err != nil {
		return nil, err
	}
	s := strings.Trim(pieces[3], "]")
	log := &NetGearLog{
		Time:      t,
		EventType: emailSent,
		ToDest:    s,
	}
	return log, nil
}

func ParseDynamicDNS(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[7:12])
	if err != nil {
		return nil, err
	}
	dest := strings.Trim(pieces[4], " ")
	log := &NetGearLog{
		EventType: dynamicDNS + " registration " + pieces[6],
		Time:      t,
		ToDest:    dest,
	}
	return log, nil
}
