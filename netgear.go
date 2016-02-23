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
	netgearLogDateFmt = "Monday, January 2, 2006 15:04:05"

	dosAttackSynAckScan    = "DoS Attack: SYN/ACK Scan"
	dosAttackRstScan       = "DoS Attack: RST Scan"
	dosAttackTCPUDPChargen = "DoS Attack: TCP/UDP Chargen"
	dosAttackAckScan       = "DoS Attack: ACK Scan"
	dosAttackICMPScan      = "DoS Attack: ICMP Scan"
	dosAttackARPAttack     = "DoS Attack: ARP Attack"
	dosAttackTCPUDPEcho    = "DoS Attack: TCP/UDP Echo"
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

func ParseNetGearLog(r io.Reader) ([]*NetGearLog, map[string]error) {
	var logs []*NetGearLog
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

func ParseNetGearLogLine(line string) (*NetGearLog, error) {
	switch {
	case strings.Contains(line, dosAttackSynAckScan):
		return dosAttack(line, dosAttackSynAckScan)
	case strings.Contains(line, dosAttackRstScan):
		return dosAttack(line, dosAttackRstScan)
	case strings.Contains(line, dosAttackTCPUDPChargen):
		return dosAttack(line, dosAttackTCPUDPChargen)
	case strings.Contains(line, dosAttackAckScan):
		return dosAttack(line, dosAttackAckScan)
	case strings.Contains(line, dosAttackTCPUDPEcho):
		return dosAttack(line, dosAttackTCPUDPEcho)
	case strings.Contains(line, dosAttackICMPScan):
		return dosAttackNoIP(line, dosAttackICMPScan)
	case strings.Contains(line, dosAttackARPAttack):
		return dosAttackNoIP(line, dosAttackARPAttack)
	case strings.Contains(line, wlanRejectIncorrectSec):
		return wLANRejectIncorrectSecurity(line)
	case strings.Contains(line, timeSyncWithNTP):
		return timeSyncWithNTP(line)
	case strings.Contains(line, dhcpIP):
		return dhcpIPAssign(line)
	case strings.Contains(line, internetConnected):
		return internetConnected(line)
	case strings.Contains(line, upnpAddNatRule):
		return upnpAddNatRule(line)
	case strings.Contains(line, upnpDelNatRule):
		return upnpDelNatRule(line)
	case strings.Contains(line, accessControl):
		return accessControl(line)
	case strings.Contains(line, lanAccessFromRemote):
		return lanAccessRemote(line)
	case strings.Contains(line, adminLogin):
		return adminLogin(line)
	case strings.Contains(line, emailSent):
		return emailSent(line)
	case strings.Contains(line, dynamicDNS):
		return dynamicDNS(line)
	default:
		return nil, fmt.Errorf("Log Line Not Parseable: \n%s", line)
	}
	return nil, fmt.Errorf("Unknown")
}

func TrimStrings(source string) string {
	return strings.TrimRight(source, ", ]")
}

func ParseTimeString(pieces []string) (time.Time, error) {
	t := strings.Join(pieces, " ")
	tm, err := time.Parse(netgearLogDateFmt, t)
	if err != nil {
		return time.Now(), err
	}
	return tm, nil
}

func dosAttack(line, eventType string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, terr := ParseTimeString(pieces[9:14])
	if terr != nil {
		return nil, terr
	}
	s := TrimStrings(pieces[6])
	log := &NetGearLog{
		Time:       t,
		FromSource: s,
		EventType:  eventType,
	}
	return log, nil
}

func dosAttackNoIP(line, eventType string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, terr := ParseTimeString(pieces[7:12])
	if terr != nil {
		return nil, terr
	}
	s := TrimStrings(pieces[6])
	log := &NetGearLog{
		Time:       t,
		FromSource: s,
		EventType:  eventType,
	}
	return log, nil
}

func dhcpIPAssign(line string) (*NetGearLog, error) {
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

func timeSyncWithNTP(line string) (*NetGearLog, error) {
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

func wLANRejectIncorrectSecurity(line string) (*NetGearLog, error) {
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

func internetConnected(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[5:10])
	if err != nil {
		return nil, err
	}
	ip := TrimStrings(pieces[4])
	log := &NetGearLog{
		EventType:  internetConnected,
		Time:       t,
		FromSource: ip,
	}
	return log, nil
}

func upnpAddNatRule(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[7:12])
	if err != nil {
		return nil, err
	}
	ip := TrimStrings(pieces[6])
	log := &NetGearLog{
		FromSource: ip,
		Time:       t,
		EventType:  upnpAddNatRule,
	}
	return log, nil
}

func upnpDelNatRule(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[7:12])
	if err != nil {
		return nil, err
	}
	ip := TrimStrings(pieces[6])
	log := &NetGearLog{
		FromSource: ip,
		Time:       t,
		EventType:  upnpDelNatRule,
	}
	return log, nil
}

func lanAccessRemote(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[8:13])
	if err != nil {
		return nil, err
	}
	src := TrimStrings(pieces[5])
	dest := TrimStrings(pieces[7])
	log := &NetGearLog{
		EventType:  lanAccessFromRemote,
		Time:       t,
		FromSource: src,
		ToDest:     dest,
	}
	return log, nil
}

func accessControl(line string) (*NetGearLog, error) {
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

func adminLogin(line string) (*NetGearLog, error) {
	pieces := strings.Fields(line)
	t, err := ParseTimeString(pieces[5:10])
	if err != nil {
		return nil, err
	}
	src := TrimStrings(pieces[4])
	log := &NetGearLog{
		EventType:  adminLogin,
		Time:       t,
		FromSource: src,
	}
	return log, nil
}

func emailSent(line string) (*NetGearLog, error) {
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

func dynamicDNS(line string) (*NetGearLog, error) {
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
