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

	eventDoSAttackSynAckScan    = "DoS Attack: SYN/ACK Scan"
	eventDoSAttackRstScan       = "DoS Attack: RST Scan"
	eventDoSAttackTCPUDPChargen = "DoS Attack: TCP/UDP Chargen"
	eventDoSAttackAckScan       = "DoS Attack: ACK Scan"
	eventDoSAttackICMPScan      = "DoS Attack: ICMP Scan"
	eventDoSAttackARPAttack     = "DoS Attack: ARP Attack"
	eventDoSAttackTCPUDPEcho    = "DoS Attack: TCP/UDP Echo"
	eventWLANRejectIncorrectSec = "WLAN access rejected: incorrect security"
	eventAccessControl          = "Access Control"
	eventLANAccessFromRemote    = "LAN access from remote"
	eventDHCPIP                 = "DHCP IP"
	eventDynamicDNS             = "Dynamic DNS"
	eventUPnPAddNatRule         = "UPnP set event: add_nat_rule"
	eventUPnPDelNatRule         = "UPnP set event: del_nat_rule"
	eventTimeSyncNTP            = "Time synchronized with NTP server"
	eventInternetConnected      = "Internet connected"
	eventAdminLogin             = "admin login"
	eventEmailSent              = "email sent to"
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
	case strings.Contains(line, eventDoSAttackSynAckScan):
		return dosAttack(line, eventDoSAttackSynAckScan)
	case strings.Contains(line, eventDoSAttackRstScan):
		return dosAttack(line, eventDoSAttackRstScan)
	case strings.Contains(line, eventDoSAttackTCPUDPChargen):
		return dosAttack(line, eventDoSAttackTCPUDPChargen)
	case strings.Contains(line, eventDoSAttackAckScan):
		return dosAttack(line, eventDoSAttackAckScan)
	case strings.Contains(line, eventDoSAttackTCPUDPEcho):
		return dosAttack(line, eventDoSAttackTCPUDPEcho)
	case strings.Contains(line, eventDoSAttackICMPScan):
		return dosAttackNoIP(line, eventDoSAttackICMPScan)
	case strings.Contains(line, eventDoSAttackARPAttack):
		return dosAttackNoIP(line, eventDoSAttackARPAttack)
	case strings.Contains(line, eventWLANRejectIncorrectSec):
		return wLANRejectIncorrectSecurity(line)
	case strings.Contains(line, eventTimeSyncNTP):
		return timeSyncWithNTP(line)
	case strings.Contains(line, eventDHCPIP):
		return dhcpIPAssign(line)
	case strings.Contains(line, eventInternetConnected):
		return internetConnected(line)
	case strings.Contains(line, eventUPnPAddNatRule):
		return upnpAddNatRule(line)
	case strings.Contains(line, eventUPnPDelNatRule):
		return upnpDelNatRule(line)
	case strings.Contains(line, eventAccessControl):
		return accessControl(line)
	case strings.Contains(line, eventLANAccessFromRemote):
		return lanAccessRemote(line)
	case strings.Contains(line, eventAdminLogin):
		return adminLogin(line)
	case strings.Contains(line, eventEmailSent):
		return emailSent(line)
	case strings.Contains(line, eventDynamicDNS):
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
		EventType:    eventDHCPIP,
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
		EventType: eventTimeSyncNTP,
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
		EventType:    eventWLANRejectIncorrectSec,
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
		EventType:  eventInternetConnected,
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
		EventType:  eventUPnPAddNatRule,
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
		EventType:  eventUPnPDelNatRule,
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
		EventType:  eventLANAccessFromRemote,
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
		EventType:    eventAccessControl + " " + blk,
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
		EventType:  eventAdminLogin,
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
		EventType: eventEmailSent,
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
		EventType: eventDynamicDNS + " registration " + pieces[6],
		Time:      t,
		ToDest:    dest,
	}
	return log, nil
}
