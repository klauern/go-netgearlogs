package netgearlogs

import (
"testing"
"os"
)

func TestDoSAttackSynAckLogLine(t *testing.T) {
	line := "[DoS Attack: SYN/ACK Scan] from source: 68.40.255.235, port 80, Tuesday, February 16, 2016 17:35:23"
	l, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if l.EventType != "DoS Attack: SYN/ACK Scan" {
		t.Errorf("Not correct Type: got %s", l.EventType)
	}
}

func TestDoSAttackRSTScanLogLine(t *testing.T) {
	line := "[DoS Attack: RST Scan] from source: 108.160.172.237, port 443, Tuesday, February 16, 2016 17:39:12"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoSAttackTCPUDPChargenLogLine(t *testing.T) {
	line := "[DoS Attack: TCP/UDP Chargen] from source: 185.130.5.253, port 57022, Tuesday, February 16, 2016 17:50:46"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoSAttackAckScanLogLine(t *testing.T) {
	line := "[DoS Attack: ACK Scan] from source: 89.108.72.11, port 80, Tuesday, February 16, 2016 08:28:56"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWlanRejectedLogLine(t *testing.T) {
	line := "[WLAN access rejected: incorrect security] from MAC address 10:a5:d0:cd:fc:19, Tuesday, February 16, 2016 17:43:14"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTimeSyncLogLine(t *testing.T) {
	line := "[Time synchronized with NTP server] Tuesday, February 16, 2016 19:03:07"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDhcpIPLogLine(t *testing.T) {
	line := "[DHCP IP: 192.168.1.11] to MAC address 20:7d:74:70:da:1d, Tuesday, February 16, 2016 18:15:51"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInternetConnectedLogLine(t *testing.T) {
	line := "[Internet connected] IP address: 96.37.90.24, Tuesday, February 16, 2016 17:02:32"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUPnPAddNatRuleLogLine(t *testing.T) {
	line := "[UPnP set event: add_nat_rule] from source 192.168.1.8, Tuesday, February 16, 2016 08:54:46"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUPnPDelNatRuleLogLine(t *testing.T) {
	line := "[UPnP set event: del_nat_rule] from source 192.168.1.8, Tuesday, February 16, 2016 08:54:06"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLANAccessRemote(t *testing.T) {
	line := "[LAN access from remote] from 80.82.79.104:46589 to 192.168.1.9:8080, Monday, February 22, 2016 13:11:37"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAdminLogin(t *testing.T) {
	line := "[admin login] from source 192.168.1.6, Wednesday, February 17, 2016 11:13:39"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoSAttackICMPScan(t *testing.T) {
	line := "[DoS Attack: ICMP Scan] from source: 208.100.26.236, Sunday, February 21, 2016 08:07:57"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmailSent(t *testing.T) {
	line := "[email sent to: klauer@gmail.com] Sunday, February 21, 2016 19:04:04"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLANAccessFromRemote(t *testing.T) {
	line := "[LAN access from remote] from 222.186.34.155:77 to 192.168.1.9:8080, Wednesday, February 17, 2016 15:22:09"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoSAttackARP(t *testing.T) {
	line := "[DoS Attack: ARP Attack] from source: 192.168.1.14, Wednesday, February 17, 2016 11:57:47"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoSAttackTcpUdpEcho(t *testing.T) {
	line := "[DoS Attack: TCP/UDP Echo] from source: 188.138.17.205, port 27221, Wednesday, February 17, 2016 23:20:09"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDynamicDNS(t *testing.T) {
	line := "[Dynamic DNS] host name klauer.mynetgear.com registeration successful, Thursday, February 18, 2016 20:09:36"
	_, err := ParseNetGearLogLine(line)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLogFile(t *testing.T) {
	f, err := os.Open("log.txt")
	if err != nil {
		t.Error(err)
	}
	_, errors := ParseNetGearLog(f)
	for k, v := range errors {
		t.Errorf("Error in %s: %s", k, v)
	}
}