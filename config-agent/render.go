package main

import (
	"fmt"
	"os"
	"strings"
)

var zoneInterfaces = map[string]string{
	"lan": "eth3",
	"wan": "eth2",
}

func buildMatch(rule Rule) string {
	parts := []string{
		fmt.Sprintf(`iifname "%s"`, zoneInterfaces[rule.SourceZone]),
		fmt.Sprintf(`oifname "%s"`, zoneInterfaces[rule.DestinationZone]),
		"ip saddr " + rule.SourceCIDR,
		"ip daddr " + rule.DestinationCIDR,
	}

	switch rule.Protocol {
	case "icmp":
		parts = append(parts, "ip protocol icmp")
	case "tcp", "udp":
		parts = append(
			parts,
			fmt.Sprintf("%s dport %d", rule.Protocol, *rule.DestinationPort),
		)
	}

	return strings.Join(parts, " ")
}

func renderPolicy(policy Policy) string {
	var output strings.Builder

	output.WriteString(`flush ruleset

table inet ngfw_filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state invalid drop
		ct state established,related accept
		iifname "eth0" udp sport 67 udp dport 68 accept
		iifname { "eth0", "eth1" } tcp dport 22 ct state new accept
		iifname "eth1" ip saddr 192.168.60.1 tcp dport 8080 ct state new accept comment "Config-agent API"
		ip protocol icmp accept
		limit rate 5/second burst 10 packets log prefix "NGFW_INPUT_DROP "
		counter drop comment "Default input drop"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state invalid drop
		ct state established,related counter accept
`)

	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		match := buildMatch(rule)

		if rule.Log {
			fmt.Fprintf(
				&output,
				"\t\t%s limit rate 5/second burst 10 packets log prefix \"NGFW_RULE_%s \"\n",
				match,
				rule.ID,
			)
		}

		fmt.Fprintf(
			&output,
			"\t\t%s counter %s comment \"%s\"\n",
			match,
			rule.Action,
			rule.ID,
		)
	}

	output.WriteString(`		limit rate 5/second burst 10 packets log prefix "NGFW_FORWARD_DROP "
		counter drop comment "Default forward drop"
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}

table ip ngfw_nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth2" ip saddr 192.168.50.0/24 counter masquerade
	}
}
`)

	return output.String()
}

func writeCandidate(path string, policy Policy) error {
	data := renderPolicy(policy)

	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		return fmt.Errorf("candidate yazilamadi: %w", err)
	}

	return nil
}
