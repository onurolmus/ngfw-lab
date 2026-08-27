package main

import (
	"fmt"
	"net/netip"
	"regexp"
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

var validZones = map[string]bool{
	"lan": true,
	"wan": true,
}

var validProtocols = map[string]bool{
	"any":  true,
	"icmp": true,
	"tcp":  true,
	"udp":  true,
}

var validActions = map[string]bool{
	"accept": true,
	"drop":   true,
}

func validateCIDR(field, value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("%s gecersiz IPv4 CIDR: %q", field, value)
	}

	if prefix != prefix.Masked() {
		return fmt.Errorf("%s ag adresi olmali: %s", field, prefix.Masked())
	}

	return nil
}

func validatePolicy(policy Policy) error {
	if policy.Version != 1 {
		return fmt.Errorf("desteklenmeyen policy surumu: %d", policy.Version)
	}

	if len(policy.Rules) > 256 {
		return fmt.Errorf("kural sayisi en fazla 256 olmali")
	}

	seenIDs := make(map[string]bool)

	for index, rule := range policy.Rules {
		field := fmt.Sprintf("rules[%d]", index)

		if !ruleIDPattern.MatchString(rule.ID) {
			return fmt.Errorf("%s gecersiz id: %q", field, rule.ID)
		}

		if seenIDs[rule.ID] {
			return fmt.Errorf("%s tekrar eden id: %q", field, rule.ID)
		}
		seenIDs[rule.ID] = true

		if !validZones[rule.SourceZone] ||
			!validZones[rule.DestinationZone] {
			return fmt.Errorf("%s gecersiz zone", field)
		}

		if rule.SourceZone == rule.DestinationZone {
			return fmt.Errorf("%s kaynak ve hedef zone ayni olamaz", field)
		}

		if err := validateCIDR(field+".source_cidr", rule.SourceCIDR); err != nil {
			return err
		}

		if err := validateCIDR(field+".destination_cidr", rule.DestinationCIDR); err != nil {
			return err
		}

		if !validProtocols[rule.Protocol] {
			return fmt.Errorf("%s gecersiz protocol: %q", field, rule.Protocol)
		}

		if !validActions[rule.Action] {
			return fmt.Errorf("%s gecersiz action: %q", field, rule.Action)
		}

		if rule.Protocol == "tcp" || rule.Protocol == "udp" {
			if rule.DestinationPort == nil || *rule.DestinationPort == 0 {
				return fmt.Errorf("%s tcp/udp icin destination_port gerekli", field)
			}
		} else if rule.DestinationPort != nil {
			return fmt.Errorf("%s bu protocol destination_port kullanamaz", field)
		}
	}

	return nil
}
