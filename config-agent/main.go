package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Policy struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	ID              string  `json:"id"`
	Enabled         bool    `json:"enabled"`
	SourceZone      string  `json:"source_zone"`
	DestinationZone string  `json:"destination_zone"`
	SourceCIDR      string  `json:"source_cidr"`
	DestinationCIDR string  `json:"destination_cidr"`
	Protocol        string  `json:"protocol"`
	DestinationPort *uint16 `json:"destination_port,omitempty"`
	Action          string  `json:"action"`
	Log             bool    `json:"log"`
}

func loadPolicy(path string) (Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf(
			"policy dosyasi acilamadi: %w",
			err,
		)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var policy Policy

	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("JSON okunamadi: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Policy{}, fmt.Errorf(
			"JSON sonunda fazladan veri bulunuyor",
		)
	}

	return policy, nil
}

func loadValidatedPolicy(path string) (Policy, error) {
	policy, err := loadPolicy(path)
	if err != nil {
		return Policy{}, err
	}

	if err := validatePolicy(policy); err != nil {
		return Policy{}, err
	}

	return policy, nil
}

func usage() {
	fmt.Fprintf(
		os.Stderr,
		"kullanim:\n"+
			"  %s render POLICY.json\n"+
			"  %s apply POLICY.json\n"+
			"  %s rollback\n"+
			"  %s serve\n",
		os.Args[0],
		os.Args[0],
		os.Args[0],
		os.Args[0],
	)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "HATA:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "render":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}

		policy, err := loadValidatedPolicy(os.Args[2])
		if err != nil {
			fail(err)
		}

		candidatePath := "ngfw-candidate.nft"

		if err := writeCandidate(candidatePath, policy); err != nil {
			fail(err)
		}

		fmt.Println("Candidate olusturuldu:", candidatePath)

	case "apply":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}

		policy, err := loadValidatedPolicy(os.Args[2])
		if err != nil {
			fail(err)
		}

		if err := applyPolicy(policy); err != nil {
			fail(err)
		}

		fmt.Println("Policy uygulandi ve kalici kaydedildi")

	case "rollback":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}

		if err := rollbackPolicy(); err != nil {
			fail(err)
		}

		fmt.Println("Rollback basariyla uygulandi")
	case "serve":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}

		if err := serveAPI(); err != nil {
			fail(err)
		}

	default:
		usage()
		os.Exit(2)
	}
}
