package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	activeRulesPath   = "/etc/nftables/ngfw.nft"
	rollbackRulesPath = "/etc/nftables/ngfw.nft.rollback"
)

func runNFT(args ...string) error {
	command := exec.Command("nft", args...)

	output, err := command.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}

		return fmt.Errorf(
			"nft %s basarisiz: %s",
			strings.Join(args, " "),
			detail,
		)
	}

	return nil
}

func atomicCopy(source, destination string, mode fs.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("%s okunamadi: %w", source, err)
	}

	directory := filepath.Dir(destination)

	temp, err := os.CreateTemp(
		directory,
		"."+filepath.Base(destination)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("gecici dosya olusturulamadi: %w", err)
	}

	tempPath := temp.Name()
	defer os.Remove(tempPath)
	defer temp.Close()

	if err := temp.Chmod(mode); err != nil {
		return fmt.Errorf("dosya izni ayarlanamadi: %w", err)
	}

	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("gecici dosya yazilamadi: %w", err)
	}

	if err := temp.Sync(); err != nil {
		return fmt.Errorf("gecici dosya diske yazilamadi: %w", err)
	}

	if err := temp.Close(); err != nil {
		return fmt.Errorf("gecici dosya kapatilamadi: %w", err)
	}

	if err := os.Rename(tempPath, destination); err != nil {
		return fmt.Errorf("dosya aktif konuma tasinamadi: %w", err)
	}

	return nil
}

func writeTempCandidate(policy Policy) (string, error) {
	temp, err := os.CreateTemp(
		"/etc/nftables",
		".ngfw-candidate-*.nft",
	)
	if err != nil {
		return "", fmt.Errorf("candidate olusturulamadi: %w", err)
	}

	tempPath := temp.Name()

	fail := func(cause error) (string, error) {
		temp.Close()
		os.Remove(tempPath)
		return "", cause
	}

	if err := temp.Chmod(0600); err != nil {
		return fail(fmt.Errorf("candidate izni ayarlanamadi: %w", err))
	}

	if _, err := temp.WriteString(renderPolicy(policy)); err != nil {
		return fail(fmt.Errorf("candidate yazilamadi: %w", err))
	}

	if err := temp.Sync(); err != nil {
		return fail(fmt.Errorf("candidate diske yazilamadi: %w", err))
	}

	if err := temp.Close(); err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("candidate kapatilamadi: %w", err)
	}

	return tempPath, nil
}

func restoreRollback() error {
	if err := runNFT("-c", "-f", rollbackRulesPath); err != nil {
		return fmt.Errorf("rollback kontrolu basarisiz: %w", err)
	}

	if err := runNFT("-f", rollbackRulesPath); err != nil {
		return fmt.Errorf("rollback uygulanamadi: %w", err)
	}

	if err := atomicCopy(
		rollbackRulesPath,
		activeRulesPath,
		0644,
	); err != nil {
		return fmt.Errorf("rollback kalici kaydedilemedi: %w", err)
	}

	return nil
}

func applyPolicy(policy Policy) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("apply islemi root yetkisi gerektirir")
	}

	candidatePath, err := writeTempCandidate(policy)
	if err != nil {
		return err
	}
	defer os.Remove(candidatePath)

	if err := runNFT("-c", "-f", candidatePath); err != nil {
		return fmt.Errorf("candidate kontrolu basarisiz: %w", err)
	}

	if err := atomicCopy(
		activeRulesPath,
		rollbackRulesPath,
		0600,
	); err != nil {
		return fmt.Errorf("rollback yedegi alinamadi: %w", err)
	}

	if err := runNFT("-f", candidatePath); err != nil {
		rollbackErr := restoreRollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"candidate uygulanamadi: %v; rollback da basarisiz: %w",
				err,
				rollbackErr,
			)
		}

		return fmt.Errorf("candidate uygulanamadi, rollback yapildi: %w", err)
	}

	if err := runNFT(
		"list",
		"chain",
		"inet",
		"ngfw_filter",
		"forward",
	); err != nil {
		rollbackErr := restoreRollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"uygulama dogrulanamadi: %v; rollback da basarisiz: %w",
				err,
				rollbackErr,
			)
		}

		return fmt.Errorf("uygulama dogrulanamadi, rollback yapildi: %w", err)
	}

	if err := atomicCopy(
		candidatePath,
		activeRulesPath,
		0644,
	); err != nil {
		rollbackErr := restoreRollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"kalici kayit basarisiz: %v; rollback da basarisiz: %w",
				err,
				rollbackErr,
			)
		}

		return fmt.Errorf("kalici kayit basarisiz, rollback yapildi: %w", err)
	}

	return nil
}

func rollbackPolicy() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("rollback islemi root yetkisi gerektirir")
	}

	return restoreRollback()
}
