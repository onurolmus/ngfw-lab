package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLogLimit = 100
	maxLogLimit     = 500
)

func parseLogLimit(rawValue string) (int, error) {
	if rawValue == "" {
		return defaultLogLimit, nil
	}

	limit, err := strconv.Atoi(rawValue)
	if err != nil || limit < 1 || limit > maxLogLimit {
		return 0, fmt.Errorf(
			"limit 1 ile %d arasinda olmali",
			maxLogLimit,
		)
	}

	return limit, nil
}

func readFirewallLogs(limit int) ([]string, error) {
	journalLineLimit := limit * 20

	if journalLineLimit < 500 {
		journalLineLimit = 500
	}

	if journalLineLimit > 10000 {
		journalLineLimit = 10000
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	command := exec.CommandContext(
		ctx,
		"journalctl",
		"-k",
		"-n",
		strconv.Itoa(journalLineLimit),
		"--no-pager",
		"-o",
		"short-iso",
	)

	output, err := command.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("log okuma zaman asimina ugradi")
	}

	if err != nil {
		return nil, fmt.Errorf(
			"journalctl calistirilamadi: %w",
			err,
		)
	}

	lines := strings.Split(string(output), "\n")
	firewallLogs := make([]string, 0, limit)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "NGFW_") {
			firewallLogs = append(firewallLogs, line)
		}
	}

	if len(firewallLogs) > limit {
		firewallLogs = firewallLogs[len(firewallLogs)-limit:]
	}

	// En yeni kayıt üstte görünsün.
	for left, right := 0, len(firewallLogs)-1; left < right; {
		firewallLogs[left], firewallLogs[right] =
			firewallLogs[right], firewallLogs[left]

		left++
		right--
	}

	return firewallLogs, nil
}

func logsHandler(token string) http.HandlerFunc {
	return func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)

			writeAPIResponse(
				writer,
				http.StatusMethodNotAllowed,
				apiResponse{
					Status: "error",
					Error:  "yalnizca GET kullanilabilir",
				},
			)
			return
		}

		if !authorized(request, token) {
			writer.Header().Set(
				"WWW-Authenticate",
				"Bearer",
			)

			writeAPIResponse(
				writer,
				http.StatusUnauthorized,
				apiResponse{
					Status: "error",
					Error:  "yetkilendirme basarisiz",
				},
			)
			return
		}

		limit, err := parseLogLimit(
			request.URL.Query().Get("limit"),
		)
		if err != nil {
			writeAPIResponse(
				writer,
				http.StatusBadRequest,
				apiResponse{
					Status: "error",
					Error:  err.Error(),
				},
			)
			return
		}

		firewallLogs, err := readFirewallLogs(limit)
		if err != nil {
			log.Printf("Loglar okunamadi: %v", err)

			writeAPIResponse(
				writer,
				http.StatusInternalServerError,
				apiResponse{
					Status: "error",
					Error:  "firewall loglari okunamadi",
				},
			)
			return
		}

		writeAPIResponse(
			writer,
			http.StatusOK,
			apiResponse{
				Status:  "ok",
				Message: "loglar getirildi",
				Logs:    firewallLogs,
			},
		)
	}
}
