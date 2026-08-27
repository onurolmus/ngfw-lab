package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxPolicyRequestBytes int64 = 1024 * 1024

var applySlot = make(chan struct{}, 1)

type apiResponse struct {
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Error   string   `json:"error,omitempty"`
	Logs    []string `json:"logs,omitempty"`
}

func writeAPIResponse(
	writer http.ResponseWriter,
	statusCode int,
	response apiResponse,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Printf("API cevabi yazilamadi: %v", err)
	}
}

func authorized(request *http.Request, token string) bool {
	expected := "Bearer " + token
	provided := request.Header.Get("Authorization")

	return subtle.ConstantTimeCompare(
		[]byte(provided),
		[]byte(expected),
	) == 1
}

func decodeRequestPolicy(reader io.Reader) (Policy, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()

	var policy Policy

	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("JSON okunamadi: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Policy{}, fmt.Errorf("JSON sonunda fazladan veri bulunuyor")
	}

	return policy, nil
}

func acquireApplySlot() bool {
	select {
	case applySlot <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseApplySlot() {
	<-applySlot
}

func serveAPI() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("API root yetkisiyle calistirilmalidir")
	}

	listenAddress := os.Getenv("NGFW_AGENT_LISTEN")
	if listenAddress == "" {
		listenAddress = "192.168.60.10:8080"
	}

	token := os.Getenv("NGFW_AGENT_TOKEN")
	if len(token) < 32 {
		return fmt.Errorf(
			"NGFW_AGENT_TOKEN en az 32 karakter olmali",
		)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(
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

		writeAPIResponse(
			writer,
			http.StatusOK,
			apiResponse{
				Status:  "ok",
				Message: "config-agent calisiyor",
			},
		)
	})

	mux.HandleFunc("/v1/policy", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writeAPIResponse(
				writer,
				http.StatusMethodNotAllowed,
				apiResponse{
					Status: "error",
					Error:  "yalnizca POST kullanilabilir",
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

		contentType := strings.ToLower(
			request.Header.Get("Content-Type"),
		)
		if !strings.HasPrefix(contentType, "application/json") {
			writeAPIResponse(
				writer,
				http.StatusUnsupportedMediaType,
				apiResponse{
					Status: "error",
					Error:  "Content-Type application/json olmali",
				},
			)
			return
		}

		request.Body = http.MaxBytesReader(
			writer,
			request.Body,
			maxPolicyRequestBytes,
		)

		policy, err := decodeRequestPolicy(request.Body)
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

		if err := validatePolicy(policy); err != nil {
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

		if !acquireApplySlot() {
			writeAPIResponse(
				writer,
				http.StatusConflict,
				apiResponse{
					Status: "error",
					Error:  "baska bir uygulama islemi devam ediyor",
				},
			)
			return
		}
		defer releaseApplySlot()

		if err := applyPolicy(policy); err != nil {
			log.Printf(
				"Policy uygulanamadi, istemci=%s: %v",
				request.RemoteAddr,
				err,
			)

			writeAPIResponse(
				writer,
				http.StatusInternalServerError,
				apiResponse{
					Status: "error",
					Error:  err.Error(),
				},
			)
			return
		}

		log.Printf(
			"Policy uygulandi, istemci=%s, kural=%d",
			request.RemoteAddr,
			len(policy.Rules),
		)

		writeAPIResponse(
			writer,
			http.StatusOK,
			apiResponse{
				Status:  "ok",
				Message: "policy uygulandi",
			},
		)
	})

	mux.HandleFunc("/v1/rollback", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writeAPIResponse(
				writer,
				http.StatusMethodNotAllowed,
				apiResponse{
					Status: "error",
					Error:  "yalnizca POST kullanilabilir",
				},
			)
			return
		}

		if !authorized(request, token) {
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

		if !acquireApplySlot() {
			writeAPIResponse(
				writer,
				http.StatusConflict,
				apiResponse{
					Status: "error",
					Error:  "baska bir uygulama islemi devam ediyor",
				},
			)
			return
		}
		defer releaseApplySlot()

		if err := rollbackPolicy(); err != nil {
			writeAPIResponse(
				writer,
				http.StatusInternalServerError,
				apiResponse{
					Status: "error",
					Error:  err.Error(),
				},
			)
			return
		}

		writeAPIResponse(
			writer,
			http.StatusOK,
			apiResponse{
				Status:  "ok",
				Message: "rollback uygulandi",
			},
		)
	})

	mux.HandleFunc("/v1/logs", logsHandler(token))
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	log.Printf("Config-agent API dinliyor: %s", listenAddress)

	return server.ListenAndServe()
}
