/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package main parses command line flags and starts the s3proxy server.
*/
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/edgelesssys/constellation/v2/s3proxy/internal/router"
)

const (
	// defaultPort is the default port to listen on.
	defaultPort = 443
	// defaultIP is the default IP to listen on.
	defaultIP = "172.18.0.1"
	// defaultRegion is the default AWS region to use.
	defaultRegion = "eu-west-1"
	// defaultCertLocation is the default location of the TLS certificate.
	defaultCertLocation = "/etc/s3proxy/certs"
	// defaultLogLevel is the default log level.
	defaultLogLevel = "info"
)

func main() {
	flags, err := parseFlags()
	if err != nil {
		panic(err)
	}

	// logLevel can be made a public variable so logging level can be changed dynamically.
	logLevel := new(slog.LevelVar)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	logger := slog.New(handler)
	logLevel.Set(flags.logLevel)

	if err := runServer(flags, logger); err != nil {
		panic(err)
	}
}

func runServer(flags cmdFlags, log *slog.Logger) error {
	log.Info("listening", "ip", flags.ip, "port", flags.port, "region", flags.region)

	router := router.New(flags.region, log)

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", flags.ip, flags.port),
		Handler: http.HandlerFunc(router.Serve),
		// Disable HTTP/2. Serving HTTP/2 will cause some clients to use HTTP/2.
		// It seems like AWS S3 does not support HTTP/2.
		// Having HTTP/2 enabled will at least cause the aws-sdk-go V1 copy-object operation to fail.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	if flags.port == 443 {
		cert, err := tls.LoadX509KeyPair(flags.certLocation+"/s3proxy.crt", flags.certLocation+"/s3proxy.key")
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// TLSConfig is populated, so we can safely pass empty strings to ListenAndServeTLS.
		return server.ListenAndServeTLS("", "")
	}

	log.Warn("TLS is disabled")
	return server.ListenAndServe()
}

func parseFlags() (cmdFlags, error) {
	port := flag.Int("port", defaultPort, "port to listen on")
	ip := flag.String("ip", defaultIP, "ip to listen on")
	region := flag.String("region", defaultRegion, "AWS region in which target bucket is located")
	certLocation := flag.String("cert", defaultCertLocation, "location of TLS certificate")
	level := flag.String("level", defaultLogLevel, "log level")

	flag.Parse()

	netIP := net.ParseIP(*ip)
	if netIP == nil {
		return cmdFlags{}, fmt.Errorf("not a valid IPv4 address: %s", *ip)
	}

	// TODO(derpsteb): enable once we are on go 1.21.
	logLevel := new(slog.Level)
	if err := logLevel.UnmarshalText([]byte(*level)); err != nil {
		return cmdFlags{}, fmt.Errorf("parsing log level: %w", err)
	}

	return cmdFlags{port: *port, ip: netIP.String(), region: *region, certLocation: *certLocation, logLevel: *logLevel}, nil
}

type cmdFlags struct {
	port         int
	ip           string
	region       string
	certLocation string
	logLevel     slog.Level
}
