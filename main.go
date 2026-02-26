package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"go-kms/client"
	"go-kms/kms"
	"go-kms/server"
	"log"
	"os"
	"strings"
)

func main() {
	// Sub-commands.
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("go-kms: KMS Server/Client Emulator (Go port)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go-kms server [options]    Start KMS server")
	fmt.Println("  go-kms client [options]    Run KMS client")
	fmt.Println()
	fmt.Println("Run 'go-kms server -h' or 'go-kms client -h' for details.")
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	ip := fs.String("ip", "0.0.0.0", "IP address to listen on")
	port := fs.Int("port", 1688, "Port to listen on")
	epid := fs.String("epid", "", "Manual ePID (auto-generated if empty)")
	lcid := fs.Int("lcid", 1033, "Locale ID for ePID generation")
	clientCount := fs.Int("count", 0, "Client count (0 = auto)")
	activation := fs.Int("activation", 120, "Activation interval in minutes")
	renewal := fs.Int("renewal", 10080, "Renewal interval in minutes")
	hwid := fs.String("hwid", "364F463A8863D35F", "Hardware ID (16 hex chars)")
	dbPath := fs.String("db", "", "Path to KmsDataBase.xml")

	fs.Parse(args)

	config := kms.DefaultServerConfig()
	config.IP = *ip
	config.Port = *port
	config.EPID = *epid
	config.LCID = *lcid
	config.Activation = *activation
	config.Renewal = *renewal

	if *clientCount > 0 {
		config.ClientCount = clientCount
	}

	// Parse HWID.
	hwidStr := strings.TrimPrefix(*hwid, "0x")
	if strings.EqualFold(hwidStr, "RANDOM") {
		u := kms.RandomUUID()
		config.HWID = u[:8]
	} else {
		hwidBytes, err := hex.DecodeString(hwidStr)
		if err != nil || len(hwidBytes) != 8 {
			log.Fatalf("Invalid HWID: %s (must be 16 hex characters)", *hwid)
		}
		config.HWID = hwidBytes
	}

	// Set KMS database path.
	if *dbPath != "" {
		kms.SetKmsDBPath(*dbPath)
	}

	srv := server.NewKMSServer(config)
	log.Fatal(srv.ListenAndServe())
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	ip := fs.String("ip", "127.0.0.1", "KMS server IP address")
	port := fs.Int("port", 1688, "KMS server port")
	mode := fs.String("mode", "Windows8.1", "Product mode")
	cmid := fs.String("cmid", "", "Client Machine ID (auto-generated if empty)")
	name := fs.String("name", "", "Machine name (auto-generated if empty)")

	fs.Parse(args)

	// List available modes.
	if *mode == "list" {
		fmt.Println("Available product modes:")
		for k := range client.Products {
			fmt.Printf("  %s\n", k)
		}
		return
	}

	config := client.DefaultClientConfig()
	config.IP = *ip
	config.Port = *port
	config.Mode = *mode
	config.CMID = *cmid
	config.Machine = *name

	if err := client.Run(config); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
