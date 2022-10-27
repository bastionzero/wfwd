package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func forward(localConn net.Conn, tunnelPortAddress string) {
	tunnel, err := net.Dial("tcp", tunnelPortAddress)
	if err != nil {
		fmt.Printf("ssh.Dial failed: %s", err)
	}

	go func() {
		_, err = io.Copy(tunnel, localConn)
		if err != nil {
			fmt.Printf("io.Copy failed: %v", err)
		}
	}()

	go func() {
		_, err = io.Copy(localConn, tunnel)
		if err != nil {
			fmt.Printf("io.Copy failed: %v", err)
		}
	}()
}

func tcpForwarder(tunnelAddress string, ipToIntercept string, portToIntercept string, wgListenPort string, wgPrivateKey string, wgPublicKey string, wgAllowedIp string) error {
	mtu := 1420
	localAddresses := []netip.Addr{netip.MustParseAddr(ipToIntercept)}
	dnsServers := []netip.Addr{}

	tun, tnet, err := netstack.CreateNetTUN(
		localAddresses,
		dnsServers,
		mtu)

	if err != nil {
		fmt.Printf("Error creating tunnel: %s", err)
		return err
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet("private_key=" + wgPrivateKey + "\n" +
		"listen_port=" + wgListenPort + "\n" +
		"public_key=" + wgPublicKey + "\n" +
		"allowed_ip=" + wgAllowedIp)

	interceptPort, err := strconv.Atoi(portToIntercept)
	if err != nil {
		fmt.Printf("Error parsing portToIntercept value %s: %s", portToIntercept, err)
		return err
	}

	// user land net stack for pulling out the traffic we want to forward
	localListener, err := tnet.ListenTCP(&net.TCPAddr{Port: interceptPort})
	if err != nil {
		fmt.Printf("net.Listen failed: %v", err)
		return err
	}

	for {
		localConn, err := localListener.Accept()
		if err != nil {
			fmt.Printf("listen.Accept failed: %v", err)
		}
		go forward(localConn, tunnelAddress)
	}
}

func Runfwd(tunnelAddress string, ipToIntercept string, portToIntercept string, wgListenPort string, wgPrivateKey string, wgPublicKey string, wgAllowedIp string) error {
	err := tcpForwarder(tunnelAddress, ipToIntercept, portToIntercept, wgListenPort, wgPrivateKey, wgPublicKey, wgAllowedIp)
	return err
}

// go build wfwd.go
// go run wfwd.go
func main() {

	if len(os.Args) != 3 {
		fmt.Println("Wireguard Forwarder: wfwd [tunnel address and port]] [config file]")
		fmt.Println("example: wfwd localhost:61704 exampleconfig.conf")
	} else {
		tunnelAddress := os.Args[1]
		configPath := os.Args[2]

		// IP address we intercept and forward e.g., 10.0.0.1
		ipToIntercept := ""
		// Port we are intercepting e.g., 80
		portToIntercept := ""
		// The port we receive wg traffic on e.g., 55211
		wgListenPort := ""
		// Our Secret Key (hex encoded)
		wgPrivateKey := ""
		// Pubkey of wg client sending us traffic (hex encoded)
		wgPublicKey := ""
		// IP range we say we route e.g., 10.0.0.1/8
		wgAllowedIp := ""

		var configfile, err = os.OpenFile(configPath, os.O_RDWR, 0644)
		if err != nil {
			fmt.Printf("Error opening config file %s, %s", configPath, err)
			return
		}
		defer configfile.Close()

		scanner := bufio.NewScanner(configfile)
		// optionally, resize scanner's capacity for lines over 64K, see next example
		for scanner.Scan() {
			line := scanner.Text()

			if line[0:2] == "//" {
				continue
			}

			key := strings.Split(line, "=")[0]
			value := strings.Split(line, "=")[1]

			if key == "ipToIntercept" {
				ipToIntercept = value
			} else if key == "portToIntercept" {
				portToIntercept = value
			} else if key == "wgListenPort" {
				wgListenPort = value
			} else if key == "wgPrivateKey" {
				wgPrivateKey = value
			} else if key == "wgPublicKey" {
				wgPublicKey = value
			} else if key == "wgAllowedIp" {
				wgAllowedIp = value
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		Runfwd(tunnelAddress, ipToIntercept, portToIntercept, wgListenPort, wgPrivateKey, wgPublicKey, wgAllowedIp)
	}

}
