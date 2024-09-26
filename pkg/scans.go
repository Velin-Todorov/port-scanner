package pkg

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

func SimpleScan(host string, port string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)

	if err != nil {
		return fmt.Sprintf("Connecting to %s on port %s failed", host, port), err
	}

	defer conn.Close()

	return fmt.Sprintf("Port %s on host %s is opened", port, host), nil
}

func VanillaScan(host string) ([]string, error) {
	var openPorts []string

	for port := 0; port < 65536; port++ {
		portStr := strconv.Itoa(port)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 5*time.Second)

		if err != nil {
			fmt.Printf("connecting to %s on port %s failed", host, portStr)
			continue
		}
		
		conn.Close()

		openPorts = append(openPorts, fmt.Sprintf("Port %s on host %s is open", portStr, host))

	}
	if len(openPorts) == 0 {
		return nil, fmt.Errorf("no open ports on host %s", host)

	}

	return openPorts, nil
}