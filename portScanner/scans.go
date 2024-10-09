package portScanner

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	DEFAULT_TIMEOUT         time.Duration = 3 * time.Second
	DEFAULT_CONCURENT_PORTS int32         = 100
)

func SimpleScan(host string, port string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)

	if err != nil {
		return fmt.Sprintf("Connecting to %s on port %s failed", host, port), err
	}

	defer conn.Close()

	return fmt.Sprintf("Port %s on host %s is opened", port, host), nil
}

func VanillaScan(host string, maxConcurrentPorts int32, timeout time.Duration) ([]string, error) {
	var openPorts []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	portCh := make(chan int, maxConcurrentPorts)
	resultCh := make(chan string)

	// Producer
	go func() {
		for port := 1; port <= 65535; port++ {
			portCh <- port
		}
		close(portCh)
	}()

	for i:=0; i < int(maxConcurrentPorts); i++ {
		wg.Add(1)

		// Consumer
		go func() {
			defer wg.Done()
			for port := range portCh {
				portStr := strconv.Itoa(port)
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), timeout)
				if err != nil {
					continue
				}
				conn.Close()
				result := fmt.Sprintf("Port %s on host %s is open", portStr, host)
				resultCh <- result		
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		mu.Lock()
		openPorts = append(openPorts, result)
		mu.Unlock()
	}
	
	if len(openPorts) == 0 {
		return nil, fmt.Errorf("no open ports on host %s", host)
	}

	return openPorts, nil
}
