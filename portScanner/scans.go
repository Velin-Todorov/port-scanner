package portScanner

import (
	"fmt"
	"math"
	"net"
	// "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"port-scanner/utils"
)

var (
	DEFAULT_TIMEOUT         time.Duration = 3 * time.Second
	DEFAULT_CONCURENT_PORTS int32         = 100
	TOTAL_PORTS             int32         = 65535
)

func SimpleScan(host string, port string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)

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

	portCh := make(chan int, TOTAL_PORTS)
	resultCh := make(chan string, TOTAL_PORTS)

	// Producer
	go func() {
		for port := 1; port <= int(TOTAL_PORTS); port++ {
			portCh <- port
		}
		close(portCh)
	}()

	for i := 0; i < int(TOTAL_PORTS); i++ {
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

func SweepScan(hosts string, port int) ([]string, error) {

	var hostsWithOpenPort []string
	var wg sync.WaitGroup

	splitHosts := strings.Split(hosts, ",")
	portAsString := strconv.Itoa(port)

	for _, host := range splitHosts {
		if strings.Contains(host, "*") {
			bufferSize := int(math.Pow(256, float64(strings.Count(host, "*"))))

			ipCh := make(chan string, bufferSize)
			resultCh := make(chan string, bufferSize)

			octets := strings.Split(host, ".")

            // Producer
			go func() {
				utils.GenerateIPs(octets, ipCh)
				close(ipCh)
			}()

			// consumer
			for i := 0; i < bufferSize; i++ {
				wg.Add(1)

				go func() {
					defer wg.Done()
					for ipAddress := range ipCh {
						res, err := SimpleScan(ipAddress, portAsString)
                        if err != nil {
                            resultCh <- err.Error()
                            continue
                        }
						resultCh <- res
					}
				}()
			}

			go func() {
				wg.Wait()
				close(resultCh)
			}()

			for result := range resultCh {	
				hostsWithOpenPort = append(hostsWithOpenPort, result)
			}

			if len(hostsWithOpenPort) == 0 {
				return nil, fmt.Errorf("no open ports on host %s", host)
			}
			return hostsWithOpenPort, nil
		}
	}

	return hostsWithOpenPort, nil
}
