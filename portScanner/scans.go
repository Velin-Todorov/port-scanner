package portScanner

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"log"
)

var (
	DEFAULT_TIMEOUT         time.Duration = 3 * time.Second
	DEFAULT_CONCURENT_PORTS int32         = 100
)

func SimpleScan(host string, port string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Millisecond)

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

	for i := 0; i < int(maxConcurrentPorts); i++ {
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
	splitHosts := strings.Split(hosts, ",")
	portAsString := strconv.Itoa(port)

	for _, host := range splitHosts {
		if strings.Contains(host, "*") {
			stars := strings.Count(host, "*")
			numberOfOctetsSet := 4 - stars
			cidr := determineCIDR(numberOfOctetsSet)
			newIPAddr := strings.ReplaceAll(host, "*", "0") + "/" + strconv.Itoa(cidr)

			ip, ipnet, err := net.ParseCIDR(newIPAddr)
			if err != nil {
				log.Fatal(err)
			}
			
			// Calculate the first usable IP. I need to exclude the first one
			// since its the network address to identify the subnet and the last one
			// which is the broadcast address
			firstUsableIPAddress := make(net.IP, len(ip))
			copy(firstUsableIPAddress, ip)
			generateIPs(firstUsableIPAddress)
			
			fmt.Println(ipnet)
			count := 0
			for firstUsableIPAddress := firstUsableIPAddress.Mask(ipnet.Mask); ipnet.Contains(firstUsableIPAddress); generateIPs(firstUsableIPAddress){
				fmt.Println(firstUsableIPAddress)
				count++
			}

			// to verify at the end if the list of IP addrs has the expected length
			possibleIpAddressesCount := math.Pow(2, float64((32-(numberOfOctetsSet*8)))) - 2

			fmt.Println(count == int(possibleIpAddressesCount))

		}
	}

	fmt.Println(portAsString)

	return hostsWithOpenPort, nil
}

func determineCIDR(octets int) int {
	cidr := 0

	switch octets {
	case 3:
		cidr = 24

	case 2:
		cidr = 16

	case 1: 
		cidr = 8
	}

	return cidr
}

func generateIPs(ipAddress net.IP) {
	for i := len(ipAddress) - 1; i >= 0; i-- {
		ipAddress[i]++
		if ipAddress[i] > 0 {
			break
		}
	}
}