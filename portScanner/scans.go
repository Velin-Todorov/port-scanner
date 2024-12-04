package portScanner

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"

	// "net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
    "runtime"

	"port-scanner/utils"
)

type Scanner interface {
	SimpleScan(host string, port string) (string, error)
	VanillaScan(host string, maxConcurrentPorts int32, timeout time.Duration) ([]string, error)
	SweepScan(hosts string, port string) ([]string, error)
}

type PortScanner struct{}

func NewPortScanner() *PortScanner {
	portScanner := new(PortScanner)
	return portScanner
}

var (
	DEFAULT_TIMEOUT         time.Duration = 3 * time.Second
	DEFAULT_CONCURENT_PORTS int32         = 100
	TOTAL_PORTS             int32         = 65535
)

func (ps *PortScanner) SimpleScan(host string, port string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)

	if err != nil {
		return fmt.Sprintf("Connecting to %s on port %s failed", host, port), err
	}

	defer conn.Close()

	return fmt.Sprintf("Port %s on host %s is opened", port, host), nil
}

func (ps *PortScanner) VanillaScan(host string, maxConcurrentPorts int32, timeout time.Duration) ([]string, error) {
	var openPorts []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	portCh := make(chan int, maxConcurrentPorts)
	resultCh := make(chan string, maxConcurrentPorts)

	// Producer
	go func() {
		for port := 1; port <= int(maxConcurrentPorts); port++ {
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

func (ps *PortScanner) SweepScan(hosts string, port int) ([]string, error) {

	var openPorts []string
	var wg sync.WaitGroup

	splitHosts := strings.Split(hosts, ",")
	portAsString := strconv.Itoa(port)

	for _, host := range splitHosts {
		// wildcard addresses
		if strings.Contains(host, "*") {
			bufferSize := int(math.Pow(256, float64(strings.Count(host, "*"))))
			fmt.Println(bufferSize)

			ipCh := make(chan string, 10)
			resultCh := make(chan string, 10)

			octets := strings.Split(host, ".")

			// Producer
			go func() {
				utils.GenerateIPs(octets, ipCh)
			}()
            
            wg.Add(bufferSize - 2)
			// consumer
			for i := 0; i < int(math.Pow(float64(runtime.NumCPU()), 3)); i++ {
				go func() {
					for ipAddress := range ipCh {
						res, err := ps.SimpleScan(ipAddress, portAsString)
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
				close(ipCh)
				close(resultCh)
			}()

			for result := range resultCh {
				openPorts = append(openPorts, result)
				wg.Done()
			}

			if len(openPorts) == 0 {
				return nil, fmt.Errorf("no open ports on host %s", host)
			}

			return openPorts, nil
		} else if strings.Contains(host, "/") {
			// CIDR hosts
			ipAddress, ipNet, _ := net.ParseCIDR(host)
			mask, _ := ipNet.Mask.Size()
			hostBits := 32 - mask
			totalHostAddresses := (1 << hostBits) - 2
			ipAddress4 := ipAddress.To4()

			baseAddress := uint32(ipAddress4[0])<<24 | uint32(ipAddress4[1])<<16 | uint32(ipAddress4[2])<<8 | uint32(ipAddress4[3])

			for i := 0; i < totalHostAddresses; i++ {
				hostIp := baseAddress + uint32(i)

				newAddress := net.IPv4(byte(hostIp>>24), byte((hostIp>>16)&0xFF), byte((hostIp>>8)&0xFF), byte(hostIp&0xFF))
				scan, _ := ps.SimpleScan(newAddress.String(), portAsString)
				openPorts = append(openPorts, scan)
			}

		} else {
			// normal hosts
			scan, _ := ps.SimpleScan(host, portAsString)
			openPorts = append(openPorts, scan)
		}
	}

	return openPorts, nil
}

func (ps *PortScanner) SynScan(host, ports string) ([]string, error) {
	var openPorts []string

	splitPorts := strings.Split(ports, ",")
	parsedHost := net.ParseIP(host)

	if parsedHost == nil {
		log.Fatalf("Failed to parse host: %s", host)
		return nil, nil
	}

	// Spawn a goroutine per port
	// goRoutines := len(splitPorts)
	_ = len(splitPorts)

    addrs, err := net.LookupHost(host)

    if err != nil {
        log.Fatalf("Error resolving %s. %s\n", host, err)
    }

    remoteAddr := addrs[0]

	srcIP, err := utils.GetSourceIP()

	if err != nil {
		log.Fatalf("Failed to obtain source IP")
		return nil, err
	}

	for _, port := range splitPorts {
		portAsInt, err := strconv.Atoi(port)

		if err != nil {
			log.Printf("Failed to parse port: %s", port)
			continue
		}

		packet := utils.TCPHeader{
			Source:      0xaa47, // Random port
			Destination: uint32(portAsInt),
			SeqNum:      rand.Uint32(),
			AckNum:      0,
			DataOffset:  5,
			Reserved:    0,
			ECN:         0,
			Ctrl:        2, //SYN
			Window:      0xaaaa,
			Checksum:    0,
			Urgent:      0,
			Options:     []utils.TCPOption{},
		}

		data := packet.Marshal()
		packet.Checksum = utils.Csum(data, utils.To4byte(srcIP.String()), utils.To4byte(host))

		data = packet.Marshal()

        conn, err := net.Dial("ip4:tcp", host)

        if err != nil {
            log.Fatalf("Dial: %s\n", err)
        }

        numWrote, err := conn.Write(data)

        if err != nil {
            log.Fatalf("Write: %s\n", err)
        }
        if numWrote != len(data) {
            log.Fatalf("Short write. Wrote %d/%d bytes\n", numWrote, len(data))
        }
    
        conn.Close()

		if err != nil {
			panic(err)
		}
        
        

        utils.ReceiveSynAck(srcIP.String(), remoteAddr)

        if err != nil {
            panic(err)
        }
       
	}

	// syscall.

	// craft syn pack
	// send the syn pack
	// check the response
	// if we get syn/ack, then send a rst packet and mark the port as opened,
	// otherwise, try one more time
	// if it does not respond, then mark the port as filtered

	return openPorts, nil

}
