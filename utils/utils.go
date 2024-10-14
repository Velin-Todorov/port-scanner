package utils

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

func GenerateNextIP(ipAddress net.IP) net.IP {

	for i := len(ipAddress) - 1; i >= 0; i-- {
		ipAddress[i]++
		// Check if there is overflow
		// if there is no overflow, then we are done
		// else continue to the next byte
		if ipAddress[i] > 0 {
			break
		}
	}
	return ipAddress
}

func GenerateFirstUsableIP(ipAddress net.IP, cidr int) net.IP {
	// Calculate the first usable IP. I need to exclude the first one
	// since its the network address to identify the subnet
	ipAddressCopy := make(net.IP, len(ipAddress))
	copy(ipAddressCopy, ipAddress)

	firstIP := GenerateNextIP(ipAddressCopy)
	return firstIP
}

func GeneratePreviousIP(ipAddress net.IP) net.IP {
	for j := len(ipAddress) - 1; j >= 0; j-- {
		if ipAddress[j] > 0 {
			ipAddress[j]--
			break
		}
		ipAddress[j] = 255
	}

	return ipAddress
}

func GenerateLastUsableIP(ipAddress net.IP) net.IP {
	ipAddressCopy := make(net.IP, len(ipAddress))
	copy(ipAddressCopy, ipAddress)

	lastUsableIPAddress := GeneratePreviousIP(ipAddressCopy)

	return lastUsableIPAddress
}

func CalculateBroadcastIP(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()

	if ip == nil {
		log.Fatal("Only IPv4 addresses are supported in this function.")
	}

	mask := ipnet.Mask
	if len(mask) != 4 {
		log.Fatal("Invalid mask length for IPv4.")
	}

	broadcast := make(net.IP, 4)
	copy(broadcast, ip)

	// Perform bitwise OR between IP and inverted mask to get the broadcast address
	for i := 0; i < 4; i++ {
		broadcast[i] |= ^mask[i]
	}

	return broadcast

}

func DetermineCIDR(octets int) int {
	return octets * 8
}

func GenerateIPAddresses(octets []string, wildcardIndex int, wg *sync.WaitGroup, ch chan net.IP ) {
	defer wg.Done()

	for i := 0; i < 256; i++ {
		currentParts := make([]string, len(octets))
		copy(currentParts, octets)
		currentParts[wildcardIndex] = fmt.Sprintf("%d", i)
		generatedIP := strings.Join(currentParts, ".")

		fmt.Println(generatedIP)
		ipAddress := net.ParseIP(generatedIP)
		ch <- ipAddress
		
	}	

}