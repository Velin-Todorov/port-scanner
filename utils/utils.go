package utils

import (
	"fmt"
	"strconv"
	"math"
	// "time"
	// "errors"
	// "strings"
	// "sync"
)

func determineWildcards(octets []string) []int {
	wildcards := []int{}
	for idx, octet := range octets {
		if octet == "*" {
			wildcards = append(wildcards, idx)
		}	
	}
	return wildcards
}

func determineFixedOctets(octets []string) ([]int, error) {
	fixedOctets := make([]int, 4)

	// Parse fixed octet values
	for i, octet := range octets {
		if octet != "*" {
			val, err := strconv.Atoi(octet)
			if err != nil || val < 0 || val > 255 {
				fmt.Printf("Invalid IP format: %s\n", octet)
				return []int{}, err
			}
			fixedOctets[i] = val
		}
	}
	return fixedOctets, nil
}


// Producer
func GenerateIPs(octets []string, ipCh chan <- string) {
	wildcards := determineWildcards(octets)
	fixedOctets, _ := determineFixedOctets(octets)

	totalCombinations := int(math.Pow(256, float64(len(wildcards))))

	for i := 1; i < totalCombinations - 1; i++ {
		address := make([]int, len(fixedOctets))
		copy(address, fixedOctets) 

		for j, pos := range wildcards {
			address[pos] = (i >> (j * 8)) & 0xFF 
		}

		ipAddress := fmt.Sprintf("%d.%d.%d.%d", address[0], address[1], address[2], address[3])
		ipCh <- ipAddress
	}
}

func DetermineCIDR(octets int) int {
	return octets * 8
}

// Crafting raw SYN Packet
func CraftPacket() byte {


}


