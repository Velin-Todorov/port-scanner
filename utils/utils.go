package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"strings"
	// "time"
	// "errors"
	// "strings"
	// "sync"
)

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000
)

type TCPHeader struct {
	Source      uint32
	Destination uint32
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8
	Reserved    uint8
	ECN         uint8
	Ctrl        uint8
	Window      uint16
	Checksum    uint16
	Urgent      uint16
	Options     []TCPOption
}

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

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
func GenerateIPs(octets []string, ipCh chan<- string) {
	wildcards := determineWildcards(octets)
	fixedOctets, _ := determineFixedOctets(octets)

	totalCombinations := int(math.Pow(256, float64(len(wildcards))))

	for i := 1; i < totalCombinations-1; i++ {
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

func NewTCPHeader(data []byte) *TCPHeader {
    var tcp TCPHeader

    r := bytes.NewReader(data)
    binary.Read(r, binary.BigEndian, &tcp.Source)
    binary.Read(r, binary.BigEndian, &tcp.Destination)
    binary.Read(r, binary.BigEndian, &tcp.SeqNum)
    binary.Read(r, binary.BigEndian, &tcp.AckNum)

    var mix uint16
    binary.Read(r, binary.BigEndian, &mix)
    tcp.DataOffset = byte(mix >> 12)
    tcp.Reserved = byte(mix >> 9 & 7)
    tcp.ECN = byte(mix >> 6 & 7)
    tcp.Ctrl = byte(mix & 0x3f)

    binary.Read(r, binary.BigEndian, &tcp.Window)
    binary.Read(r, binary.BigEndian, &tcp.Checksum)
    binary.Read(r, binary.BigEndian, &tcp.Urgent)

    return &tcp
}

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
    // bitwise AND to check if the bit is set.
    return tcp.Ctrl&flagBit != 0
}

func (tcp *TCPHeader) Marshal() []byte {
    buf := new(bytes.Buffer)

    binary.Write(buf, binary.BigEndian, tcp.Source)
    binary.Write(buf, binary.BigEndian, tcp.Destination)
    binary.Write(buf, binary.BigEndian, tcp.SeqNum)
    binary.Write(buf, binary.BigEndian, tcp.AckNum)

    mix := uint16(tcp.DataOffset) << 12 |
            uint16(tcp.Reserved) << 9 |
            uint16(tcp.ECN) << 6 |
            uint16(tcp.Ctrl)
    
    binary.Write(buf, binary.BigEndian, mix)
    binary.Write(buf, binary.BigEndian, tcp.Window)
    binary.Write(buf, binary.BigEndian, tcp.Checksum)
    binary.Write(buf, binary.BigEndian, tcp.Urgent)

    for _, option := range tcp.Options {
        binary.Write(buf, binary.BigEndian, option.Kind)
        if option.Length > 1 {
            binary.Write(buf, binary.BigEndian, option.Length)
            binary.Write(buf, binary.BigEndian, option.Data)
        }
    }
    out := buf.Bytes()
    pad := 20 - len(out)

    for i := 0; i < pad; i++ {
        out = append(out, 0)
    }

    return out
}

// Compute checksum
func Csum(data []byte, srcip, dstip [4]byte) uint16 {

    pseudoHeader := []byte{
        srcip[0], srcip[1], srcip[2], srcip[3],
        dstip[0], dstip[1], dstip[2], dstip[3],
        0,
        6,
        0, byte(len(data)),
    }

    csum := make([]byte, 0, len(pseudoHeader) + len(data))
    csum = append(csum, pseudoHeader...)
    csum = append(csum, data...)

    lenCsum := len(csum)
    var nextWord uint16
    var sum uint32
    for i := 0; i + 1 < len(csum); i += 2 {
        nextWord = uint16(csum[i]) << 8 | uint16(csum[i + 1])
        sum += uint32(nextWord)
    }

    if lenCsum % 2 != 0 {
        sum += uint32(csum[len(csum) - 1])
    }

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)

    return uint16(^sum)
}

func IPtoUint32(ip net.IP) uint32 {
    ip = ip.To4()
    
    if ip == nil {
        return 0
    }

    return uint32(ip[0]) << 24 | uint32(ip[1]) << 16 | uint32(ip[2]) << 8 | uint32(ip[3])
}

func GetSourceIP() (net.IP, error) {
    conn, err := net.Dial("udp", "8.8.8.8:80")

    if err != nil {
        return nil, err
    }

    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP, nil
}

func To4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}


func ReceiveSynAck(localAddress, remoteAddress string) {
	netaddr, err := net.ResolveIPAddr("ip4", localAddress)
	if err != nil {
		log.Fatalf("net.ResolveIPAddr: %s. %s\n", localAddress, netaddr)
	}

	conn, err := net.ListenIP("ip4:tcp", netaddr)
	if err != nil {
		log.Fatalf("ListenIP: %s\n", err)
	}

	for {
		buf := make([]byte, 1024)
		numRead, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("ReadFrom: %s\n", err)
		}
		fmt.Println(raddr)
		if raddr.String() != remoteAddress {
			
			// this is not the packet we are looking for
			continue
		}
		tcp := NewTCPHeader(buf[:numRead])
		fmt.Println(tcp.Ctrl)
		if tcp.HasFlag(SYN) || (tcp.HasFlag(SYN) && tcp.HasFlag(ACK)) {
			break
		}
	}
}