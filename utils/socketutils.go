package utils

import (
	"fmt"
	"github.com/emirpasic/gods/sets/hashset"
	"math/rand"
	"net"
)

const MinMulticastAddr = uint32(uint(225)<<24 | uint(255))

const MaxMulticastAddr = uint32(uint(239)<<24 | uint(255)<<16 | uint(255)<<8 | uint(255))

const SpecialMinMulticastAddr = uint32(uint(232) << 24)

const SpecialMaxMulticastAddr = uint32(uint(232)<<24 | uint(255)<<16 | uint(255)<<8 | uint(255))

const MulticastAddrLength = int(MaxMulticastAddr - MinMulticastAddr)

const SpecialMulticastAddrLength = SpecialMaxMulticastAddr - SpecialMinMulticastAddr

type socketType interface {
	isPortAvailable(port uint16) bool
}

type TCPSocket struct {
}

type UDPSocket struct {
}

type PortErrorDesc struct {
	Msg string
}

func RandomMulticastAddress() (addr string, port uint16) {
	i := uint32(rand.Intn(MulticastAddrLength)) + MinMulticastAddr + 1
	if i >= SpecialMinMulticastAddr && i <= SpecialMaxMulticastAddr {
		i += SpecialMulticastAddrLength
	}
	addr = FormatIntAddress(i)
	port = FindAvailableUDPPort(0, 65535) + 1
	return
}

func FormatIntAddress(a uint32) (addr string) {
	return fmt.Sprintf("%d.%d.%d.%d", uint(a>>24&0xff), uint(a>>16&0xff), uint(a>>8&0xff), uint(a&0xff))
}

func (TCPSocket) isPortAvailable(port uint16) bool {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprint(":", port))
	if err != nil {
		return false
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return false
	}
	defer l.Close()
	return true
}

func (UDPSocket) isPortAvailable(port uint16) bool {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprint(":", port))
	if err != nil {
		return false
	}
	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return false
	}
	defer l.Close()
	return true
}

func (pe *PortErrorDesc) Error() string {
	return pe.Msg
}

var udpSocket *UDPSocket = &UDPSocket{}

var tcpSocket *TCPSocket = &TCPSocket{}

func FindAvailableTCPPort(min uint16, max uint16) (port uint16, err error) {
	portSet := hashset.New()
	portRange := max - min
	maxRandom := portRange >> 1
	//随机获取一半的端口
	for portSet.Size() < int(maxRandom) {
		port := uint16(rand.Intn(int(portRange))) + min
		if portSet.Contains(port) {
			continue
		}
		portSet.Add(port)
		if tcpSocket.isPortAvailable(port) {
			return port, nil
		}
	}
	//随机一半后还未找到可用端口，则遍历查询
	for port = max; port > min; port-- {
		if portSet.Contains(port) {
			continue
		}
		if tcpSocket.isPortAvailable(port) {
			return port, nil
		}
	}
	return 0, &PortErrorDesc{fmt.Sprintf("not engough available tcp port[%d:%d]", min, max)}
}

func FindAvailableUDPPort(min uint16, max uint16) (port uint16, err error) {
	portSet := hashset.New()
	portRange := max - min
	maxRandom := portRange >> 1
	//随机获取一半的端口
	for portSet.Size() < int(maxRandom) {
		port := uint16(rand.Intn(int(portRange))) + min
		if portSet.Contains(port) {
			continue
		}
		portSet.Add(port)
		if udpSocket.isPortAvailable(port) {
			return port, nil
		}
	}
	//随机一半后还未找到可用端口，则遍历查询
	for port = max; port > min; port-- {
		if portSet.Contains(port) {
			continue
		}
		if udpSocket.isPortAvailable(port) {
			return port, nil
		}
	}
	return 0, &PortErrorDesc{fmt.Sprintf("not engough available udp port[%d:%d]", min, max)}
}
