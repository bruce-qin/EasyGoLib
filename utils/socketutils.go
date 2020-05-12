package utils

import (
	"fmt"
	"github.com/emirpasic/gods/sets/hashset"
	"golang.org/x/net/ipv4"
	"math/rand"
	"net"
	"strings"
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
	port, _ = FindAvailableUDPPort(12000, 65535)
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

func FindSupportMulticastInterface() (infs []*net.Interface) {
	interfaces, _ := net.Interfaces()
out:
	for _, ifc := range interfaces {
		if ifc.Flags&net.FlagUp|net.FlagMulticast != net.FlagUp|net.FlagMulticast {
			continue out
		}
		addrs, _ := ifc.Addrs()
		var ip net.IP
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), "::1/") || strings.HasPrefix(addr.String(), "0:0:0:0:0:0:0:1/") || strings.Contains(addr.String(), "127.0.0.1") {
				continue out
			}
			switch v := addr.(type) {
			case *net.IPAddr:
				if v.IP.To4() != nil {
					ip = v.IP
				}
			case *net.IPNet:
				if v.IP.To4() != nil {
					ip = v.IP
				}
			default:
				continue
			}
		}
		if ip == nil {
			continue out
		}
		infs = append(infs, &ifc)
	}
	return
}

func ListenMulticastAddress(multicastAddr *net.UDPAddr, infs ...*net.Interface) (conn *ipv4.PacketConn, err error) {
	//if runtime.GOOS == "windows"{
	var p net.PacketConn
	p, err = net.ListenPacket("udp4", fmt.Sprint(":", multicastAddr.Port))
	if err != nil {
		return
	}
	conn = ipv4.NewPacketConn(p)
	if infs == nil || len(infs) == 0 {
		infs = FindSupportMulticastInterface()
	}
	for _, inf := range infs {
		err = conn.JoinGroup(inf, multicastAddr)
		if err != nil {
			return
		}
	}
	if err = conn.SetMulticastLoopback(true); err != nil {
		return
	}
	//udpConn := p.(*net.UDPConn)
	//file, _ := udpConn.File()
	//df := file.Fd()
	//
	//syscall.SetsockoptInt(df, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	return
	//} else {
	//	var s int
	//	s, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	//	if err != nil {
	//		return
	//	}
	//	if err = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
	//		return
	//	}
	//	if err = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); err != nil{
	//		return
	//	}
	//
	//	if err = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
	//		return
	//	}
	//
	//	for _, inf := range infs{
	//		if err = syscall.SetsockoptString(s, syscall.SOL_SOCKET, syscall.IP_MULTICAST_IF, inf.Name); err != nil {
	//			return
	//		}
	//	}
	//
	//	lsa := syscall.SockaddrInet4{Port: multicastAddr.Port}
	//	copy(lsa.Addr[:], multicastAddr.IP.To4())
	//
	//	if err = syscall.Bind(s, &lsa); err != nil {
	//		_ = syscall.Close(s)
	//		return
	//	}
	//	f := os.NewFile(uintptr(s), "")
	//	c, err := net.FilePacketConn(f)
	//	_ = f.Close()
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	p := ipv4.NewPacketConn(c)
	//
	//	return p, nil
	//}
}
