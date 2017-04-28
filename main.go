package main

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/link/sniffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"
)

// #cgo CFLAGS: -I./ZeroTierOne/include
// #cgo LDFLAGS: -L./ -lzerotier -lstdc++
// #include <string.h>
// #include <ZeroTierOne.h>
// static inline enum ZT_ResultCode newNode(ZT_Node **node, uintptr_t uptr, void *tptr, const struct ZT_Node_Callbacks *callbacks, uint64_t now) {
// 	return ZT_Node_new(node, (void*)uptr, tptr, callbacks, now);
// }
// long dataStoreGet(ZT_Node *node, void *userPtr, void *threadPtr, char *objectName, void *buffer, long unsigned int size, long unsigned int offset, long unsigned int *resSize);
// int dataStorePut(ZT_Node *node, void *userPtr, void *threadPtr, char *objectName, void *buffer, long unsigned int size, int secure);
// int wirePacketSend(ZT_Node *node, void *userPtr, void *threadPtr, struct sockaddr_storage *localAddr, struct sockaddr_storage *remoteAddr, void *buffer, unsigned int size, unsigned int ttl);
// void eventCallback(ZT_Node *node, void *userPtr, void *threadPtr, enum ZT_Event event, void *metaEventData);
// void virtualNetworkFrame(ZT_Node *node, void *userPtr, void *threadPtr, uint64_t networkId, void *networkUserPtr, uint64_t srcMac, uint64_t dstMac, unsigned int etherType, unsigned int vlanId, void *buffer, unsigned int size);
// int virtualNetworkConfig(ZT_Node *node, void *userPtr, void *threadPtr, uint64_t networkId, void *networkUserPtr, enum ZT_VirtualNetworkConfigOperation configOp, ZT_VirtualNetworkConfig *netConfig);
import "C"

type MACIPPair struct {
	MAC [6]byte
	IP  net.IP
}

type ZeroTierNetwork struct {
	id         uint64
	ip         net.IP
	mac        uint64
	stack      tcpip.Stack
	linkEP     *channel.Endpoint
	MACIPPairs []MACIPPair

	parentNode *ZeroTierNode
}

type ZeroTierNode struct {
	node     unsafe.Pointer
	sock     *net.UDPConn
	networks map[uint64]*ZeroTierNetwork

	dataStore map[string][]byte

	shuttingDown bool
	threadWG     sync.WaitGroup
}

func NewZeroTierNode() (*ZeroTierNode, error) {
	node := &ZeroTierNode{
		networks:  make(map[uint64]*ZeroTierNetwork),
		dataStore: make(map[string][]byte),
	}

	if err := node.start(); err != nil {
		return nil, err
	}

	return node, nil
}

func LoadZeroTierNode(config string) (*ZeroTierNode, error) {
	node := &ZeroTierNode{
		networks:  make(map[uint64]*ZeroTierNetwork),
		dataStore: make(map[string][]byte),
	}

	file, err := os.Open(config)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&node.dataStore); err != nil {
		return nil, err
	}

	if err := node.start(); err != nil {
		return nil, err
	}

	return node, nil
}

func (this *ZeroTierNode) start() error {
	var err error
	this.sock, err = net.ListenUDP("udp", nil)
	if err != nil {
		return errors.New("NewZeroTierNode: failed to create socket and bind to UDP port")
	}

	var callbacks C.struct_ZT_Node_Callbacks
	callbacks.version = 0
	callbacks.dataStoreGetFunction = C.ZT_DataStoreGetFunction(C.dataStoreGet)
	callbacks.dataStorePutFunction = C.ZT_DataStorePutFunction(C.dataStorePut)
	callbacks.wirePacketSendFunction = C.ZT_WirePacketSendFunction(C.wirePacketSend)
	callbacks.virtualNetworkFrameFunction = C.ZT_VirtualNetworkFrameFunction(C.virtualNetworkFrame)
	callbacks.virtualNetworkConfigFunction = C.ZT_VirtualNetworkConfigFunction(C.virtualNetworkConfig)
	callbacks.eventCallback = C.ZT_EventCallback(C.eventCallback)

	// WARN: bypasses cgo Go-Go pointer checks, which should be fine as long as Close is called
	result := C.newNode(&this.node, C.uintptr_t(uintptr(unsafe.Pointer(this))), nil, &callbacks, getNow())
	if result != 0 {
		return errors.New(fmt.Sprintf("NewZeroTierNode: ZT_Node_new failed with error code: %d", result))
	}

	this.threadWG.Add(3)

	go func() {
		defer this.threadWG.Done()

		for !this.shuttingDown {
			var deadline C.uint64_t
			result := C.ZT_Node_processBackgroundTasks(this.node, nil, getNow(), &deadline)
			if result != 0 {
				panic(fmt.Sprintf("ProcessBackgroundTasksThread: ZT_Node_processBackgroundTasks failed with error code: %d", result))
			}

			delta := int64(deadline - getNow())
			time.Sleep(time.Millisecond * time.Duration(delta))
		}
	}()

	go func() {
		defer this.threadWG.Done()

		buffer := make([]byte, 3200)
		for !this.shuttingDown {
			this.sock.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := this.sock.ReadFrom(buffer)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				panic(fmt.Sprintf("ProcessIncomingUDPThread: failed with error: %s", err))
			}
			actualAddr, err := net.ResolveUDPAddr("udp", addr.String())
			if err != nil {
				panic(fmt.Sprintf("ProcessIncomingUDPThread: resolution failed with error: %s", err))
			}
			var remoteAddr syscall.RawSockaddrInet4
			copy(remoteAddr.Addr[:], actualAddr.IP.To4()[:])
			remoteAddr.Family = syscall.AF_INET
			remoteAddr.Port = uint16(actualAddr.Port)>>8 | ((uint16(actualAddr.Port) & 0xFF) << 8)
			remoteAddrRaw := (*C.struct_sockaddr_storage)(unsafe.Pointer(&remoteAddr))
			var deadline C.uint64_t
			result := C.ZT_Node_processWirePacket(this.node, nil, getNow(), &C.ZT_SOCKADDR_NULL, remoteAddrRaw, unsafe.Pointer(&buffer[0]), C.uint(n), &deadline)
			if result != 0 {
				panic(fmt.Sprintf("ProcessIncomingUDPThread: ZT_Node_processWirePacket failed with error code: %d", result))
			}
		}
	}()

	go func() {
		defer this.threadWG.Done()

		for !this.shuttingDown {
			for _, network := range this.networks {
				select {
				case pkt := <-network.linkEP.C:
					if pkt.Proto == header.IPv4ProtocolNumber {
						v := make(buffer.View, len(pkt.Header)+len(pkt.Payload))
						copy(v, pkt.Header)
						copy(v[len(pkt.Header):], pkt.Payload)

						h := header.IPv4(v)
						network.SendToIPv4(net.IP(h.DestinationAddress().To4()), v)
					}
				case <-time.After(time.Millisecond * 100):
					// pass
				}
			}
		}
	}()

	return nil
}

func (this *ZeroTierNode) Close() {
	this.shuttingDown = true
	this.threadWG.Wait()
	C.ZT_Node_delete(this.node)
}

func (this *ZeroTierNode) Join(networkId uint64) (*ZeroTierNetwork, error) {
	result := C.ZT_Node_join(this.node, C.uint64_t(networkId), nil, nil)
	if result != 0 {
		return nil, errors.New(fmt.Sprintf("Join: ZT_Node_join failed with error code: %d", result))
	}
	// TODO: go-ify
	start := time.Now().Unix()
	for time.Now().Unix()-start < 3000 {
		if network, ok := this.networks[networkId]; ok {
			return network, nil
		}

		time.Sleep(time.Millisecond * 100)
	}
	return nil, errors.New("Join: joining the network timed out")
}

func (this *ZeroTierNode) Save(config string) error {
	file, err := os.Create(config)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(&this.dataStore); err != nil {
		return err
	}
	return nil
}

func (this *ZeroTierNetwork) SubscribeMulticast(mac uint64, adi uint32) {
	result := C.ZT_Node_multicastSubscribe(unsafe.Pointer(this.parentNode.node), nil, C.uint64_t(this.id), C.uint64_t(mac), C.ulong(adi))
	if result != 0 {
		panic("")
	}
}

func (this *ZeroTierNetwork) SendToMAC(mac [6]byte, data []byte, protocolNum tcpip.NetworkProtocolNumber) {
	paddedMac := append([]byte{0x00, 0x00}, mac[:]...)
	macInt := binary.BigEndian.Uint64(paddedMac)

	var deadline C.uint64_t
	result := C.ZT_Node_processVirtualNetworkFrame(this.parentNode.node, nil, getNow(), C.uint64_t(this.id), C.uint64_t(this.mac), C.uint64_t(macInt), C.uint(protocolNum), 0, unsafe.Pointer(&data[0]), C.uint(len(data)), &deadline)
	if result != 0 {
		panic("")
	}
}

func (this *ZeroTierNetwork) SendToIPv4(ip net.IP, data []byte) {
	mac, ok := this.lookupMAC(ip)
	if !ok {
		fmt.Println("[ARP] unknown mac for ip")
		this.SendARPRequest(ip)
	} else {
		this.SendToMAC(mac, data, header.IPv4ProtocolNumber)
	}
}

func (this *ZeroTierNetwork) SendARPRequest(ip net.IP) {
	fmt.Println("sending ARP request", ip)

	v := make(buffer.View, header.ARPSize)
	hReply := header.ARP(v)
	hReply.SetIPv4OverEthernet()
	hReply.SetOp(header.ARPRequest)

	var ourMAC [8]byte
	binary.BigEndian.PutUint64(ourMAC[:], this.mac)

	copy(hReply.HardwareAddressSender(), ourMAC[2:])
	copy(hReply.ProtocolAddressSender(), this.ip)
	copy(hReply.ProtocolAddressTarget(), ip)

	this.SendToMAC([6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, v, header.ARPProtocolNumber)
}

func (this *ZeroTierNetwork) tryAddMACIPPair(mac [6]byte, ip net.IP) {
	found := false
	for i, pair := range this.MACIPPairs {
		if pair.IP.Equal(ip) || bytes.Equal(pair.MAC[:], mac[:]) {
			// update the existing entry, is this wise?
			this.MACIPPairs[i] = MACIPPair{mac, ip}
			fmt.Println("[ARP] update: ", ip, "is at", mac)
			found = true
		}
	}
	if !found {
		this.MACIPPairs = append(this.MACIPPairs, MACIPPair{mac, ip})
		fmt.Println("[ARP]", ip, "is at", mac)
	}
}

func (this *ZeroTierNetwork) lookupMAC(ip net.IP) ([6]byte, bool) {
	for _, pair := range this.MACIPPairs {
		if pair.IP.Equal(ip) {
			return pair.MAC, true
		}
	}

	return [6]byte{}, false
}

//export dataStoreGet
func dataStoreGet(node *C.ZT_Node, userPtr unsafe.Pointer, threadPtr unsafe.Pointer, objectNameRaw *C.char, buffer unsafe.Pointer, sizeRaw C.ulong, offsetRaw C.ulong, resSize *C.ulong) C.long {
	this := (*ZeroTierNode)(userPtr)

	objectName := C.GoString(objectNameRaw)
	fmt.Println("dataStoreGet:", objectName)

	size := int(sizeRaw)
	offset := int(offsetRaw)

	if data, ok := this.dataStore[objectName]; ok {
		*resSize = C.ulong(len(data))

		if offset >= len(data) {
			return 0
		}
		data = data[offset:]

		if size >= len(data) {
			size = len(data)
		}
		data = data[:size]

		C.memcpy(buffer, unsafe.Pointer(&data[0]), C.size_t(size))

		return C.long(len(data))
	}

	return -1
}

//export dataStorePut
func dataStorePut(node *C.ZT_Node, userPtr unsafe.Pointer, threadPtr unsafe.Pointer, objectNameRaw *C.char, buffer unsafe.Pointer, size C.ulong, secure C.int) C.int {
	this := (*ZeroTierNode)(userPtr)

	objectName := C.GoString(objectNameRaw)
	fmt.Println("dataStorePut", objectName)

	data := C.GoBytes(buffer, C.int(size))
	this.dataStore[objectName] = data

	return 0
}

//export wirePacketSend
func wirePacketSend(node *C.ZT_Node, userPtr unsafe.Pointer, threadPtr unsafe.Pointer, localAddr *C.struct_sockaddr_storage, remoteAddrRaw *C.struct_sockaddr_storage, bufferRaw unsafe.Pointer, size C.uint, ttl C.uint) C.int {
	this := (*ZeroTierNode)(userPtr)

	remoteAddr := *(*syscall.RawSockaddrInet4)(unsafe.Pointer(remoteAddrRaw))
	destIP := net.IP(remoteAddr.Addr[:])
	ip, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", destIP.String(), remoteAddr.Port>>8|((remoteAddr.Port&0xFF)<<8)))
	if err != nil {
		panic(err)
	}
	//fmt.Println("wirePacketSend", ip)
	buffer := C.GoBytes(bufferRaw, C.int(size))
	_, err = this.sock.WriteTo(buffer, ip)
	if err != nil {
		panic(err)
	}
	return 0
}

//export eventCallback
func eventCallback(node *C.ZT_Node, userPtr unsafe.Pointer, threadPtr unsafe.Pointer, event C.enum_ZT_Event, metaEventData unsafe.Pointer) {
	desc := ""
	if event == 5 && metaEventData != nil {
		desc = C.GoString((*C.char)(metaEventData))
	}
	//fmt.Println("eventCallback:", event, desc)
	_ = desc
}

//export virtualNetworkFrame
func virtualNetworkFrame(node *C.ZT_Node, userPtr unsafe.Pointer, threadPtr unsafe.Pointer, networkId C.uint64_t, networkUserPtr unsafe.Pointer, srcMac C.uint64_t, dstMac C.uint64_t, etherTypeRaw C.uint, vlanId C.uint, bufferRaw unsafe.Pointer, size C.uint) {
	this := (*ZeroTierNode)(userPtr)

	network, ok := this.networks[uint64(networkId)]
	if !ok {
		return
	}

	fmt.Println("virtualNetworkFrame", srcMac, dstMac)

	etherType := tcpip.NetworkProtocolNumber(etherTypeRaw)
	if etherType == header.ARPProtocolNumber {
		v := make(buffer.View, int(size))
		copy(v, C.GoBytes(bufferRaw, C.int(size)))
		h := header.ARP(v)
		if h.Op() == header.ARPRequest {
			// TODO: check its this node they want
			v := make(buffer.View, header.ARPSize)
			hReply := header.ARP(v)
			hReply.SetIPv4OverEthernet()
			hReply.SetOp(header.ARPReply)

			var ourMAC [8]byte
			binary.BigEndian.PutUint64(ourMAC[:], network.mac)

			copy(hReply.HardwareAddressSender(), ourMAC[2:])
			copy(hReply.ProtocolAddressSender(), network.ip)
			copy(hReply.HardwareAddressTarget(), h.HardwareAddressSender())
			copy(hReply.ProtocolAddressTarget(), h.ProtocolAddressSender())

			var deadline C.uint64_t
			result := C.ZT_Node_processVirtualNetworkFrame(this.node, nil, getNow(), networkId, C.uint64_t(network.mac), srcMac, etherTypeRaw, vlanId, unsafe.Pointer(&v[0]), C.uint(header.ARPSize), &deadline)
			if result != 0 {
				panic("")
			}
		}

		var MAC [6]byte
		copy(MAC[:], h.HardwareAddressSender())
		network.tryAddMACIPPair(MAC, net.IP(h.ProtocolAddressSender()))
	} else if etherType == header.IPv4ProtocolNumber {
		buf := make(buffer.View, int(size))
		copy(buf, C.GoBytes(bufferRaw, C.int(size)))
		vv := buf.ToVectorisedView([1]buffer.View{})
		network.linkEP.Inject(ipv4.ProtocolNumber, &vv)
	}
}

//export virtualNetworkConfig
func virtualNetworkConfig(node *C.ZT_Node, userPtr unsafe.Pointer, threadPtr unsafe.Pointer, networkId C.uint64_t, networkUserPtr unsafe.Pointer, configOp C.enum_ZT_VirtualNetworkConfigOperation, netConfig *C.ZT_VirtualNetworkConfig) C.int {
	this := (*ZeroTierNode)(userPtr)

	if configOp == 2 {
		fmt.Println("ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_CONFIG_UPDATE")

		var status C.ZT_NodeStatus
		C.ZT_Node_status(unsafe.Pointer(node), &status)
		fmt.Printf("id: %X\n", status.address)

		if netConfig.assignedAddressCount > 0 {
			network, ok := this.networks[uint64(networkId)]
			if !ok {
				network = &ZeroTierNetwork{
					id:         uint64(networkId),
					stack:      stack.New([]string{ipv4.ProtocolName}, []string{ipv4.PingProtocolName, tcp.ProtocolName}),
					parentNode: this,
				}

				id, linkEP := channel.New(256, uint32(netConfig.mtu), "")
				id = sniffer.New(id)
				if err := network.stack.CreateNIC(1, id); err != nil {
					panic(err)
				}

				network.stack.SetRouteTable([]tcpip.Route{
					{
						Destination: "\x00\x00\x00\x00",
						Mask:        "\x00\x00\x00\x00",
						Gateway:     "",
						NIC:         1,
					},
				})

				network.linkEP = linkEP
				this.networks[uint64(networkId)] = network
			}

			network.mac = uint64(netConfig.mac)

			for i := 0; i < int(netConfig.assignedAddressCount); i++ {
				remoteAddr := *(*syscall.RawSockaddrInet4)(unsafe.Pointer(&netConfig.assignedAddresses[i]))
				ipInt := binary.BigEndian.Uint32(remoteAddr.Addr[:])
				if ipInt == 0 {
					continue
				}
				network.ip = net.IP(remoteAddr.Addr[:])
				fmt.Println(network.ip)

				// subscribe to broadcast packets for this ip (required for ARP)
				C.ZT_Node_multicastSubscribe(unsafe.Pointer(node), nil, networkId, 0xFFFFFFFFFFFF, C.ulong(ipInt))
			}

			if network.ip != nil {
				network.stack.AddAddress(1, ipv4.ProtocolNumber, tcpip.Address(network.ip))
			}
		}
	}

	return 0
}

func getNow() C.uint64_t {
	return C.uint64_t(time.Now().UnixNano() / int64(time.Millisecond))
}

func parseNetworkId(networkId string) uint64 {
	data, err := hex.DecodeString(networkId)
	if err != nil {
		panic("parseNetworkId: " + err.Error())
	}
	if len(data) > 8 {
		panic("parseNetworkId: network id longer than 8 bytes")
	}
	data = append(bytes.Repeat([]byte{0x00}, 8-len(data)), data...)
	return binary.BigEndian.Uint64(data)
}

func main() {
	fmt.Println("geonet")

	var major, minor, revision C.int
	C.ZT_version(&major, &minor, &revision)
	fmt.Println("libzerotier ( major:", major, ", minor:", minor, ", rev:", revision, ")")

	node, err := LoadZeroTierNode("node.conf")
	if err != nil {
		if os.IsNotExist(err) {
			node, err = NewZeroTierNode()
		}
		if err != nil {
			panic(err)
		}
	}
	defer node.Save("node.conf")
	defer node.Close()

	network, err := node.Join(parseNetworkId("8056c2e21c000001"))
	if err != nil {
		panic(err)
	}

	/*multicastIP := net.ParseIP("224.1.1.1").To4()
	ipInt := binary.BigEndian.Uint32(multicastIP)
	multicastMAC := 0x01005E000000 | (uint64(ipInt) & ((1 << 23) - 1))
	network.SubscribeMulticast(multicastMAC, 0)*/

	for {
		time.Sleep(5 * time.Second)

		ip := net.ParseIP("28.245.251.71").To4()

		/*if _, ok := network.lookupMAC(ip); !ok {
			fmt.Println("IP NOT IN ARP CACHE")
			continue
		}*/

		var wq waiter.Queue
		ep, err := network.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			panic(err)
		}
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		wq.EventRegister(&waitEntry, waiter.EventOut)
		ep.Connect(tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.Address(ip),
			Port: 1337,
		})
		<-notifyCh
		wq.EventUnregister(&waitEntry)

		fmt.Println("connected")

		buf := []byte("GET / HTTP/1.0\r\n\r\n")
		v := make(buffer.View, len(buf))
		copy(v, buf)
		ep.Write(v, nil)

		break

		/*payload := "HELLOWORLD"
		v := make(buffer.View, header.IPv4MinimumSize+len(payload))
		ip := header.IPv4(v)
		ip.Encode(&header.IPv4Fields{
			IHL:         header.IPv4MinimumSize,
			TotalLength: uint16(len(v)),
			ID:          uint16(0), // FIX: umm shouldn't this not be zero?
			TTL:         32,
			Protocol:    uint8(253),
			SrcAddr:     tcpip.Address(network.ip),
			DstAddr:     tcpip.Address(multicastIP),
		})
		var multicastMACBytesPadded [8]byte
		binary.BigEndian.PutUint64(multicastMACBytesPadded[:], multicastMAC)
		var multicastMACBytes [6]byte
		copy(multicastMACBytes[:], multicastMACBytesPadded[:6])
		network.SendToMAC(multicastMACBytes, v)*/
	}

	for {
		time.Sleep(5 * time.Second)
	}
}
