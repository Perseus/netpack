// Package netpack is a minimal package that was created for basic reading of
// packets from packet captures and network streams
package netpack

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

// NetFace is a small struct made to make storing the source IP
// and the destination port in the cache easier.
type NetFace struct {
	// SrcIP will contain the IP of the source of the packet
	SrcIP net.IP

	// DstPort will contain the port of the destination of the packet
	DstPort layers.TCPPort
}

// GetPCAPFile opens a file containing a packet capture
// and returns the handle that contains it. If unable to open,
// error is returned.
func GetPCAPFile(fileName string) (*pcap.Handle, error) {

	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}

	return handle, nil
}

// SetBPFFilter sets the BPF filter for a connection ( packet capture or network stream )
// so that it can be analysed accordingly
func SetBPFFilter(handle *pcap.Handle, filter string) error {
	err := handle.SetBPFFilter(filter)
	return err

}

// GetPacketStream retrieves the stream of packets from
// the packet capture
func GetPacketStream(handle *pcap.Handle) chan gopacket.Packet {
	stream := gopacket.NewPacketSource(handle, handle.LinkType())
	return stream.Packets()
}

// GetDestinationPort reads the layers present in the packet,
// and retrieves the destination port number from the structs TCP or UDP
func GetDestinationPort(packet gopacket.Packet) (layers.TCPPort, error) {

	var (
		eth  layers.Ethernet
		ipv4 layers.IPv4
		tcp  layers.TCP
		udp  layers.UDP
		err  error
		port layers.TCPPort
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ipv4,
		&tcp,
		&udp)

	var layersInPacket []gopacket.LayerType

	err = parser.DecodeLayers(packet.Data(), &layersInPacket)

	if err != nil {
		return port, err
	}
	port = tcp.DstPort

	return port, nil
}

// AddDataToCache inserts an IP and Port, which are specificed by the parameters, to the cache
func AddDataToCache(IP net.IP, Port layers.TCPPort, c *Cache) bool {
	IPHash := GetIPHash(IP.String())
	dataInfo := NetFace{IP, Port}

	err := c.AddItem(IPHash, dataInfo, 5*time.Minute)
	return err
}

// GetSrcIP reads the layers in the packet
// and retrieves the IP Address of the source of the packet
func GetSrcIP(packet gopacket.Packet) (net.IP, error) {

	var (
		eth  layers.Ethernet
		ipv4 layers.IPv4
		tcp  layers.TCP
		udp  layers.UDP
		IP   net.IP
		err  error
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ipv4,
		&tcp,
		&udp)

	var layersInPacket []gopacket.LayerType
	err = parser.DecodeLayers(packet.Data(), &layersInPacket)
	if err != nil {
		return IP, err
	}

	IP = ipv4.SrcIP

	return IP, nil
}

// GetIPHash returns the md5 hash value of a string - for caching purposes
func GetIPHash(text string) string {
	hasher := md5.New()

	// https://godoc.org/hash#Hash
	// it never returns an error
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetCurrentNetworkDevice lists all the network devices in the current environment and
// retrieves the name of the first one and returns it.
func GetCurrentNetworkDevice() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err == nil {
		return devices[0].Name, nil
	}

	return devices[0].Name, err

}

// GetNetworkStream opens a live packet capturing stream and returns the handle
func GetNetworkStream(device string) (*pcap.Handle, error) {

	pcapHandle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)

	if err != nil {
		return pcapHandle, err
	}

	bpfErr := SetBPFFilter(pcapHandle, "tcp")

	if bpfErr != nil {
		return pcapHandle, bpfErr
	}

	return pcapHandle, nil
}
