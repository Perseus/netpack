package main

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/perseus/netpack"
	"net"
	"time"
)

func cacheDataFromPCAP(text string) error {

	c := netpack.CreateNewCache()

	pcap, err := netpack.GetPCAPFile(text)

	if err != nil {
		return err
	}

	// set the bpf to tcp
	netpack.SetBPFFilter(pcap, "tcp")

	var (
		port       layers.TCPPort
		ip         net.IP
		portCheck  error
		IPCheck    error
		IPHash     string
		packetInfo netpack.NetFace
	)

	for packet := range netpack.GetPacketStream(pcap) {
		port, portCheck = netpack.GetDestinationPort(packet)
		if portCheck != nil {
			fmt.Println(portCheck)
			continue
		}
		ip, IPCheck = netpack.GetSrcIP(packet)
		if IPCheck != nil {
			fmt.Println(IPCheck)
			continue
		}
		// md5 hash is fine as each request by the same ip needs to be stored in the same map, so there is no salt required
		IPHash = netpack.GetIPHash(ip.String())

		packetInfo = netpack.NetFace{ip, port}
		c.AddItem(IPHash, packetInfo, 5*time.Minute)

	}

	// this displays all the cached items
	cachedItems := c.GetAllItems()
	fmt.Println(cachedItems)
	// sleep current goroutine for 5 seconds, to test the caching mechanism
	// after 5 seconds, the cache map should be empty.
	return nil

}

func cacheDataFromNetwork() {
	// let the cache expire in 10 seconds for testing purposes
	c := netpack.CreateNewCache()

	var (
		port       layers.TCPPort
		ip         net.IP
		portCheck  error
		IPCheck    error
		IPHash     string
		packetInfo netpack.NetFace
	)
	// getting a network stream doesn't seem to work with travis-ci
	// temporarily switching this with a normal packet capture
	// it works on any other machine
	pcap, err := netpack.GetPCAPFile("../pcaps/http.cap")
	// pcap, err := GetNetworkStream("wlp3s0")
	if err != nil {
		fmt.Println(err)
		return
	}
	//defer pcap.Close()

	for packet := range netpack.GetPacketStream(pcap) {
		port, portCheck = netpack.GetDestinationPort(packet)
		if portCheck != nil {
			fmt.Println(portCheck)
			continue
		}
		ip, IPCheck = netpack.GetSrcIP(packet)
		if IPCheck != nil {
			fmt.Println(IPCheck)
			continue
		}

		IPHash = netpack.GetIPHash(ip.String())
		packetInfo = netpack.NetFace{ip, port}
		c.AddItem(IPHash, packetInfo, 5*time.Second)

		// since this loop will run as long as packets are incoming on the network,
		// set a condition to store only 4-5 items in cache (packets from unique IPs)

		if c.GetCount() >= 4 {
			break
		}
	}

	// this displays all the cached items
	cachedItems := c.GetAllItems()
	fmt.Println(cachedItems)

}

func main() {

	err := cacheDataFromPCAP("../pcaps/http.cap")
	if err == nil {
		fmt.Println(" Cache created successfully ")
	} else {
		fmt.Println(err)
	}

	cacheDataFromNetwork()

}
