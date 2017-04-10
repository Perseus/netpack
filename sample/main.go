package main

import (
	"github.com/perseus/netpack"
	"github.com/patrickmn/go-cache"
	"time"
	"net"
	"fmt"
	"github.com/google/gopacket/layers"
)

func cacheDataFromPCAP(text string) error {

	// cache expires every 5 minutes
	c := cache.New(5*time.Minute, 10*time.Minute)


	pcap,err := netpack.GetPCAPFile(text)
	
	if err != nil {
		return err
	}

	// set the bpf to tcp
	netpack.SetBPFFilter(pcap,"tcp")

	var (
		port layers.TCPPort
		ip net.IP
		err2 error
		IPHash string
		packetInfo netpack.NetFace
	)


	for packet := range netpack.GetPacketStream(pcap) {
		port,err2 = netpack.GetDestinationPort(packet)
		ip = netpack.GetSrcIP(packet)

		// md5 hash is fine as each request by the same ip needs to be stored in the same map, so there is no salt required
		IPHash = netpack.GetIPHash(ip.String())

		if err2 == nil {
			packetInfo = netpack.NetFace{ip, port}
			c.Set(IPHash, packetInfo, cache.DefaultExpiration)
		}
		
	}


	if err2 == nil {
		// this displays all the cached items
		fmt.Println(" Packet cache from packet capture : ")
		cachedItems := c.Items()
		for i,j := range cachedItems {
			fmt.Println(i,j)
		}
		c.Flush()
	} else {
		return err2
	}

	return nil

}

func cacheDataFromNetwork() {
	netDevice, err := netpack.GetCurrentNetworkDevice()


	// let the cache expire in 10 seconds for testing purposes
	c := cache.New(5*time.Minute, 10*time.Minute)
	if err != nil {
		panic(err)
	}
	var (
		port layers.TCPPort
		ip net.IP
		err2 error
		IPHash string
		packetInfo netpack.NetFace
	)
	pcap := netpack.GetNetworkStream(netDevice)
	

	for packet := range netpack.GetPacketStream(pcap) {
		port, err2 = netpack.GetDestinationPort(packet)
		ip = netpack.GetSrcIP(packet)
		IPHash = netpack.GetIPHash(ip.String())
		if err2 == nil {
			packetInfo = netpack.NetFace{ip, port}
			c.Set(IPHash, packetInfo, cache.DefaultExpiration)
		}


		// since this loop will run as long as packets are incoming on the network,
		// set a condition to store only 4-5 items in cache (packets from unique IPs)

		if c.ItemCount() >= 4 {
			break
		}
	}

	if err2 == nil {
		fmt.Println(" Packet cache from live network stream : ")
		// this displays all the cached items
		cachedItems := c.Items()
		for i,j := range cachedItems {
			fmt.Println(i,j)
		}
		// sleep current goroutine for 5 seconds, to test the caching mechanism
		// after 5 seconds, the cache map should be empty.
		c.Flush()
	} else {
		fmt.Println(err2)
	}



}

func main() {

	err := cacheDataFromPCAP("pcaps/http.cap")
	if err == nil {
		fmt.Println(" Cache created successfully " )
	} else {
		fmt.Println(err)
	}


	cacheDataFromNetwork()

}