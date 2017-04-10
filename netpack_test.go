package netpack

import (
	"github.com/google/gopacket/layers"
	"net"
	"testing"
	"time"
)

func TestGetDestPort(t *testing.T) {
	// let the cache expire in 5 seconds for testing purposes
	c := CreateNewCache()
	t.Logf("\n")

	pcap, err := GetPCAPFile("pcaps/http.cap")

	if err != nil {
		t.Log(err)
		return
	}

	// set the bpf to tcp
	SetBPFFilter(pcap, "tcp")

	var (
		port	layers.TCPPort
		ip	net.IP
		portCheck	error
		IPCheck		error
		IPHash string
		packetInfo NetFace
	)

	for packet := range GetPacketStream(pcap) {
		port, portCheck = GetDestinationPort(packet)
		if portCheck != nil {
			t.Log(portCheck)
			continue
		}
		ip, IPCheck = GetSrcIP(packet)
		if IPCheck != nil {
			t.Log(IPCheck)
			continue
		}
		// md5 hash is fine as each request by the same ip needs to be stored in the same map, so there is no salt required
		IPHash = GetIPHash(ip.String())

		packetInfo = NetFace{ip, port}
		c.AddItem(IPHash, packetInfo, 5 * time.Second)
		

	}

	
		// this displays all the cached items
		cachedItems := c.GetAllItems()
		t.Log(cachedItems)
		// sleep current goroutine for 5 seconds, to test the caching mechanism
		// after 5 seconds, the cache map should be empty.
		time.Sleep(5 * time.Second)
		cachedItems = c.GetAllItems()
		t.Log(cachedItems)
		

}

func TestLiveNetwork(t *testing.T) {

	// let the cache expire in 10 seconds for testing purposes
	c := CreateNewCache()

	var (
		port       layers.TCPPort
		ip         net.IP
		portCheck       error
		IPCheck		error
		IPHash     string
		packetInfo NetFace

	)
	pcap, err := GetNetworkStream("wlp3s0")
	if err != nil {
		t.Log(err)
		return 
	}
	//defer pcap.Close()

	for packet := range GetPacketStream(pcap) {
		port, portCheck = GetDestinationPort(packet)
		if portCheck != nil {
			t.Log(portCheck)
			continue
		}
		ip, IPCheck = GetSrcIP(packet)
		if IPCheck != nil {
			t.Log(IPCheck)
			continue
		}

		IPHash = GetIPHash(ip.String())
		packetInfo = NetFace{ip, port}
		c.AddItem(IPHash, packetInfo, 5 * time.Second)

		// since this loop will run as long as packets are incoming on the network,
		// set a condition to store only 4-5 items in cache (packets from unique IPs)

		if c.GetCount() >= 4 {
			break
		}
	}

		// this displays all the cached items
		cachedItems := c.GetAllItems()
		t.Log(cachedItems)

		// sleep current goroutine for 5 seconds, to test the caching mechanism
		// after 5 seconds, the cache map should be empty.

		time.Sleep(5 * time.Second)
		cachedItems = c.GetAllItems()
		t.Log(cachedItems)
		

}

func TestCache(t *testing.T) {

	testIP := net.ParseIP("192.168.0.1")
	data := NetFace{testIP,80}
	IPHash := GetIPHash(testIP.String())
	

	expiration := 5 * time.Second
	c := CreateNewCache()
	c.AddItem(IPHash, data, expiration)
	

	t.Logf(c.GetAllItems())

}
