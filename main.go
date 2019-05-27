package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"log"
	"os"
	"time"
)

var (
	device      string        = "lo0"
	snapshotLen uint32        = 1024
	promiscuous bool          = false
	timeout     time.Duration = 30 * time.Second
)

type Endpoint struct {
	IP       net.IP
	Mac      net.HardwareAddr
	Port     uint32
	Seq      uint32
	Ack      uint32
	Protocol uint8
	Options  gopacket.SerializeOptions
}

type pack struct {
	data []byte
	ci   gopacket.CaptureInfo
	err  error
}

var (
	DefaultOptions = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	DefaultSender = &Endpoint{
		IP:       net.IP{127, 0, 0, 1},
		Mac:      net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		Port:     4432,
		Protocol: 2,
		Seq:      uint32(rand.Intn(100)),
		Ack:      0,
		Options:  DefaultOptions,
	}
	DefaultReciever = &Endpoint{
		IP:       net.IP{8, 8, 8, 8},
		Mac:      net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		Port:     80,
		Protocol: 2,
		Seq:      uint32(rand.Intn(100)),
		Ack:      0,
		Options:  DefaultOptions,
	}
)

type Reader struct {
	r         io.Reader
	buf       []byte
	num       int
	junksize  uint32
	Sender    *Endpoint
	Reciever  *Endpoint
	PacketBuf []pack
}

func (src *Endpoint) EthernetIPv4(dst *Endpoint) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       src.Mac,
		DstMAC:       dst.Mac,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func (src *Endpoint) IPv4(dst *Endpoint) *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:   src.IP,
		DstIP:   dst.IP,
		Version: 4,
		TTL:     64,
	}
}

func (src *Endpoint) UDP(dst *Endpoint) *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(src.Port),
		DstPort: layers.UDPPort(dst.Port),
	}
}

/*
1. Random Seq
2. Payload+seq
*/
func (src *Endpoint) TCP(dst *Endpoint) *layers.TCP {
	return &layers.TCP{
		SrcPort: layers.TCPPort(src.Port),
		DstPort: layers.TCPPort(dst.Port),
		Seq:     src.Seq,
		Window:  0xaaaa, // change this
	}
}

func NewReader(r io.Reader) (*Reader, error) {
	ret := Reader{r: r, buf: make([]byte, 1024), junksize: 1024, Sender: DefaultSender, Reciever: DefaultReciever}
	return &ret, nil
}

func (r *Reader) Pack(options gopacket.SerializeOptions, layer ...gopacket.SerializableLayer) ([]byte, gopacket.CaptureInfo, error) {
	ci := gopacket.CaptureInfo{}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, options,
		layer...,
	); err != nil {
		return nil, ci, err
	}
	out := buffer.Bytes()
	ci.Timestamp = time.Now()
	ci.Length = len(out)
	ci.CaptureLength = len(out)

	return out, ci, nil
}

// func (src *Endpoint) AckPack(dst *Endpoint) ([]byte, gopacket.CaptureInfo, error) {
// 	ethLayer := &layers.Ethernet{
// 		SrcMAC:       src.Mac,
// 		DstMAC:       dst.Mac,
// 		EthernetType: layers.EthernetTypeIPv4,
// 	}
// 	ipLayer := &layers.IPv4{
// 		SrcIP:   r.Endpoint.DstIP,
// 		DstIP:   r.Endpoint.SrcIP,
// 		Version: 4,
// 		TTL:     64,
// 	}
// 	r.Endpoint.DstSeq++
// 	tcp := &layers.TCP{
// 		SrcPort: layers.TCPPort(r.Endpoint.DstPort),
// 		DstPort: layers.TCPPort(r.Endpoint.SrcPort),
// 		Window:  0xaaaa,
// 		SYN:     false,
// 		Seq:     r.Endpoint.DstSeq,
// 		Ack:     r.Endpoint.SrcSeq + 1,
// 	}

// 	ipLayer.Protocol = layers.IPProtocolTCP
// 	tcp.SetNetworkLayerForChecksum(ipLayer)
// 	return r.Pack(
// 		ethLayer,
// 		ipLayer,
// 		tcp,
// 	)
// }

// func (r *Reader) Handshake() (packets [3]pack) {

// 	ethLayer := r.EthernetIPv4()
// 	ipLayer := r.IPv4()
// 	tcp := r.TCP()
// 	tcp.SYN = true
// 	ipLayer.Protocol = layers.IPProtocolTCP
// 	tcp.SetNetworkLayerForChecksum(ipLayer)
// 	data, ci, err := r.Pack(ethLayer, ipLayer, tcp)
// 	packets[0] = pack{data, ci, err}
// 	fmt.Printf("1. SYN -> Seq(%d)", r.Endpoint.SrcSeq)

// 	return packets
// }

func (r *Reader) Handshake() {

	fmt.Printf("1. SenderSeq: %d, RecieverSeq:%d\n", r.Sender.Seq, r.Reciever.Seq)
	//generate SYN
	ethLayer := r.Sender.EthernetIPv4(r.Reciever)
	ipLayer := r.Sender.IPv4(r.Reciever)
	tcp := r.Sender.TCP(r.Reciever)
	tcp.SYN = true
	tcp.Window = 0
	tcp.Seq = r.Sender.Seq
	tcp.SetNetworkLayerForChecksum(ipLayer)
	ipLayer.Protocol = layers.IPProtocolTCP
	d, c, e := r.Pack(r.Sender.Options, ethLayer,
		ipLayer,
		tcp,
		gopacket.Payload(r.buf[:r.num]))
	r.PacketBuf = append(r.PacketBuf, pack{d, c, e})
	fmt.Printf("2. SenderSeq: %d, RecieverSeq:%d\n", r.Sender.Seq, r.Reciever.Seq)
	r.Sender.Seq++

	// generate Ack,SYN Pack
	ethLayer = r.Reciever.EthernetIPv4(r.Sender)
	ipLayer = r.Reciever.IPv4(r.Sender)
	tcp = r.Reciever.TCP(r.Sender)
	tcp.SYN = true
	tcp.ACK = true
	tcp.Seq = r.Reciever.Seq
	tcp.Window = 0
	tcp.Ack = r.Sender.Seq
	tcp.SetNetworkLayerForChecksum(ipLayer)
	ipLayer.Protocol = layers.IPProtocolTCP
	d, c, e = r.Pack(r.Reciever.Options, ethLayer,
		ipLayer,
		tcp,
	)
	r.PacketBuf = append(r.PacketBuf, pack{d, c, e})
	r.Reciever.Seq++
	fmt.Printf("3. SenderSeq: %d, RecieverSeq:%d\n", r.Sender.Seq, r.Reciever.Seq)
	// generate ACK
	ethLayer = r.Sender.EthernetIPv4(r.Reciever)
	ipLayer = r.Sender.IPv4(r.Reciever)
	tcp = r.Sender.TCP(r.Reciever)
	tcp.ACK = true
	tcp.Ack = r.Reciever.Seq
	tcp.Seq = r.Sender.Seq
	tcp.SetNetworkLayerForChecksum(ipLayer)
	ipLayer.Protocol = layers.IPProtocolTCP
	d, c, e = r.Pack(r.Sender.Options, ethLayer,
		ipLayer,
		tcp,
		gopacket.Payload(r.buf[:r.num]))
	r.PacketBuf = append(r.PacketBuf, pack{d, c, e})

}

func (r *Reader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var err error

	if len(r.PacketBuf) > 0 {
		var p pack
		p, r.PacketBuf = r.PacketBuf[0], r.PacketBuf[1:]
		return p.data, p.ci, p.err
	}

	r.num, err = io.ReadAtLeast(r.r, r.buf, 1)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}

	//generate Sender Pack
	ethLayer := r.Sender.EthernetIPv4(r.Reciever)
	ipLayer := r.Sender.IPv4(r.Reciever)
	tcp := r.Sender.TCP(r.Reciever)
	tcp.ACK = true
	tcp.PSH = true
	tcp.Seq = r.Sender.Seq //after first packet send,ack here ACK from r.Receiver (len+1)
	tcp.Ack = r.Reciever.Seq

	tcp.SetNetworkLayerForChecksum(ipLayer)
	ipLayer.Protocol = layers.IPProtocolTCP

	d, c, e := r.Pack(r.Sender.Options, ethLayer,
		ipLayer,
		tcp,
		gopacket.Payload(r.buf[:r.num]))
	send := &pack{d, c, e}
	//r.Sender.Seq++

	// generate Ack Pack
	ethLayer = r.Reciever.EthernetIPv4(r.Sender)
	ipLayer = r.Reciever.IPv4(r.Sender)
	tcp = r.Reciever.TCP(r.Sender)
	tcp.ACK = true
	tcp.Seq = r.Reciever.Seq
	tcp.Ack = r.Sender.Seq + uint32(r.num) //Seq+PayloadLen
	tcp.SetNetworkLayerForChecksum(ipLayer)
	ipLayer.Protocol = layers.IPProtocolTCP
	d, c, e = r.Pack(r.Reciever.Options, ethLayer,
		ipLayer,
		tcp,
	)
	recieve := pack{d, c, e}
	r.PacketBuf = append(r.PacketBuf, recieve)
	r.Reciever.Seq++
	//transLayer = tcp
	//var transLayer gopacket.SerializableLayer

	// if r.Protocol == 1 {
	// 	//udp
	// 	udp := r.UDP()
	// 	ipLayer.Protocol = layers.IPProtocolUDP
	// 	udp.SetNetworkLayerForChecksum(ipLayer)
	// 	transLayer = udp
	// } else {
	//tcp

	//}
	return send.data, send.ci, send.err
}

func main() {
	a := kingpin.New("topcap", "A command-line pcap build application")
	a.Version("1.0")
	a.HelpFlag.Short('h')
	a.Author("Ripx80")
	inputFile := a.Arg("input", "file to convert to pcap").Required().File()
	outputFile := a.Arg("output", "filename of output pcap").Required().String()
	tcp := a.Flag("tcp", "use tcp as transport protocol. out-of-order warning").Bool()

	_, err := a.Parse(os.Args[1:])
	if err != nil {
		log.Println("Error parsing commandline arguments: ", err)
		a.Usage(os.Args[1:])
		os.Exit(1)
	}

	ifhandle, err := pcap.OpenLive(device, int32(snapshotLen), promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer ifhandle.Close()

	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}
	pcapWriter := pcapgo.NewWriter(f)
	pcapWriter.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	defer f.Close()

	// if you will use a buffer of bytes
	//rawBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	// rawBytes := []byte(`GET / HTTP/1.0\r\n\r\n`)
	// handle, err := NewReader(bytes.NewReader(rawBytes))
	// fmt.Println(*inputFile)
	handle, err := NewReader(*inputFile)
	if err != nil {
		log.Fatal("canot use io Reader")
	}

	//generate Handshake in PacketBuf
	handle.Handshake()

	if *tcp {
		fmt.Println("tcp")
		//handle.Protocol = 2
	}
	cnt := 0
	for {
		if cnt == 6 {
			break
		}
		data, ci, err := handle.ReadPacketData()
		switch {
		case err == io.EOF:
			fmt.Println("finish")
			return
		case err != nil:
			log.Printf("Failed to read packet: %s\n", err)
		default:
			//ifhandle.WritePacketData(data)
			err := pcapWriter.WritePacket(ci, data)
			if err != nil {
				fmt.Print(err)
				return
			}
		}
		cnt++
	}

}
