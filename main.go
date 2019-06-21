package main

/*

Todo
	Random Seed rand.Seed(42) for Seq numbers
	Set Endpoints in Main not in Lib
	Add UPD plain support
	Add GET, POST HTTP Support
*/

import (
	"fmt"
	"io"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"log"
	"os"
	"time"
)

type Endpoint struct {
	IP       net.IP
	Mac      net.HardwareAddr
	Port     uint32
	Seq      uint32
	Ack      uint32
	Protocol uint8

	//layers
	ethLayer *layers.Ethernet
	ipLayer  *layers.IPv4
	tcpLayer *layers.TCP

	WindowSize uint16
	Options    gopacket.SerializeOptions
}

type pack struct {
	data []byte
	ci   gopacket.CaptureInfo
	err  error
}

type Reader struct {
	r         io.Reader
	buf       []byte
	num       int
	total     int
	junksize  uint32
	Sender    *Endpoint
	Reciever  *Endpoint
	PacketBuf []pack
	first     bool
	Http      bool
	//	TotalSize int64
}

func Pack(options gopacket.SerializeOptions, layer ...gopacket.SerializableLayer) ([]byte, gopacket.CaptureInfo, error) {
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

func (src *Endpoint) init(dst *Endpoint) {
	src.ethLayer = src.EthernetIPv4(dst)
	src.ipLayer = src.IPv4(dst)
	src.tcpLayer = src.TCP(dst)
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

func (src *Endpoint) TCP(dst *Endpoint) *layers.TCP {
	return &layers.TCP{
		SrcPort: layers.TCPPort(src.Port),
		DstPort: layers.TCPPort(dst.Port),
		Seq:     src.Seq,
		Window:  src.WindowSize,
	}
}

func (src *Endpoint) genTCPPack(payload ...[]byte) pack {
	//generate fresh tcp layer
	src.tcpLayer.SetNetworkLayerForChecksum(src.ipLayer)
	src.ipLayer.Protocol = layers.IPProtocolTCP

	if len(payload) > 0 {
		d, c, e := Pack(src.Options, src.ethLayer,
			src.ipLayer,
			src.tcpLayer,
			gopacket.Payload(payload[0]),
		)

		return pack{d, c, e}
	}
	d, c, e := Pack(src.Options, src.ethLayer,
		src.ipLayer,
		src.tcpLayer,
	)
	return pack{d, c, e}
}

func NewReader(r io.Reader) (*Reader, error) {
	var (
		DefaultOptions = gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		DefaultSender = &Endpoint{
			IP:         net.IP{127, 0, 0, 1},
			Mac:        net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			Port:       4432,
			Protocol:   2,
			Seq:        uint32(rand.Intn(1000)),
			Options:    DefaultOptions,
			WindowSize: 0xaaa,
		}
		DefaultReciever = &Endpoint{
			IP:         net.IP{8, 8, 8, 8},
			Mac:        net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			Port:       80,
			Protocol:   2,
			Seq:        uint32(rand.Intn(1000)),
			Options:    DefaultOptions,
			WindowSize: 0xaaa,
		}
	)
	ret := Reader{r: r, buf: make([]byte, 1024), junksize: 1024, Sender: DefaultSender, Reciever: DefaultReciever, first: true}
	ret.Sender.init(ret.Reciever)
	ret.Reciever.init(ret.Sender)

	//fi, _ := (*Reader).Stat()
	//fmt.Printf("File Size: %d\n", fi.Size())

	return &ret, nil
}

func (r *Reader) HttpOK() {

	const resp = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n"
	b := fmt.Sprintf(resp, 3899)
	fmt.Printf("%s\n", b)
	r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
	r.Reciever.tcpLayer.PSH = true
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Ack
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack([]byte(b)))

	//ACK
	r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Ack + uint32(len(b))
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())

	//r.Reciever.Ack = r.Reciever.Ack + uint32(len(b))

	//r.Sender.Seq++
}

func (r *Reader) HttpGet() {
	// generate http get request from sender,(*inputFile).Name()

	const request = "GET /%s HTTP/1.1\r\nUser-Agent: Mozilla/4.0\r\nHost: %s\r\n\r\n"
	b := fmt.Sprintf(request, "fn", "8.8.8.8")
	fmt.Println(b)

	r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
	r.Sender.tcpLayer.PSH = true
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack([]byte(b)))

	//r.Sender.Seq++
	//ACK
	r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Ack = r.Sender.Seq + uint32(len(b)) //+ 1 //uint32(len(b))
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())

	//r.Reciever.Ack = r.Reciever.Ack + uint32(len(b)) + 1

	//r.Reciever.Ack = r.Reciever.Ack + uint32(len(b))

	//r.Reciever.Ack++
	//r.Reciever.Ack = r.Sender.Seq

	//r.HttpOK()

	//r.Reciever.Ack++
}

func (r *Reader) Handshake() {

	//generate SYN
	r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
	r.Sender.tcpLayer.SYN = true
	r.Sender.tcpLayer.Window = 0 //this should be null
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())

	// generate Ack,SYN Pack
	r.Sender.Seq++
	r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
	r.Reciever.tcpLayer.SYN = true
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Window = 0
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())

	// generate ACK
	r.Reciever.Seq++
	r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())

	//r.Reciever.Ack = r.Sender.Seq

}

func (r *Reader) TCPEnd() {
	//sender FIN,ACK
	r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.FIN = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Ack
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())

	// FIN,ACK
	r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.FIN = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Ack + 1
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())
	//r.Reciever.Ack++
	//r.Sender.Seq++

	//ACK
	r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Ack + 1
	r.Reciever.tcpLayer.Ack = r.Sender.Seq + 1
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())
}

func (r *Reader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var err error

	if len(r.PacketBuf) > 0 {
		var p pack
		p, r.PacketBuf = r.PacketBuf[0], r.PacketBuf[1:]
		return p.data, p.ci, p.err
	}

	r.num, err = io.ReadAtLeast(r.r, r.buf, 1)
	r.total = r.total + r.num
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}

	//generate Sender Pack
	var send pack

	if r.first {
		r.first = false

		r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
		r.Reciever.tcpLayer.ACK = true
		r.Reciever.tcpLayer.Ack = r.Sender.Seq
		r.Reciever.tcpLayer.Seq = r.Reciever.Seq

		r.Reciever.tcpLayer.PSH = true
		//the response must contain the data in body
		a := append([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: image/jpeg\r\n\r\n"), r.buf[:r.num]...)
		send = r.Reciever.genTCPPack(a)
		//r.Reciever.Seq++

		//ACK
		r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
		r.Sender.tcpLayer.ACK = true
		r.Sender.tcpLayer.Seq = r.Sender.Seq
		r.Sender.tcpLayer.Ack = r.Reciever.Seq + uint32(len(a))
		r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())

		r.Reciever.Ack = r.Reciever.Seq + uint32(len(a))

	} else {
		r.Reciever.tcpLayer = r.Reciever.TCP(r.Sender)
		r.Reciever.tcpLayer.ACK = true
		r.Reciever.tcpLayer.Seq = r.Reciever.Ack
		r.Reciever.tcpLayer.Ack = r.Sender.Seq
		send = r.Reciever.genTCPPack(r.buf[:r.num])

		//ACK
		r.Sender.tcpLayer = r.Sender.TCP(r.Reciever)
		r.Sender.tcpLayer.ACK = true
		r.Sender.tcpLayer.Seq = r.Sender.Seq
		r.Sender.tcpLayer.Ack = r.Reciever.Ack + uint32(r.num)
		r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())
		r.Reciever.Ack = r.Reciever.Ack + uint32(r.num)
	}
	if r.num < 1024 {
		//r.HttpOK()
		r.TCPEnd()
	}

	//var transLayer gopacket.SerializableLayer

	// if r.Protocol == 1 {
	// 	//udp
	// 	udp := r.UDP()
	// 	ipLayer.Protocol = layers.IPProtocolUDP
	// 	udp.SetNetworkLayerForChecksum(ipLayer)
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
	//tcp := a.Flag("tcp", "use tcp as transport protocol. out-of-order warning").Bool()

	_, err := a.Parse(os.Args[1:])
	if err != nil {
		log.Println("Error parsing commandline arguments: ", err)
		a.Usage(os.Args[1:])
		os.Exit(1)
	}

	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}

	var junksize uint32 = 1024
	pcapWriter := pcapgo.NewWriter(f)
	pcapWriter.WriteFileHeader(junksize, layers.LinkTypeEthernet)
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

	//generate Handshake in PacketBuf init from Sender -->
	handle.Handshake()
	handle.HttpGet()

	for {
		data, ci, err := handle.ReadPacketData()
		switch {
		case err == io.EOF:
			fmt.Println("finish")
			return
		case err != nil:
			log.Printf("Failed to read packet: %s\n", err)
		default:
			err := pcapWriter.WritePacket(ci, data)
			if err != nil {
				fmt.Print(err)
				return
			}
		}
	}

}
