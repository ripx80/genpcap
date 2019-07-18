package genpcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net"
	"time"
)

/*
Endpoint impelemnts the sender and receiver
*/
type Endpoint struct {
	IP   net.IP
	Mac  net.HardwareAddr
	Port uint32
	Seq  uint32

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

// Reader implements a normal io.Reader interface
type Reader struct {
	r         io.Reader
	buf       []byte
	Sender    *Endpoint
	Reciever  *Endpoint
	PacketBuf []pack
}

/*
Pack build a gopacket package with options and layers
*/
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
	src.ethLayer = src.ethernetIPv4(dst)
	src.ipLayer = src.ipv4(dst)
	src.tcpLayer = src.tcp(dst)
}

func (src *Endpoint) ethernetIPv4(dst *Endpoint) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       src.Mac,
		DstMAC:       dst.Mac,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func (src *Endpoint) ipv4(dst *Endpoint) *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:   src.IP,
		DstIP:   dst.IP,
		Version: 4,
		TTL:     64,
	}
}

func (src *Endpoint) udp(dst *Endpoint) *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(src.Port),
		DstPort: layers.UDPPort(dst.Port),
	}
}

func (src *Endpoint) tcp(dst *Endpoint) *layers.TCP {
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

/*
NewReader return a new *Reader to handle packet data. Read content in junks to buffer
*/
func NewReader(r io.Reader, sender, reciever *Endpoint, junksize uint32) (*Reader, error) {
	if junksize > 1460 {
		return nil, fmt.Errorf("your junksize can be a maximum of 1460 bytes")
	}
	ret := Reader{r: r, buf: make([]byte, junksize), Sender: sender, Reciever: reciever}
	ret.Sender.init(ret.Reciever)
	ret.Reciever.init(ret.Sender)

	return &ret, nil
}

/*
Handshake generate a tcp handshake
*/
func (r *Reader) Handshake() {

	//generate SYN
	r.Sender.tcpLayer = r.Sender.tcp(r.Reciever)
	r.Sender.tcpLayer.SYN = true
	r.Sender.tcpLayer.Window = 0 //this should be null
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())

	// generate Ack,SYN Pack
	r.Sender.Seq++
	r.Reciever.tcpLayer = r.Reciever.tcp(r.Sender)
	r.Reciever.tcpLayer.SYN = true
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Window = 0
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())

	// generate ACK
	r.Reciever.Seq++
	r.Sender.tcpLayer = r.Sender.tcp(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())
}

/*
HTTPGet generate a http get request
*/
func (r *Reader) HTTPGet() {
	const request = "GET /%s HTTP/1.1\r\nUser-Agent: Mozilla/4.0\r\nHost: %s\r\nAccept: */*\r\n\r\n"
	b := fmt.Sprintf(request, "pp.jpeg", "8.8.8.8:80")
	r.Sender.tcpLayer = r.Sender.tcp(r.Reciever)
	r.Sender.tcpLayer.PSH = true
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack([]byte(b)))
	//increase Seq by sended bytes from sender
	r.Sender.Seq += uint32(len(b))

	//ACK
	r.Reciever.tcpLayer = r.Reciever.tcp(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())
}

/*
HTTPResponse read the first data content from reader and generate a http response with content included
*/
func (r *Reader) HTTPResponse(contentLen int64) error {

	num, err := io.ReadAtLeast(r.r, r.buf, 1)
	if err != nil {
		return err
	}

	t := time.Now()
	a := append([]byte(fmt.Sprintf("HTTP/1.0 200 OK\r\nServer: Apache\r\nDate: %s\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\nLast-Modified: %s\r\nConnection: keep-alive\r\nAccept-Ranges: bytes\r\n\r\n", t.Format(time.ANSIC), contentLen, t.Format(time.ANSIC))), r.buf[:num]...)

	// HTTP OK with Body
	r.Reciever.tcpLayer = r.Reciever.tcp(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.PSH = true
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack(a))
	r.Reciever.Seq += uint32(len(a))

	//ACK
	r.Sender.tcpLayer = r.Sender.tcp(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())
	return nil
}

func (r *Reader) tcpEnd() {
	//sender FIN,ACK
	r.Reciever.tcpLayer = r.Reciever.tcp(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.FIN = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())

	// FIN,ACK
	r.Reciever.Seq++
	r.Sender.tcpLayer = r.Sender.tcp(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.FIN = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())
	r.Sender.Seq++

	//ACK
	r.Reciever.tcpLayer = r.Reciever.tcp(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.PacketBuf = append(r.PacketBuf, r.Reciever.genTCPPack())
}

/*
ReadPacketData reads all data from reader and split it in junksize packages.
You can generate packages which are not in reader source like ack packages.
These packages will be put on the packetbuffer. ReadPacketData will get all packages from buffer
and then reads more data from Reader interface.
*/
func (r *Reader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {

	if len(r.PacketBuf) > 0 {
		var p pack
		p, r.PacketBuf = r.PacketBuf[0], r.PacketBuf[1:]
		return p.data, p.ci, p.err
	}

	num, err := io.ReadAtLeast(r.r, r.buf, 1)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}

	//generate Sender Pack
	var send pack

	r.Reciever.tcpLayer = r.Reciever.tcp(r.Sender)
	r.Reciever.tcpLayer.ACK = true
	r.Reciever.tcpLayer.Seq = r.Reciever.Seq
	r.Reciever.tcpLayer.Ack = r.Sender.Seq
	r.Reciever.Seq += uint32(num)
	send = r.Reciever.genTCPPack(r.buf[:num])

	//ACK
	r.Sender.tcpLayer = r.Sender.tcp(r.Reciever)
	r.Sender.tcpLayer.ACK = true
	r.Sender.tcpLayer.Seq = r.Sender.Seq
	r.Sender.tcpLayer.Ack = r.Reciever.Seq
	r.PacketBuf = append(r.PacketBuf, r.Sender.genTCPPack())

	if num < 1024 {
		r.tcpEnd()
	}
	return send.data, send.ci, send.err
}
