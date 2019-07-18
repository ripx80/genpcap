package main

import (
	"io"
	"log"
	"math/rand"
	"net"

	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/ripx80/genpcap"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	a := kingpin.New("genpcap", "A command-line pcap build application")
	a.Version("1.0")
	a.HelpFlag.Short('h')
	a.Author("Ripx80")
	junksize := a.Flag("junksize", "split the file content for packages").Short('s').Default("1024").Uint32()
	inputFile := a.Arg("input", "file to convert to pcap").Required().File()
	outputFile := a.Arg("output", "filename of output pcap").Required().String()

	_, err := a.Parse(os.Args[1:])
	if err != nil {
		log.Println("Error parsing commandline arguments: ", err)
		a.Usage(os.Args[1:])
		os.Exit(1)
	}

	//output
	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}
	pcapWriter := pcapgo.NewWriter(f)
	pcapWriter.WriteFileHeader(*junksize, layers.LinkTypeEthernet)
	defer f.Close()

	//input
	filesize, _ := (*inputFile).Stat()

	rand.Seed(time.Now().UnixNano())
	var (
		defaultOptions = gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		defaultSender = &genpcap.Endpoint{
			IP:         net.IP{127, 0, 0, 1},
			Mac:        net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			Port:       4432,
			Seq:        uint32(rand.Intn(1000)),
			Options:    defaultOptions,
			WindowSize: 1084,
		}
		defaultReciever = &genpcap.Endpoint{
			IP:         net.IP{8, 8, 8, 8},
			Mac:        net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			Port:       80,
			Seq:        uint32(rand.Intn(1000)),
			Options:    defaultOptions,
			WindowSize: 1084,
		}
	)

	handle, err := genpcap.NewReader(*inputFile, defaultSender, defaultReciever, *junksize)
	if err != nil {
		log.Fatal("io.Reader:", err)
	}

	handle.Handshake()
	handle.HTTPGet()

	err = handle.HTTPResponse(filesize.Size())
	if err != nil {
		log.Println(err)
		return
	}

	for {
		data, ci, err := handle.ReadPacketData()
		switch {
		case err == io.EOF:
			log.Println("generation complete")
			return
		case err != nil:
			log.Printf("Failed to read packet: %s\n", err)
		default:
			err := pcapWriter.WritePacket(ci, data)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}
