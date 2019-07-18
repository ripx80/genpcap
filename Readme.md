# genpacp

Generate a http (GET/RESPONSE) transfered a given file in pcap format. Extracted content with wireshark.
And yep written in go.

If you use bro you will get a tcp trunced error message. If you know how I can fix this, your are welcome ;-)

This is a poc to write a pacp injector with a given file or url.
RFC are welcome!

## Roadmap

- tests!
- random seed rand.Seed(42) for seq numbers
- add udp plain support
- calculate correct window size
- http get content type of file
