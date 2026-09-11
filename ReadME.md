# Dataplane — a pcap packet parser in Rust

This is a program that reads incoming packets from a predefined file "pcap_file.pcap" found in the project root.
Usage: In order to run the program, use the command "cargo run".

Global Header → Packet header → Ethernet Header → IPv4/IPv6 → TCP/UDP

It parses the global header of the file and each packet header that the file contains.
For each packet, the program further parses the ethernet header, the ip header (IPv4, IPv6) and
the transport layer which at the moment is able to parse only TCP and UDP.

Each layer of the traffic has its own file with unit tests comprised of hardcoded data to verify
its correctness.

Instead of crowding the main file, handler functions have been created in order to maintain an ordered
and non-confusing main file.

# Sample output:
--- PCAP Global Header ---
Magic Number:  0xA1B2C3D4
Version:       2.4
Timezone:      0
SigFigs:       0
SnapLen:       262144 bytes
LinkType:      1 (Network type)

Starting to parse packets:

---PACKET NUMBER 1---

Timestamp: 1788272531 seconds, 731018 microseconds  |  Included size: 1294  |  Original size: 1294

Destination MAC address: F4:1D:6B:60:DB:01
Source MAC address : 40:C2:BA:41:4D:53
EtherType: 0x86DD
Version:         6
Traffic Class:   0x02
Flow Label:      0x416D0
Payload Length:  1240
Next Header:     17
Hop Limit:       64
Source IP:       2a02:2f01:6801:1800:3b50:fb0a:bcfa:7321
Destination IP:  2a00:1450:400d:80b::200e

UDP Header:
Src Port: 45931
Dest Port: 443
Length: 1240
Checksum: 60123

---PACKET NUMBER 2---

Timestamp: 1788272531 seconds, 731032 microseconds  |  Included size: 1294  |  Original size: 1294

Destination MAC address: F4:1D:6B:60:DB:01
Source MAC address : 40:C2:BA:41:4D:53
EtherType: 0x86DD
Version:         6
Traffic Class:   0x02
Flow Label:      0x416D0
Payload Length:  1240
Next Header:     17
Hop Limit:       64
Source IP:       2a02:2f01:6801:1800:3b50:fb0a:bcfa:7321
Destination IP:  2a00:1450:400d:80b::200e

UDP Header:
Src Port: 45931
Dest Port: 443
Length: 1240
Checksum: 60123

Finished parsing! Total packets read: 2