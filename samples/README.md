# Samples

These captures are synthetic.  None of them comes from real traffic.  MAC addresses are locally administered.  IP addresses come from the documentation ranges of RFC 5737 and RFC 3849.  Host names end in `.example`.  Payloads are either random bytes or J2735 messages with made-up values.  The places, vehicles and IDs in those messages are made up too.  Keys, signatures and certificate digests are random bytes.

| File | Contents |
|---|---|
| `bus-priority.pcapng` | Big-endian, with nanosecond times and a direction on each packet.  A bus asks an intersection for signal priority with signed SRMs and gets signed SSMs back.  It also has packet comments. |
| `dsrc-and-cv2x.pcapng` | Two interfaces: a DSRC radio (radiotap) and a C-V2X radio (UDP over IPv4 and IPv6).  It has BSMs, PSMs and SDSMs, a Name Resolution Block, and comments. |
| `pcapng-basic.pcapng` | One Ethernet interface and 20 Enhanced Packet Blocks of WSMs. |
| `pcapng-big-endian.pcapng` | A big-endian section with nanosecond times, over Linux SLL. |
| `pcapng-interfaces.pcapng` | Interfaces that differ in every field and option, a Name Resolution Block, an Interface Statistics Block, and a multi-line UTF-8 comment. |
| `intersection.pcapng` | A MAP, SPATs and BSMs from one intersection over Ethernet. |
| `message-types.pcapng` | One message of each J2735 type over Ethernet. |
| `signed-dsrc.pcapng` | A signed WSA, BSMs and a TIM over DSRC, with radiotap headers. |
| `example.pcapng` | 11 SPATs and 10 BSMs, in turn, over Ethernet. |
| `ethernet-wsmp.pcapng` | 300 WSMs directly over Ethernet. |
| `ethernet-mixed.pcapng` | WSMs in UDP over IPv4, mixed with ARP, IGMP, ICMPv6, multicast and TCP traffic. |
| `ieee802-11-qos-epd.pcapng` | 802.11 QoS data frames with no radiotap header, from three stations. |
| `radiotap-qos-epd.pcapng` | One radiotap frame with rate, channel, signal and A-MPDU status fields. |
| `sll-ipv6-udp-wsmp.pcapng` | WSMs in UDP over IPv6, over Linux SLL. |
