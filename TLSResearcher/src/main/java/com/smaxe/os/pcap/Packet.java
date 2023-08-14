/**
 * Copyright (c) 2009 Andrei Sochirca, All Rights Reserved
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.  
 */
package com.smaxe.os.pcap;

/**
 * <code>Packet</code> - packet utility methods/constants.
 * 
 * @author Andrei Sochirca
 */
public final class Packet extends Object {
    // DLT_* constants (Data Link Type constants)
    /**
     * <code>DLT_NULL</code> - 0 : no link-layer encapsulation.
     */
    public final static int DLT_NULL = 0;
    /**
     * <code>DLT_EN10MB</code> - 1 : Ethernet (10Mb).
     */
    public final static int DLT_EN10MB = 1;
    /**
     * <code>DLT_EN3MB</code> - 2 : Experimental Ethernet (3Mb).
     */
    public final static int DLT_EN3MB = 2;
    /**
     * <code>DLT_AX25</code> - 3 : Amateur Radio AX.25.
     */
    public final static int DLT_AX25 = 3;
    /**
     * <code>DLT_PRONET</code> - 4 : Proteon ProNET Token Ring.
     */
    public final static int DLT_PRONET = 4;
    /**
     * <code>DLT_CHAOS</code> - 5 : Chaos.
     */
    public final static int DLT_CHAOS = 5;
    /**
     * <code>DLT_IEEE802</code> - 6 : IEEE 802 Networks.
     */
    public final static int DLT_IEEE802 = 6;
    /**
     * <code>DLT_ARCNET</code> - 7 : ARCNET.
     */
    public final static int DLT_ARCNET = 7;
    /**
     * <code>DLT_SLIP</code> - 8 : Serial Line IP.
     */
    public final static int DLT_SLIP = 8;
    /**
     * <code>DLT_PPP</code> - 9 : Point-to-point Protocol.
     */
    public final static int DLT_PPP = 9;
    /**
     * <code>DLT_FDDI</code> - 10 : FDDI.
     */
    public final static int DLT_FDDI = 10;    
    
    // PROTOCOL_* constants
    /**
     * <code>PROTOCOL_ICMP</code> - 1 : Internet Control Message Protocol (http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol).
     */
    public final static int PROTOCOL_ICMP = 1;
    /**
     * <code>PROTOCOL_IGMP</code> - 2 : Internet Group Management Protocol (http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol).
     */
    public final static int PROTOCOL_IGMP = 2;
    /**
     * <code>PROTOCOL_TCP</code> - 6 : Transmission Control Protocol (http://en.wikipedia.org/wiki/Transmission_Control_Protocol).
     */
    public final static int PROTOCOL_TCP = 6;
    /**
     * <code>PROTOCOL_UDP</code> - 17 : User Datagram Protocol (http://en.wikipedia.org/wiki/User_Datagram_Protocol).
     */
    public final static int PROTOCOL_UDP = 17;
    
    /**
     * <code>EthernetHeader</code> - Ethernet header. 
     */
    public final static class EthernetHeader extends Object {
        /**
         * <code>SIZE</code> - 14
         */
        public final static int SIZE = 14;
        
        /**
         * destination MAC.
         */
        public byte[] destinationMac;
        /**
         * source MAC.
         */
        public byte[] sourceMac;
        /**
         * packet type.
         */
        public int type;
        
        /**
         * Constructor.
         */
        public EthernetHeader() {
        }
    }
    
    /**
     * <code>IPv4Header</code> - IPv4 header.
     * <p> Note:
     * <br> - http://en.wikipedia.org/wiki/IPv4
     */
    public final static class IPv4Header extends Object {
        // fields
        /**
         * The second field (4 bits) is the Internet Header Length (IHL) telling
         * the number of 32-bit words in the header. Since an IPv4 header may
         * contain a variable number of options, this field specifies the size of the header
         * (this also coincides with the offset to the data).
         * The minimum value for this field is 5 (RFC 791), which is a length of 5x32 = 160 bits.
         * Being a 4-bit value, the maximum length is 15 words (15x32 bits) or 480 bits.
         */
        public int headerLength;
        /**
         * 
         */
        public int differentiatedServices;
        /**
         * This 16-bit field defines the entire datagram size, including header and data, in bytes.
         * The minimum-length datagram is 20 bytes (20-byte header + 0 bytes data)
         * and the maximum is 65,535 � the maximum value of a 16-bit word.
         * The minimum size datagram that any host is required to be able to handle is 576 bytes,
         * but most modern hosts handle much larger packets.
         * Sometimes subnetworks impose further restrictions on the size,
         * in which case datagrams must be fragmented.
         * Fragmentation is handled in either the host or packet switch in IPv4 (see Fragmentation and reassembly).
         */
        public int totalLength;
        /**
         * This field is an identification field and is primarily used for uniquely
         * identifying fragments of an original IP datagram.
         * Some experimental work has suggested using the ID field for other purposes,
         * such as for adding packet-tracing information to datagrams in order
         * to help trace back datagrams with spoofed source addresses.
         */
        public int identification;
        /**
         * A three-bit field follows and is used to control or identify fragments. They are (in order, from high order to low order):
         * - Reserved; must be zero. As an April Fools joke, proposed for use in RFC 3514 as the "Evil bit".
         * - Don't Fragment (DF)
         * - More Fragments (MF)
         * If the DF flag is set and fragmentation is required to route the packet then the packet will be dropped.
         * This can be used when sending packets to a host that does not have sufficient resources to handle fragmentation.
         * When a packet is fragmented all fragments have the MF flag set except the last fragment,
         * which does not have the MF flag set. The MF flag is also not set on packets that are not fragmented -
         * an unfragmented packet is its own last fragment.
         */
        public int flags;
        /**
         * The fragment offset field, measured in units of eight-byte blocks,
         * is 13 bits long and specifies the offset of a particular fragment relative
         * to the beginning of the original unfragmented IP datagram. The first fragment
         * has an offset of zero. This allows a maximum offset of (213 � 1) x 8 = 65,528
         * which would exceed the maximum IP packet length of 65,535 with
         * the header length included.
         */
        public int fragmentOffset;
        /**
         * An eight-bit time to live (TTL) field helps prevent datagrams from persisting
         * (e.g. going in circles) on an internet. This field limits a datagram's lifetime.
         * It is specified in seconds, but time intervals less than 1 second are rounded up to 1.
         * In latencies typical in practice, it has come to be a hop count field.
         * Each packet switch (or router) that a datagram crosses decrements the TTL field
         * by one. When the TTL field hits zero, the packet is no longer forwarded
         * by a packet switch and is discarded.
         * Typically, an ICMP message (specifically the time exceeded) is sent back
         * to the sender that it has been discarded. The reception of these ICMP
         * messages is at the heart of how traceroute works.
         */
        public int timeToLive;
        /**
         * This field defines the protocol used in the data portion of the IP datagram.
         * The Internet Assigned Numbers Authority maintains a list of Protocol numbers
         * which was originally defined in RFC 790. Common protocols and their decimal
         * values are shown below (please check PROTOCOL_* constants).
         */
        public int protocol;
        /**
         * The 16-bit checksum field is used for error-checking of the header.
         */
        public int headerChecksum;
        /**
         * An IPv4 address is a group of four octets for a total of 32 bits.
         * The value for this field is determined by taking the binary value of each octet
         * and concatenating them together to make a single 32-bit value.
         * This address is the address of the sender of the packet.
         * Note that this address may not be the "true" sender of the packet due
         * to network address translation. Instead, the source address will be translated
         * by the NATing machine to its own address. Thus, reply packets sent by
         * the receiver are routed to the NATing machine,
         * which translates the destination address to the original sender's address.
         */
        public int sourceAddress;
        /**
         * Identical to the source address field but indicates the receiver of the packet.
         */
        public int destinationAddress;
        
        /**
         * Constructor.
         */
        public IPv4Header() {
        }
        
        @Override
        public String toString() {
            return "IPv4Header [" + " headerLength=" + headerLength +
                ", differentiatedServices=" + differentiatedServices + ", totalLength=" + totalLength +
                ", identification=" + identification + ", flags=" + flags + ", fragmentOffset=" + fragmentOffset +
                ", timeToLive=" + timeToLive + ", protocol=" + protocol + ", headerChecksum=" + headerChecksum +
                ", sourceAddress=" + ByteUtils.toIPv4String(sourceAddress) + ", destinationAddress=" + ByteUtils.toIPv4String(destinationAddress) + "]";
        }
    }
    
    /**
     * <code>IPv6Header</code> - IPv6 header.
     * <p> Note:
     * <br> - http://en.wikipedia.org/wiki/IPv6_packet
     */
    public final static class IPv6Header extends Object {
        // fields
        /**
         * The bits of this field hold two values. The 6 most-significant bits are used for DSCP,
         * which is used to classify packets.The remaining two bits are used for ECN;
         * priority values subdivide into ranges: traffic where the source provides
         * congestion control and non-congestion control traffic.
         */
        public int trafficClass;
        /**
         * Originally created for giving real-time applications special service.
         * Flow Label specifications and minimum requirements are described,
         * and first uses of this field are emerging.[7]
         */
        public int flowLabel;
        /**
         * The size of the payload in octets, including any extension headers.
         * The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option.
         */
        public int payloadLength;
        /**
         * Specifies the type of the next header. This field usually specifies
         * the transport layer protocol used by a packet's payload.
         * When extension headers are present in the packet this field indicates
         * which extension header follows.
         * The values are shared with those used for the IPv4 protocol field, 
         * as both fields have the same function (see List of IP protocol numbers).
         */
        public int nextHeader;
        /**
         * Replaces the time to live field of IPv4. This value is decremented by
         * one at each intermediate node the packet visits.
         * When the counter reaches 0 the packet is discarded.
         */
        public int hopLimit;
        /**
         * The IPv6 address of the sending node.
         */
        public byte[] sourceAddress;
        /**
         * The IPv6 address of the destination node(s).
         */
        public byte[] destinationAddress;
        
        /**
         * Constructor.
         */
        public IPv6Header() {
        }
    }
    
    /**
     * <code>TcpHeader</code> - TCP header.
     */
    public final static class TcpHeader extends Object {
        // fields
        /**
         * IPv4 header.
         */
        public IPv4Header ipv4Header;
        /**
         * IPv6 header.
         */
        public IPv6Header ipv6Header;
        /**
         * Identifies the sending port.
         */
        public int sourcePort;
        /**
         * Identifies the receiving port.
         */
        public int destinationPort;
        /**
         * has a dual role:
         * - If the SYN flag is set, then this is the initial sequence number.
         * The sequence number of the actual first data byte will then be this sequence number plus 1.
         * - If the SYN flag is clear, then this is the sequence number of the first data byte.
         */
        public int sequenceNumber;
        /**
         * If the ACK flag is set then the value of this field is the next sequence number
         * that the receiver is expecting. This acknowledges receipt of all prior bytes (if any).
         * The first ACK sent by each end acknowledges the other end's initial sequence number itself,
         * but no data.
         */
        public int acknowledgmentNumber;
        /**
         * Specifies the size of the TCP header in 32-bit words. The minimum size header
         * is 5 words and the maximum is 15 words thus giving the minimum size of 20 bytes
         * and maximum of 60 bytes, allowing for up to 40 bytes of options in the header.
         * This field gets its name from the fact that it is also the offset from the start of the TCP segment
         * to the actual data.
         */
        public int dataOffset;
        /**
         * Flags (aka Control bits) � contains 8 1-bit flags.
         */
        public int flags;
        /**
         * The size of the receive window, which specifies the number of bytes
         * (beyond the sequence number in the acknowledgment field) that the
         * receiver is currently willing to receive.
         */
        public int window;
        /**
         * The 16-bit checksum field is used for error-checking of the header and data.
         */
        public int checksum;
        /**
         * if the URG flag is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte.
         */
        public int urgentPointer;
        
        /**
         * Constructor.
         */
        public TcpHeader() {
        }
        
        /**
         * Returns 'CWR' flag.
         * 
         * @return 'CWR' flag
         */
        public boolean getCWR() {
            return (flags & 0x80) == 0x80;
        }
        
        /**
         * Returns 'ECE' flag.
         * 
         * @return 'ECE' flag
         */
        public boolean getECE() {
            return (flags & 0x40) == 0x40;
        }
        
        /**
         * Returns 'URG' flag.
         * 
         * @return 'URG' flag
         */
        public boolean getURG() {
            return (flags & 0x20) == 0x20;
        }
        
        /**
         * Returns 'ACK' flag.
         * 
         * @return 'ACK' flag
         */
        public boolean getACK() {
            return (flags & 0x10) == 0x10;
        }
        
        /**
         * Returns 'PSH' flag.
         * 
         * @return 'PSH' flag
         */
        public boolean getPSH() {
            return (flags & 0x08) == 0x08;
        }
        
        /**
         * Returns 'RST' flag.
         * 
         * @return 'RST' flag
         */
        public boolean getRST() {
            return (flags & 0x04) == 0x04;
        }
        
        /**
         * Returns 'SYN' flag.
         * 
         * @return 'SYN' flag
         */
        public boolean getSYN() {
            return (flags & 0x02) == 0x02;
        }
        
        /**
         * Returns 'FIN' flag.
         * 
         * @return 'FIN' flag
         */
        public boolean getFIN() {
            return (flags & 0x01) == 0x01;
        }
        
        @Override
        public String toString() {
            return "TcpHeader [sourcePort=" + sourcePort + ", destinationPort=" + destinationPort +
                ", sequenceNumber=" + sequenceNumber + ", acknowledgmentNumber=" + acknowledgmentNumber +
                ", dataOffset=" + dataOffset + ", flags=" + flags + ", window=" + window +
                ", checksum=" + checksum + ", urgentPointer=" + urgentPointer + ", ipv4Header=" + ipv4Header + "]";
        }
    }
    
    /**
     * <code>UdpHeader</code> - UDP header.
     */
    public final static class UdpHeader extends Object {
        // fields
        /**
         * IPv4 header.
         */
        public IPv4Header ipv4Header;
        /**
         * IPv6 header.
         */
        public IPv6Header ipv6Header;
        /**
         * This field identifies the sending port when meaningful and should be assumed
         * to be the port to reply to if needed. If not used, then it should be zero.
         */
        public int sourcePort;
        /**
         * This field identifies the destination port and is required.
         */
        public int destinationPort;
        /**
         * A 16-bit field that specifies the length in bytes of the entire datagram: header and data.
         * The minimum length is 8 bytes since that's the length of the header.
         * The field size sets a theoretical limit of 65,535 bytes (8 byte header + 65527 bytes of data)
         * for a UDP datagram. The practical limit for the data length which is imposed
         * by the underlying IPv4 protocol is 65,507 bytes.
         */
        public int length;
        /**
         * The 16-bit checksum field is used for error-checking of the header and data.
         * The algorithm for computing the checksum is different for transport over IPv4 and IPv6.
         * If the checksum is omitted in IPv4, the field uses the value all-zeros.
         * This field is not optional for IPv6.
         */
        public int checksum;
        
        /**
         * Constructor.
         */
        public UdpHeader() {
        }
        
        @Override
        public String toString() {
            return "UdpHeader [sourcePort=" + sourcePort + ", destinationPort=" + destinationPort +
                ", length=" + length + ", checksum=" + checksum + ", ipv4Header=" + ipv4Header + "]";
        }
    }
    
    /**
     * Returns {@link Packet.TcpHeader <tt>header</tt>} flags as string.
     * 
     * @param header TCP packet header
     * @return tcp header flags
     */
    public static String getTcpHeaderFlags(final Packet.TcpHeader header) {
        StringBuilder buf = new StringBuilder(32);
        
        if (header.getCWR()) {
            buf.append("cwr").append(",");
        }
        if (header.getECE()) {
            buf.append("ece").append(",");
        }
        if (header.getURG()) {
            buf.append("urg").append(",");
        }
        if (header.getACK()) {
            buf.append("ack").append(",");
        }
        if (header.getPSH()) {
            buf.append("psh").append(",");
        }
        if (header.getRST()) {
            buf.append("rst").append(",");
        }
        if (header.getSYN()) {
            buf.append("syn").append(",");
        }
        if (header.getFIN()) {
            buf.append("fin").append(",");
        }
        
        return buf.toString();
    }
    
    /**
     * Constructor.
     */
    private Packet() {
    }
}