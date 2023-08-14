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
 * <code>PacketProcessor</code> - packet processor.
 * 
 * @author Andrei Sochirca
 */
public class PacketProcessor extends Object implements IPacketProcessor {
	
    /**
     * Parses Ethernet header.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return Ethernet header
     */
    public static Packet.EthernetHeader parseEthernetHeader(final byte[] data, final int dataOffset) {
        Packet.EthernetHeader header = new Packet.EthernetHeader();
        
        header.destinationMac = ByteUtils.read6Bytes(data, dataOffset);
        header.sourceMac = ByteUtils.read6Bytes(data, dataOffset + 6);
        header.type = ByteUtils.read2Bytes(data, dataOffset + 12);
        
        return header;
    }
    
    /**
     * Parses IPv4 header.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return IPv4 header
     */
    public static Packet.IPv4Header parseIPv4Header(final byte[] data, final int dataOffset) {
        Packet.IPv4Header header = new Packet.IPv4Header();
        
        header.headerLength = (data[dataOffset] & 0x0F);
        header.differentiatedServices = (data[dataOffset + 1] & 0xFF);
        header.totalLength = ByteUtils.read2Bytes(data, dataOffset + 2);
        header.identification = ByteUtils.read2Bytes(data, dataOffset + 4);
        header.flags = (data[dataOffset + 6] & 0xC0) >> 6;
        header.fragmentOffset = ByteUtils.read2Bytes(data, dataOffset + 6) & 0x3FFF;
        header.timeToLive = (data[dataOffset + 8] & 0xFF);
        header.protocol = (data[dataOffset + 9] & 0xFF);
        header.headerChecksum = ByteUtils.read2Bytes(data, dataOffset + 10);
        header.sourceAddress = ByteUtils.read4Bytes(data, dataOffset + 12);
        header.destinationAddress = ByteUtils.read4Bytes(data, dataOffset + 16);
        
        return header;
    }
    
    /**
     * Parses IPv6 header.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return IPv6 header
     */
    public static Packet.IPv6Header parseIPv6Header(final byte[] data, final int dataOffset) {
        Packet.IPv6Header header = new Packet.IPv6Header();
        
        header.trafficClass = ((data[dataOffset] & 0x0F) << 4) + ((data[dataOffset + 1] & 0xF0) >> 4);
        header.flowLabel = ((data[dataOffset + 1] & 0x0F) << 16) + ByteUtils.read2Bytes(data, dataOffset + 2);
        header.payloadLength = ByteUtils.read2Bytes(data, dataOffset + 4);
        header.nextHeader = (data[dataOffset + 6] & 0xFF);
        header.hopLimit = (data[dataOffset + 7] & 0xFF);
        header.sourceAddress = new byte[16];
        System.arraycopy(data, dataOffset + 8, header.sourceAddress, 0, 16);
        header.destinationAddress = new byte[16];
        System.arraycopy(data, dataOffset + 24, header.destinationAddress, 0, 16);
        
        return header;
    }
    
    /**
     * Parses TCP header.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return TCP header
     */
    public static Packet.TcpHeader parseTcpHeader(final byte[] data, final int dataOffset) {
        Packet.TcpHeader header = new Packet.TcpHeader();
        
        header.sourcePort = ByteUtils.read2Bytes(data, dataOffset);
        header.destinationPort = ByteUtils.read2Bytes(data, dataOffset + 2);
        header.sequenceNumber = ByteUtils.read4Bytes(data, dataOffset + 4);
        header.acknowledgmentNumber = ByteUtils.read4Bytes(data, dataOffset + 8);
        header.dataOffset = (data[dataOffset + 12] & 0xF0) >> 4;
        header.flags = (data[dataOffset + 13] & 0xFF);
        header.window = ByteUtils.read2Bytes(data, dataOffset + 14);
        header.checksum = ByteUtils.read2Bytes(data, dataOffset + 16);
        header.urgentPointer = ByteUtils.read2Bytes(data, dataOffset + 18);
        
        return header;
    }
    
    /**
     * Parses UDP header.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return UDP header
     */
    public static Packet.UdpHeader parseUdpHeader(final byte[] data, final int dataOffset) {
        Packet.UdpHeader header = new Packet.UdpHeader();
        
        header.sourcePort = ByteUtils.read2Bytes(data, dataOffset);
        header.destinationPort = ByteUtils.read2Bytes(data, dataOffset + 2);
        header.length = ByteUtils.read2Bytes(data, dataOffset + 4);
        header.checksum = ByteUtils.read2Bytes(data, dataOffset + 6);
        
        return header;
    }
    
    /**
     * Constructor.
     */
    public PacketProcessor() {
    }
    
    // IPacketProcessor implementation
    
    public final void onPacket(final int dataLinkType, final long timestamp, final byte[] data, final int dataOffset, final int dataLength) {
        switch (dataLinkType) {
            case Packet.DLT_EN10MB: {
                onEN10MB(timestamp, data, dataOffset, dataLength);
            } break;
            case Packet.DLT_PPP: {
                onPPP(timestamp, data, dataOffset, dataLength);
            } break;
            default: {
                onUnsupportedPacket(dataLinkType, timestamp, data, dataOffset, dataLength);
            } break;
        }
    }
    
    // for use in subclasses
    /**
     * Notifies about TCP packet.
     * 
     * @param header TCP packet header
     * @param data packet data buffer
     * @param dataOffset packet data buffer offset
     * @param dataLength packet data length
     */
    protected void onTcpPacket(final Packet.TcpHeader header, final byte[] data, final int dataOffset, final int dataLength) {
    }
    
    /**
     * Notifies about UDP packet.
     * 
     * @param header UDP packet header
     * @param data packet data buffer
     * @param dataOffset packet data buffer offset
     * @param dataLength packet data length
     */
    protected void onUdpPacket(final Packet.UdpHeader header, final byte[] data, final int dataOffset, final int dataLength) {
    }
    
    /**
     * Notifies about unsupported packet
     * 
     * @param dataLinkType data link type
     * @param timestamp timestamp
     * @param data packet data buffer
     * @param dataOffset packet data buffer offset
     * @param dataLength packet data length
     */
    protected void onUnsupportedPacket(final int dataLinkType, final long timestamp, final byte[] data, final int dataOffset, final int dataLength) {
        System.out.println("onUnsupportedPacket: " + dataLinkType + " " + timestamp + " " + dataLength);
    }
    
    // inner use methods
    /**
     * Processes the packet received from EN10MB (Ethernet) data link.
     * 
     * @param timestamp timestamp
     * @param data packet data buffer
     * @param dataOffset packet data buffer offset
     * @param dataLength packet data length
     */
    private void onEN10MB(final long timestamp, final byte[] data, final int dataOffset, int dataLength) {
        // Ethernet (a.k.a. Ethernet II)
        // +---------+---------+---------+----------
        // |   Dst      |   Src      |  Type    |  Data... 
        // +---------+---------+---------+----------
        // <-- 6 --> <-- 6 --> <-- 2 --> <-46-1500->
        // Type 0x08 0x00 = TCP/IP
        
        // check if TCP/IP
        if ((data[dataOffset + 12] == 0x08) && (data[dataOffset + 13] == 0x00)) {
            onIpPacket(Packet.DLT_EN10MB, timestamp, data, dataOffset + Packet.EthernetHeader.SIZE, dataLength - Packet.EthernetHeader.SIZE);
        }
    }
    
    /**
     * Processes the packet received from Point-to-Point Protocol data link.
     * 
     * @param timestamp timestamp
     * @param data packet data buffer
     * @param dataOffset packet data buffer offset
     * @param dataLength packet data length
     */
    private void onPPP(final long timestamp, final byte[] data, final int dataOffset, int dataLength) {
        final int ipid = ByteUtils.read4Bytes(data, dataOffset);
        
        // PPP frames are variants of HDLC frames:
        // 1 byte: 0x7E, the beginning of a PPP frame (ommitted)
        // 1 byte: 0xFF, standard broadcast address
        // 1 byte: 0x03, unnumbered data
        // 2 bytes: PPP ID of embedded data (0x0021 for IP)
        
        if (ipid == 0xFF030021) {
            onIpPacket(Packet.DLT_PPP, timestamp, data, dataOffset + 4, dataLength - 4);
        }
    }
    
    /**
     * Processes the IP packet received from <code>dataLinkType</code>.
     * 
     * @param dataLinkType
     * @param timestamp timestamp
     * @param data packet data buffer
     * @param dataOffset packet data buffer offset
     * @param dataLength packet data length
     */
    private void onIpPacket(final int dataLinkType, final long timestamp, final byte[] data, final int dataOffset, int dataLength) {
        final int version = (data[dataOffset] & 0xF0) >> 4;
        
        if (version == 0x04) {
            Packet.IPv4Header ipv4Header = PacketProcessor.parseIPv4Header(data, dataOffset);
            
            final int packetOffset = dataOffset + (ipv4Header.headerLength * 4);
            
            switch (ipv4Header.protocol) {
                case Packet.PROTOCOL_ICMP: {
                } break;
                case Packet.PROTOCOL_IGMP: {
                } break;
                case Packet.PROTOCOL_TCP: {
                    Packet.TcpHeader tcpHeader = parseTcpHeader(data, packetOffset);
                    
                    tcpHeader.ipv4Header = ipv4Header;
                    
                    final int tcpDataOffset = packetOffset + tcpHeader.dataOffset * 4 /*32-bit word length*/;
                    final int tcpDataLength = (ipv4Header.totalLength == 0 ? dataLength : ipv4Header.totalLength) -
                        (tcpDataOffset - dataOffset);
                    
                    onTcpPacket(tcpHeader, data, tcpDataOffset, tcpDataLength);
                    
                } break;
                case Packet.PROTOCOL_UDP: {
                    Packet.UdpHeader udpHeader = parseUdpHeader(data, packetOffset);
                    
                    udpHeader.ipv4Header = ipv4Header;
                    
                    onUdpPacket(udpHeader, data, packetOffset + 8 /*headerLength*/, udpHeader.length - 8 /*headerLength*/);
                    
                } break;
                default: {
                    onUnsupportedPacket(dataLinkType, timestamp, data, dataOffset, dataLength);
                }
            }
        }
        else
        if (version == 0x06) {
            Packet.IPv6Header ipv6Header = PacketProcessor.parseIPv6Header(data, dataOffset);
            
            int packetOffset = dataOffset + 40;
            int nextHeader = ipv6Header.nextHeader;
            
            boolean upperLayerPayload = false;
            
            while (!upperLayerPayload) {
                switch (nextHeader) {
                    // extensions
                    // Hop-by-Hop Options
                    case 0:
                    // Routing
                    case 43:
                    // Destination Options
                    case 60: {
                        nextHeader = data[packetOffset] & 0xFF;
                        packetOffset += 8 * ((data[packetOffset + 1] & 0xFF) + 1);
                    } break;
                    case Packet.PROTOCOL_ICMP: {
                        upperLayerPayload = true;
                    } break;
                    case Packet.PROTOCOL_TCP: {
                        upperLayerPayload = true;
                        
                        Packet.TcpHeader tcpHeader = parseTcpHeader(data, packetOffset);
                        
                        tcpHeader.ipv6Header = ipv6Header;
                        
                        final int tcpDataOffset = packetOffset + tcpHeader.dataOffset * 4 /*32-bit word length*/;
                        final int tcpDataLength = ipv6Header.payloadLength - (tcpDataOffset - dataOffset);
                        
                        onTcpPacket(tcpHeader, data, tcpDataOffset, tcpDataLength);
                    } break;
                    case Packet.PROTOCOL_UDP: {
                        upperLayerPayload = true;
                        
                        Packet.UdpHeader udpHeader = parseUdpHeader(data, packetOffset);
                        
                        udpHeader.ipv6Header = ipv6Header;
                        
                        onUdpPacket(udpHeader, data, packetOffset + 8 /*headerLength*/, udpHeader.length - 8 /*headerLength*/);
                    } break;
                    default: {
                        upperLayerPayload = true;
                        
                        onUnsupportedPacket(dataLinkType, timestamp, data, dataOffset, dataLength);
                    }
                }
            }
        }
    }
}