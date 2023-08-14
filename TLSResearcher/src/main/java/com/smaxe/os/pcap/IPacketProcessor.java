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
 * <code>IPacketProcessor</code> - packet processor.
 * 
 * @author Andrei Sochirca
 */
public interface IPacketProcessor {
    /**
     * Invoked when a new packet is available.
     * 
     * @param dataLinkType data link type
     * @param timestamp packet timestamp
     * @param data packet data buffer
     * @param dataOffset packet data offset
     * @param dataLength packet data length
     */
    public void onPacket(final int dataLinkType, final long timestamp, final byte[] data, final int dataOffset, final int dataLength);
}