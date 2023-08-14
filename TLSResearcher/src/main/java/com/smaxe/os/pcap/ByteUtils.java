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
 * <code>ByteUtils</code> - byte utility methods.
 * 
 * @author Andrei Sochirca
*/
public final class ByteUtils extends Object {
    /**
     * Returns hex representation of the <code>data</code>.
     * 
     * @param data byte array
     * @param separator separator
     * @return hex representation
     */
    public static String toHexString(final byte[] data, final String separator) {
        return toHexString(data, 0 /*dataOffset*/, data.length, separator);
    }
    
    /**
     * Returns hex representation of the <code>data</code> bytes.
     * 
     * @param data byte array
     * @param dataOffset data offset
     * @param dataLength data length
     * @param separator separator
     * @return hex representation
     */
    public static String toHexString(final byte[] data, final int dataOffset, final int dataLength, final String separator) {
        StringBuilder buf = new StringBuilder(dataLength * (5 + separator.length()));
        
        for (int i = dataOffset, n = dataOffset + dataLength; i < n; i++) {
            final String hex = Integer.toHexString(data[i] & 0xFF).toUpperCase();
            
            buf.append("0x");
            buf.append(hex.length() < 2 ? "0" : "");
            buf.append(hex);
            
            if (i < n - 1) {
                buf.append(separator);
                buf.append(" ");
            }
        }
        
        return buf.toString();
    }
    
    /**
     * Returns IPv4 representation of the <code>data</code> bytes.
     * 
     * @param data byte array
     * @param dataOffset data offset
     * @return ip representation
     */
    public static String toIPv4String(final byte[] data, final int dataOffset) {
        StringBuilder buf = new StringBuilder(32);
        
        for (int i = dataOffset, n = dataOffset + 4; i < n; i++) {
            buf.append(data[i] & 0xFF);
            
            if (i < n - 1) {
                buf.append(".");
            }
        }
        
        return buf.toString();
    }
    
    /**
     * Returns IPv4 representation of the <code>ip</code>.
     * 
     * @param ip ip integer
     * @return ip representation
     */
    public static String toIPv4String(final int ip) {
        StringBuilder buf = new StringBuilder(32);
        
        for (int i = 0; i < 4; i++) {
            buf.append((ip >> (24 - 8 * i)) & 0xFF);
            
            if (i < 3) {
                buf.append(".");
            }
        }
        
        return buf.toString();
    }
    
    /**
     * Reads 2 bytes (big-endian) as int.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return int
     */
    public static int read2Bytes(final byte[] data, final int dataOffset) {
        return ((data[dataOffset] & 0xFF) << 8) + (data[dataOffset + 1] & 0xFF);
    }
    
    /**
     * Reads 4 bytes (big-endian) as int.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return int
     */
    public static int read4Bytes(final byte[] data, final int dataOffset) {
        return ((data[dataOffset] & 0xFF) << 24) + ((data[dataOffset + 1] & 0xFF) << 16) + ((data[dataOffset + 2] & 0xFF) << 8) + (data[dataOffset + 3] & 0xFF);
    }
    
    /**
     * Reads 6 bytes.
     * 
     * @param data data buffer
     * @param dataOffset data buffer offset
     * @return 6-byte buffer
     */
    public static byte[] read6Bytes(final byte[] data, final int dataOffset) {
    	byte[] bytes = new byte[6];
    	System.arraycopy(data, dataOffset, bytes, 0, 6);
    	return bytes;
    }
    
    /**
     * Constructor.
     */
    private ByteUtils() {
    }
}