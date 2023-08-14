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
package com.smaxe.os.jna.pcap;

import com.sun.jna.Structure;

/**
 * <code>sockaddr</code> 
 * 
 * @author Andrei Sochirca
 */
@Structure.FieldOrder({"sa_family", "sa_data"})
public class sockaddr extends Structure {
    /**
     * <code>AF_INET</code>
     */
    public final static int AF_INET = 2;
    
    /**
     * <code>ByReference</code> 
     */
    public static class ByReference extends sockaddr implements Structure.ByReference {
        /**
         * Constructor.
         */
        public ByReference() {
        }
    }
    
    /**
     * address family, AF_xxx.
     */
    public int sa_family;
    /**
     * 16 bytes of protocol address.
     */
    public byte[] sa_data = new byte[16];
    
    /**
     * Constructor.
     */
    public sockaddr() {
    }
    
    @Override
    public String toString() {
        return "sockaddr (family=" + sa_family +
            ", ip=" + (sa_data[0] & 0xFF) + "." + (sa_data[1] & 0xFF) + "." + (sa_data[2] & 0xFF) + "." + (sa_data[3] & 0xFF) + ")";
    }
}