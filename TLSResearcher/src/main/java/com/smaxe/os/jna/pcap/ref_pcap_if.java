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

import com.sun.jna.Native;
import com.sun.jna.ptr.ByReference;

/**
 * <code>ref_pcap_if</code>
 * 
 * @author Andrei Sochirca
 */
public class ref_pcap_if extends ByReference {
    /**
     * Constructor.
     */
    public ref_pcap_if() {
        this(Native.POINTER_SIZE);
    }
    
    /**
     * Constructor.
     * 
     * @param dataSize
     */
    protected ref_pcap_if(final int dataSize) {
        super(dataSize);
    }
    
    /**
     * @return value
     */
    public pcap_if getValue() {
        pcap_if pcap_if = new pcap_if(getPointer().getPointer(0));
        
        pcap_if.read();
        
        return pcap_if;
    }
}